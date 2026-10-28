// Minimal "Sign in with NobleID" web app: net/http + html/template + the
// nobleid.org/signin helper (go-oidc + x/oauth2). Confidential client: the
// secret and tokens stay on this server; the browser only gets an opaque
// session cookie.
//
//	ISSUER=https://id.nobleid.org CLIENT_ID=... CLIENT_SECRET=... \
//	REDIRECT_URI=http://localhost:3000/callback go run .
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"maps"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	nobleid "nobleid.org/signin"
)

const sessionIdle = 8 * time.Hour

type session struct {
	mu       sync.Mutex // serialises refreshes: a rotated refresh token must never be used twice
	csrf     string
	tx       *nobleid.Transaction
	user     map[string]any
	tokens   *nobleid.Tokens
	lastSeen time.Time
}

type app struct {
	nobleid      *nobleid.Client
	origin       string
	callbackPath string
	secure       bool

	mu       sync.Mutex
	sessions map[string]*session
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	clientID, clientSecret := os.Getenv("CLIENT_ID"), os.Getenv("CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatal("Set CLIENT_ID and CLIENT_SECRET (see .env.example).")
	}
	redirect := env("REDIRECT_URI", "http://localhost:3000/callback")
	ru, err := url.Parse(redirect)
	if err != nil || ru.Host == "" {
		log.Fatal("REDIRECT_URI is not a URL")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	client, err := nobleid.New(ctx, nobleid.Config{
		Issuer:       env("ISSUER", nobleid.DefaultIssuer), // http is accepted only for localhost (the local mock)
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirect,
		Scopes:       strings.Fields(env("SCOPE", "openid profile email orcid affiliations works offline_access")),
		AuthMethod:   nobleid.ClientSecretBasic,
	})
	cancel()
	if err != nil {
		log.Fatalf("discovery failed: %v", err) // *nobleid.Error: code and description only
	}

	a := &app{
		nobleid:      client,
		origin:       ru.Scheme + "://" + ru.Host,
		callbackPath: ru.Path,
		secure:       ru.Scheme == "https",
		sessions:     map[string]*session{},
	}
	go a.prune()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.home)
	mux.HandleFunc("GET /login", a.login)
	mux.HandleFunc("GET "+a.callbackPath, a.callback)
	mux.HandleFunc("GET /works", a.works)
	mux.HandleFunc("POST /refresh", a.refresh)
	mux.HandleFunc("POST /logout", a.logout)

	srv := &http.Server{
		Addr:              "localhost:" + env("PORT", "3000"), // this machine only; put a reverse proxy in front in production
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("example listening on %s (port %s)", a.origin, env("PORT", "3000"))
	log.Fatal(srv.ListenAndServe())
}

/* ── a tiny in-memory session store (use a real one in production) ── */

func randomID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// cookieName uses the __Host- prefix over https, which pins the cookie to
// this exact origin (Secure, Path=/, no Domain).
func (a *app) cookieName() string {
	if a.secure {
		return "__Host-sid"
	}
	return "sid"
}

func (a *app) setCookie(w http.ResponseWriter, sid string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: a.cookieName(), Value: sid, Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

// get returns the caller's session, or nil.
func (a *app) get(r *http.Request) (string, *session) {
	c, err := r.Cookie(a.cookieName())
	if err != nil {
		return "", nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[c.Value]
	if s == nil {
		return "", nil
	}
	s.lastSeen = time.Now()
	return c.Value, s
}

// create starts a new session under a fresh random id.
func (a *app) create(w http.ResponseWriter) *session {
	sid := randomID()
	s := &session{csrf: randomID(), lastSeen: time.Now()}
	a.mu.Lock()
	a.sessions[sid] = s
	a.mu.Unlock()
	a.setCookie(w, sid, 0)
	return s
}

func (a *app) destroy(w http.ResponseWriter, sid string) {
	a.mu.Lock()
	delete(a.sessions, sid)
	a.mu.Unlock()
	a.setCookie(w, "", -1)
}

func (a *app) prune() {
	for range time.Tick(10 * time.Minute) {
		a.mu.Lock()
		for k, s := range a.sessions {
			if time.Since(s.lastSeen) > sessionIdle {
				delete(a.sessions, k)
			}
		}
		a.mu.Unlock()
	}
}

/* ── html (html/template escapes everything rendered) ── */

var pages = template.Must(template.New("").Parse(`
{{define "top"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NobleID example</title></head><body style="font-family:system-ui;max-width:48rem;margin:2rem auto;padding:0 1rem">{{end}}
{{define "end"}}</body></html>{{end}}
{{define "form"}}<form method="post" action="{{.Action}}" style="display:inline"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>{{.Label}}</button></form>{{end}}
{{define "signed-out"}}{{template "top"}}<h1>NobleID example (Go)</h1><p id="signed-out">You are signed out.</p><p><a href="/login">Sign in with NobleID</a></p>{{template "end"}}{{end}}
{{define "signed-in"}}{{template "top"}}<h1>Signed in</h1><p>Hello, {{.Name}}.</p>
<pre id="claims">{{.Claims}}</pre>
<p><a href="/works">My works</a>
{{if .CanRefresh}}{{template "form" .Refresh}}{{end}}
{{template "form" .Logout}}</p>{{template "end"}}{{end}}
{{define "works"}}{{template "top"}}<h1>Works</h1>{{if .}}<pre id="works">{{.}}</pre>{{else}}<p>The works scope was not granted.</p>{{end}}<p><a href="/">Back</a></p>{{template "end"}}{{end}}
{{define "error"}}{{template "top"}}<h1>Sign-in failed</h1><p id="error">{{.Code}}{{if .Description}}: {{.Description}}{{end}}</p><p><a href="/">Back</a></p>{{template "end"}}{{end}}
`))

type formData struct{ Action, Label, CSRF string }

func render(w http.ResponseWriter, status int, name string, data any) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; img-src https:; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template %s: %v", name, err)
	}
}

func redirect(w http.ResponseWriter, r *http.Request, to string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// fail renders the error page. Only the OAuth code and description reach the
// page or the log, never a token, code or secret.
func fail(w http.ResponseWriter, err error) {
	var e *nobleid.Error
	if errors.As(err, &e) {
		log.Printf("sign-in error: %s", e.Code)
		render(w, http.StatusBadRequest, "error", e)
		return
	}
	log.Printf("request failed")
	render(w, http.StatusInternalServerError, "error", &nobleid.Error{Code: "server_error"})
}

/* ── routes ── */

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	_, s := a.get(r)
	if s == nil {
		render(w, http.StatusOK, "signed-out", nil)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.user == nil {
		render(w, http.StatusOK, "signed-out", nil)
		return
	}
	shown := maps.Clone(s.user)
	shown["granted_scope"] = strings.Join(s.tokens.Scope, " ")
	j, _ := json.MarshalIndent(shown, "", "  ")
	name, _ := s.user["name"].(string)
	if name == "" {
		name, _ = s.user["nobleid"].(string)
	}
	render(w, http.StatusOK, "signed-in", map[string]any{
		"Name":       name,
		"Claims":     string(j),
		"CanRefresh": s.tokens.RefreshToken != "",
		"Refresh":    formData{"/refresh", "Refresh tokens", s.csrf},
		"Logout":     formData{"/logout", "Sign out", s.csrf},
	})
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	_, s := a.get(r)
	if s == nil {
		s = a.create(w)
	}
	authURL, tx := a.nobleid.StartSignIn()
	s.mu.Lock()
	s.tx = &tx
	s.mu.Unlock()
	redirect(w, r, authURL)
}

func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	sid, s := a.get(r)
	var tx *nobleid.Transaction
	if s != nil {
		s.mu.Lock()
		tx, s.tx = s.tx, nil // single use, whatever happens next
		s.mu.Unlock()
	}
	res, err := a.nobleid.FinishSignIn(r.Context(), r.URL.Query(), tx)
	if err != nil {
		fail(w, err)
		return
	}
	info, err := a.nobleid.UserInfo(r.Context(), res.Tokens.AccessToken, res.Claims.Subject)
	if err != nil {
		fail(w, err)
		return
	}
	// Key your accounts on sub. Only trust email for linking when email_verified is true.
	user := maps.Clone(res.Claims.Raw)
	maps.Copy(user, info)

	// New session id after sign-in.
	if sid != "" {
		a.destroy(w, sid)
	}
	fresh := a.create(w)
	fresh.user, fresh.tokens = user, res.Tokens
	redirect(w, r, "/")
}

func (a *app) works(w http.ResponseWriter, r *http.Request) {
	_, s := a.get(r)
	if s == nil {
		redirect(w, r, "/")
		return
	}
	s.mu.Lock()
	tokens := s.tokens
	s.mu.Unlock()
	if tokens == nil {
		redirect(w, r, "/")
		return
	}
	if !tokens.HasScope("works") {
		render(w, http.StatusOK, "works", "")
		return
	}
	works, err := a.nobleid.Works(r.Context(), tokens.AccessToken, 50, 0)
	if err != nil {
		fail(w, err)
		return
	}
	j, _ := json.MarshalIndent(works, "", "  ")
	render(w, http.StatusOK, "works", string(j))
}

// checkPost enforces a same-origin Origin header (when sent) and the CSRF token.
func (a *app) checkPost(w http.ResponseWriter, r *http.Request) (string, *session, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 10_000)
	sid, s := a.get(r)
	if err := r.ParseForm(); err != nil || s == nil {
		render(w, http.StatusForbidden, "error", &nobleid.Error{Code: "forbidden"})
		return "", nil, false
	}
	if o := r.Header.Get("Origin"); o != "" && o != a.origin {
		render(w, http.StatusForbidden, "error", &nobleid.Error{Code: "forbidden"})
		return "", nil, false
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(s.csrf)) != 1 {
		render(w, http.StatusForbidden, "error", &nobleid.Error{Code: "forbidden"})
		return "", nil, false
	}
	return sid, s, true
}

func (a *app) refresh(w http.ResponseWriter, r *http.Request) {
	sid, s, ok := a.checkPost(w, r)
	if !ok {
		return
	}
	s.mu.Lock() // one refresh per session at a time
	defer s.mu.Unlock()
	if s.tokens == nil || s.tokens.RefreshToken == "" {
		redirect(w, r, "/")
		return
	}
	sub, _ := s.user["sub"].(string)
	t, err := a.nobleid.Refresh(r.Context(), s.tokens.RefreshToken, sub) // fails if sub changed
	if err != nil {
		// invalid_grant: the user removed the app, or the session ended. Any
		// other failure (a rejected ID token, a different sub) may come after
		// the provider already rotated the refresh token, so the one we hold
		// could be spent. Either way, sign out locally.
		a.destroy(w, sid)
		var e *nobleid.Error
		if errors.As(err, &e) && e.Code == "invalid_grant" {
			redirect(w, r, "/")
			return
		}
		fail(w, err)
		return
	}
	if len(t.Scope) == 0 {
		t.Scope = s.tokens.Scope
	}
	s.tokens = t // stores the rotated refresh token
	redirect(w, r, "/")
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	sid, s, ok := a.checkPost(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	tokens := s.tokens
	s.mu.Unlock()
	// NobleID has no end-session endpoint: revoke, then clear our session.
	if tokens != nil {
		if tokens.RefreshToken != "" {
			if err := a.nobleid.Revoke(r.Context(), tokens.RefreshToken, "refresh_token"); err != nil {
				log.Printf("revoke refresh token failed")
			}
		}
		if err := a.nobleid.Revoke(r.Context(), tokens.AccessToken, "access_token"); err != nil {
			log.Printf("revoke access token failed")
		}
	}
	a.destroy(w, sid)
	redirect(w, r, "/")
}
