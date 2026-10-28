package nobleid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	testClientID = "nbcl_test_client"
	testSecret   = "nbcs_test+secret/with:chars"
	testRedirect = "http://localhost:3000/callback"
)

// fakeProvider is a tiny OIDC provider: discovery, JWKS (ES256), token,
// userinfo, works and revocation. It is only as strict as these tests need.
type fakeProvider struct {
	t       *testing.T
	srv     *httptest.Server
	key     *ecdsa.PrivateKey
	nonce   string // nonce to put in the next ID token
	aud     string
	refresh atomic.Int32
	revoked []url.Values
	auth    []string
	extra   map[string]any // merged into the next ID tokens (overrides)
	mu      sync.Mutex
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{t: t, key: key, aud: testClientID}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss := p.srv.URL
		writeJSON(w, 200, map[string]any{
			"issuer":                                iss,
			"authorization_endpoint":                "http://127.0.0.1:1/oauth/authorize",
			"token_endpoint":                        iss + "/oauth/token",
			"userinfo_endpoint":                     iss + "/oauth/userinfo",
			"revocation_endpoint":                   iss + "/oauth/revoke",
			"jwks_uri":                              iss + "/jwks",
			"id_token_signing_alg_values_supported": []string{"ES256"},
			"authorization_response_iss_parameter_supported": true,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{Key: &p.key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}
		writeJSON(w, 200, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.auth = append(p.auth, r.Header.Get("Authorization"))
		p.mu.Unlock()
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			writeJSON(w, 400, map[string]string{"error": "invalid_request"})
			return
		}
		_ = r.ParseForm()
		if r.PostForm.Get("client_secret") != "" {
			writeJSON(w, 400, map[string]string{"error": "invalid_client"})
			return
		}
		switch r.PostForm.Get("grant_type") {
		case "authorization_code":
			if r.PostForm.Get("code_verifier") == "" {
				writeJSON(w, 400, map[string]string{"error": "invalid_grant", "error_description": "PKCE required"})
				return
			}
			writeJSON(w, 200, map[string]any{
				"access_token": "nbat_secret_access", "token_type": "Bearer", "expires_in": 900,
				"refresh_token": "nbrt_secret_1", "scope": "openid profile works",
				"id_token": p.idToken(true),
			})
		case "refresh_token":
			n := p.refresh.Add(1)
			time.Sleep(50 * time.Millisecond) // widen the window for the concurrency test
			if r.PostForm.Get("refresh_token") == "nbrt_dead" {
				writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
				return
			}
			if r.PostForm.Get("refresh_token") == "nbrt_slow" {
				w.Header().Set("Retry-After", "7")
				writeJSON(w, 429, map[string]string{"error": "slow_down"})
				return
			}
			writeJSON(w, 200, map[string]any{
				"access_token": "nbat_new", "token_type": "Bearer", "expires_in": 900,
				"refresh_token": "nbrt_rotated_" + string(rune('0'+n)), "scope": "openid profile",
				"id_token": p.idToken(false),
			})
		}
	})
	mux.HandleFunc("/oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer nbat_secret_access" {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			w.WriteHeader(401)
			return
		}
		writeJSON(w, 200, map[string]any{"sub": "user-1", "verified_authorship_count": 1})
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/jwks", http.StatusFound)
	})
	mux.HandleFunc("/oauth/works", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"total": 0, "works": []any{}, "limit": r.URL.Query().Get("limit")})
	})
	mux.HandleFunc("/oauth/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		p.revoked = append(p.revoked, r.PostForm)
		p.auth = append(p.auth, r.Header.Get("Authorization"))
		p.mu.Unlock()
		w.WriteHeader(200)
	})
	p.srv = httptest.NewServer(mux)
	// httptest listens on 127.0.0.1, which New accepts over http.
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProvider) set(nonce, aud string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nonce, p.aud = nonce, aud
}

func (p *fakeProvider) authHeaders() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.auth...)
}

func (p *fakeProvider) idToken(withNonce bool) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now().Unix()
	c := map[string]any{"iss": p.srv.URL, "sub": "user-1", "aud": p.aud, "iat": now, "exp": now + 300,
		"nobleid": "NI000000001", "email_verified": true, "amr": []string{"pwd"}}
	if withNonce {
		c["nonce"] = p.nonce
	}
	for k, v := range p.extra {
		c[k] = v
	}
	payload, _ := json.Marshal(c)
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: p.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		p.t.Fatal(err)
	}
	jws, err := s.Sign(payload)
	if err != nil {
		p.t.Fatal(err)
	}
	out, _ := jws.CompactSerialize()
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newTestClient(t *testing.T, p *fakeProvider) *Client {
	t.Helper()
	c, err := New(context.Background(), Config{
		Issuer: p.srv.URL, ClientID: testClientID, ClientSecret: testSecret, RedirectURL: testRedirect,
		Scopes: []string{"openid", "profile", "works", "offline_access"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func codeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "not an *Error: " + err.Error()
}

func TestNewRejectsPlainHTTPIssuer(t *testing.T) {
	for _, iss := range []string{"http://id.example.org", "http://192.0.2.1:8080", "ftp://localhost"} {
		_, err := New(context.Background(), Config{Issuer: iss, ClientID: "x", RedirectURL: testRedirect})
		if codeOf(err) != "invalid_request" {
			t.Errorf("%s: got %v", iss, err)
		}
	}
}

func TestStartSignIn(t *testing.T) {
	p := newFakeProvider(t)
	c := newTestClient(t, p)
	authURL, tx := c.StartSignIn()
	u, _ := url.Parse(authURL)
	q := u.Query()
	if u.Host != "127.0.0.1:1" {
		t.Errorf("authorization endpoint not taken from discovery: %s", u.Host)
	}
	if q.Get("state") != tx.State || q.Get("nonce") != tx.Nonce || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || q.Get("response_type") != "code" || q.Get("client_id") != testClientID ||
		q.Get("redirect_uri") != testRedirect || q.Get("scope") != "openid profile works offline_access" {
		t.Errorf("bad authorize request: %v", q)
	}
	if strings.Contains(authURL, tx.Verifier) {
		t.Error("the PKCE verifier leaked into the URL")
	}
}

// The checks run in a fixed order; each case breaks exactly one thing and
// everything checked earlier is valid.
func TestFinishSignInCheckOrder(t *testing.T) {
	p := newFakeProvider(t)
	c := newTestClient(t, p)
	_, tx := c.StartSignIn()
	good := func() url.Values {
		return url.Values{"state": {tx.State}, "iss": {c.Issuer()}, "code": {"abc"}}
	}
	cases := []struct {
		name string
		tx   *Transaction
		mod  func(url.Values)
		want string
	}{
		{"no transaction", nil, func(url.Values) {}, "invalid_state"},
		{"state wrong, before iss and error", &tx, func(q url.Values) { q.Set("state", "x"); q.Set("iss", "https://evil"); q.Set("error", "access_denied") }, "invalid_state"},
		{"state missing", &tx, func(q url.Values) { q.Del("state") }, "invalid_state"},
		{"iss wrong, before error", &tx, func(q url.Values) { q.Set("iss", "https://evil.example"); q.Set("error", "access_denied") }, "invalid_issuer"},
		{"iss missing", &tx, func(q url.Values) { q.Del("iss") }, "invalid_issuer"},
		{"provider error, before code", &tx, func(q url.Values) { q.Del("code"); q.Set("error", "access_denied") }, "access_denied"},
		{"code missing", &tx, func(q url.Values) { q.Del("code") }, "invalid_request"},
	}
	for _, tc := range cases {
		q := good()
		tc.mod(q)
		_, err := c.FinishSignIn(context.Background(), q, tc.tx)
		if got := codeOf(err); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}

	// Flow age is checked last, before any network call.
	old := tx
	old.CreatedAt = time.Now().Add(-MaxFlowAge - time.Second)
	if _, err := c.FinishSignIn(context.Background(), url.Values{"state": {old.State}, "iss": {c.Issuer()}, "code": {"abc"}}, &old); codeOf(err) != "expired" {
		t.Errorf("expired flow: got %v", err)
	}
	if n := len(p.authHeaders()); n != 0 {
		t.Errorf("token endpoint called %d times during rejected callbacks", n)
	}
}

func TestFinishSignInHappyPathAndTokenChecks(t *testing.T) {
	p := newFakeProvider(t)
	c := newTestClient(t, p)
	ctx := context.Background()

	_, tx := c.StartSignIn()
	p.set(tx.Nonce, testClientID)
	res, err := c.FinishSignIn(ctx, url.Values{"state": {tx.State}, "iss": {c.Issuer()}, "code": {"abc"}}, &tx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Claims.Subject != "user-1" || res.Claims.NobleID != "NI000000001" || !res.Claims.EmailVerified || res.Claims.Raw["nonce"] != tx.Nonce {
		t.Errorf("claims: %+v", res.Claims)
	}
	if !res.Tokens.HasScope("works") || res.Tokens.HasScope("email") || res.Tokens.RefreshToken != "nbrt_secret_1" {
		t.Errorf("tokens: scope %v", res.Tokens.Scope)
	}
	if time.Until(res.Tokens.Expiry) < 14*time.Minute {
		t.Errorf("expiry not read from expires_in: %v", res.Tokens.Expiry)
	}
	// client_secret_basic with form-urlencoded id and secret.
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(testClientID)+":"+url.QueryEscape(testSecret)))
	if h := p.authHeaders()[0]; h != want {
		t.Errorf("token endpoint auth header %q, want %q", h, want)
	}

	info, err := c.UserInfo(ctx, res.Tokens.AccessToken, res.Claims.Subject)
	if err != nil || info["verified_authorship_count"] != float64(1) {
		t.Errorf("userinfo: %v %v", info, err)
	}
	if _, err := c.UserInfo(ctx, res.Tokens.AccessToken, "someone-else"); codeOf(err) != "invalid_token" {
		t.Errorf("userinfo sub mismatch not rejected: %v", err)
	}
	if _, err := c.UserInfo(ctx, "nbat_wrong", ""); codeOf(err) != "invalid_token" {
		t.Errorf("bearer error not parsed: %v", err)
	}
	if _, err := c.Works(ctx, res.Tokens.AccessToken, 101, 0); codeOf(err) != "invalid_request" {
		t.Errorf("limit not validated: %v", err)
	}
	if w, err := c.Works(ctx, res.Tokens.AccessToken, 50, 0); err != nil || w["limit"] != "50" {
		t.Errorf("works: %v %v", w, err)
	}

	// Wrong nonce.
	_, tx2 := c.StartSignIn()
	p.set("not-the-nonce", testClientID)
	if _, err := c.FinishSignIn(ctx, url.Values{"state": {tx2.State}, "iss": {c.Issuer()}, "code": {"abc"}}, &tx2); codeOf(err) != "invalid_id_token" {
		t.Errorf("nonce mismatch: %v", err)
	}
	// Wrong audience.
	_, tx3 := c.StartSignIn()
	p.set(tx3.Nonce, "nbcl_someone_else")
	if _, err := c.FinishSignIn(ctx, url.Values{"state": {tx3.State}, "iss": {c.Issuer()}, "code": {"abc"}}, &tx3); codeOf(err) != "invalid_id_token" {
		t.Errorf("aud mismatch: %v", err)
	}
}

func TestRefreshRotationAndSerialisation(t *testing.T) {
	p := newFakeProvider(t)
	c := newTestClient(t, p)
	ctx := context.Background()

	var wg sync.WaitGroup
	got := make([]*Tokens, 5)
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok, err := c.Refresh(ctx, "nbrt_secret_1", "user-1")
			if err != nil {
				t.Error(err)
			}
			got[i] = tok
		}(i)
	}
	wg.Wait()
	if n := p.refresh.Load(); n != 1 {
		t.Errorf("same refresh token sent %d times; want 1", n)
	}
	for _, tok := range got {
		if tok == nil || tok.RefreshToken != got[0].RefreshToken || !strings.HasPrefix(tok.RefreshToken, "nbrt_rotated_") {
			t.Errorf("rotated refresh token not returned: %+v", tok)
		}
	}

	_, err := c.Refresh(ctx, "nbrt_dead", "user-1")
	if codeOf(err) != "invalid_grant" {
		t.Errorf("invalid_grant not surfaced: %v", err)
	}
	_, err = c.Refresh(ctx, "nbrt_slow", "user-1")
	var e *Error
	if !errors.As(err, &e) || e.Code != "slow_down" || e.Status != 429 || e.RetryAfter != 7*time.Second {
		t.Errorf("slow_down not surfaced: %#v", err)
	}
	// The refreshed ID token is for user-1: a session for anyone else must not take it.
	if _, err := c.Refresh(ctx, "nbrt_secret_2", "user-2"); codeOf(err) != "invalid_id_token" {
		t.Errorf("sub change not rejected: %v", err)
	}
	if _, err := c.Refresh(ctx, "nbrt_secret_3", ""); codeOf(err) != "invalid_request" {
		t.Errorf("empty expected sub accepted: %v", err)
	}
}

func TestRevokeAndNoTokensInErrors(t *testing.T) {
	p := newFakeProvider(t)
	c := newTestClient(t, p)
	if err := c.Revoke(context.Background(), "nbrt_secret_1", "refresh_token"); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	r := p.revoked[0]
	p.mu.Unlock()
	if r.Get("token") != "nbrt_secret_1" || r.Get("token_type_hint") != "refresh_token" || r.Get("client_secret") != "" {
		t.Errorf("revocation form: %v", r)
	}
	if h := p.authHeaders(); !strings.HasPrefix(h[len(h)-1], "Basic ") {
		t.Error("revocation did not use client_secret_basic")
	}

	_, err := c.Refresh(context.Background(), "nbrt_dead", "user-1")
	for _, secret := range []string{"nbrt_dead", testSecret, "nbat_"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error string contains a token or secret: %q", err.Error())
		}
	}
}

func TestIDTokenSubAndAzp(t *testing.T) {
	p := newFakeProvider(t)
	c := newTestClient(t, p)
	ctx := context.Background()
	cases := []struct {
		name  string
		extra map[string]any
		ok    bool
	}{
		{"azp is this client", map[string]any{"azp": testClientID}, true},
		{"azp is another client", map[string]any{"azp": "nbcl_other"}, false},
		{"several audiences, no azp", map[string]any{"aud": []string{testClientID, "nbcl_other"}}, false},
		{"several audiences, azp is this client", map[string]any{"aud": []string{testClientID, "nbcl_other"}, "azp": testClientID}, true},
		{"empty sub", map[string]any{"sub": ""}, false},
	}
	for _, tc := range cases {
		_, tx := c.StartSignIn()
		p.set(tx.Nonce, testClientID)
		p.mu.Lock()
		p.extra = tc.extra
		p.mu.Unlock()
		_, err := c.FinishSignIn(ctx, url.Values{"state": {tx.State}, "iss": {c.Issuer()}, "code": {"abc"}}, &tx)
		if tc.ok && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if !tc.ok && codeOf(err) != "invalid_id_token" {
			t.Errorf("%s: not rejected: %v", tc.name, err)
		}
	}
}

func TestRefreshSurvivesACancelledCaller(t *testing.T) {
	p := newFakeProvider(t)
	c := newTestClient(t, p)
	// The provider takes 50ms; this caller gives up after 5ms.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if _, err := c.Refresh(ctx, "nbrt_secret_1", "user-1"); err == nil {
		t.Fatal("expected the first caller to be cancelled")
	}
	// The request carries on; a second caller with the same token joins it.
	tok, err := c.Refresh(context.Background(), "nbrt_secret_1", "user-1")
	if err != nil || !strings.HasPrefix(tok.RefreshToken, "nbrt_rotated_") {
		t.Fatalf("second caller: %v %+v", err, tok)
	}
	if n := p.refresh.Load(); n != 1 {
		t.Errorf("same refresh token sent %d times; want 1", n)
	}
}

func TestDefaultHTTPClientDoesNotFollowRedirects(t *testing.T) {
	p := newFakeProvider(t)
	c := newTestClient(t, p)
	resp, err := c.httpClient.Get(p.srv.URL + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("redirect was followed: status %d", resp.StatusCode)
	}
}
