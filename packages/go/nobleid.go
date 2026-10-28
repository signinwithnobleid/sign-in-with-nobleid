// Package nobleid is a thin server-side helper for "Sign in with NobleID".
//
// It wraps github.com/coreos/go-oidc/v3 and golang.org/x/oauth2 with
// NobleID's settings already chosen: discovery, ES256 ID tokens verified
// against the provider's JWKS, PKCE S256, state, nonce and the RFC 9207 `iss`
// check on every callback, refresh-token rotation that never runs two
// refreshes of the same token at once in this process, and RFC 7009
// revocation. It does no cryptography of its own.
//
// Keep tokens on your server. Store the Transaction returned by StartSignIn in
// your server-side session and pass it back to FinishSignIn exactly once.
package nobleid

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// DefaultIssuer is NobleID's issuer. Endpoints are read from its discovery document.
const DefaultIssuer = "https://id.nobleid.org"

// refreshTimeout bounds a shared refresh request, which runs independently of
// any one caller's context.
const refreshTimeout = 30 * time.Second

// MaxFlowAge is how long a sign-in may take between StartSignIn and FinishSignIn.
const MaxFlowAge = 10 * time.Minute

// DefaultScopes are requested when Config.Scopes is empty.
var DefaultScopes = []string{oidc.ScopeOpenID, "profile", "email"}

// AuthMethod selects how the client authenticates at the token and revocation endpoints.
type AuthMethod int

const (
	// ClientSecretBasic sends the form-urlencoded client id and secret in an
	// HTTP Basic Authorization header. The default for confidential clients.
	ClientSecretBasic AuthMethod = iota
	// ClientSecretPost sends client_id and client_secret in the form body.
	ClientSecretPost
)

// Config configures a Client.
type Config struct {
	// Issuer defaults to DefaultIssuer. It must be https; http is accepted only
	// for localhost and 127.0.0.1 (a local mock provider).
	Issuer       string
	ClientID     string // nbcl_...
	ClientSecret string // nbcs_...; read it from the environment. Empty means a public client.
	RedirectURL  string // must exactly match a redirect URI registered for the client
	Scopes       []string
	AuthMethod   AuthMethod
	// HTTPClient is used for every request to the provider. Defaults to a
	// client with a 10 second timeout that never follows redirects. A client
	// you supply should do the same: set a Timeout, and set CheckRedirect to
	// return http.ErrUseLastResponse, so that a redirect is never followed
	// with a token or client secret attached.
	HTTPClient *http.Client
}

// Client talks to NobleID. It is safe for concurrent use.
type Client struct {
	issuer        string
	clientID      string
	clientSecret  string
	authMethod    AuthMethod
	httpClient    *http.Client
	provider      *oidc.Provider
	verifier      *oidc.IDTokenVerifier
	oauth         *oauth2.Config
	userinfoURL   string
	revocationURL string
	worksURL      string

	mu         sync.Mutex
	refreshing map[string]*refreshCall

	now func() time.Time // for tests
}

type refreshCall struct {
	done chan struct{}
	tok  *Tokens
	sub  string // sub of the ID token in the response, "" if there was none
	err  error
}

// Transaction is the per-sign-in secret state. Keep it in the server-side
// session (never in a URL or an unencrypted cookie) and use it once.
type Transaction struct {
	State     string    `json:"state"`
	Nonce     string    `json:"nonce"`
	Verifier  string    `json:"verifier"`
	CreatedAt time.Time `json:"created_at"`
}

// Tokens is the result of a token request.
type Tokens struct {
	AccessToken  string
	RefreshToken string // empty unless offline_access was granted; NobleID rotates it on every refresh
	IDToken      string
	TokenType    string
	// Scope is what the user actually granted (they may untick scopes). Empty if the response did not say.
	Scope []string
	// Expiry is computed from expires_in in this response. Never assume a lifetime.
	Expiry time.Time
}

// HasScope reports whether s was granted.
func (t *Tokens) HasScope(s string) bool { return t != nil && slices.Contains(t.Scope, s) }

// Claims are the ID token claims NobleID emits. Raw holds every claim,
// including ones not listed here. Key accounts on Subject, never on Email.
type Claims struct {
	Subject            string `json:"sub"`
	NobleID            string `json:"nobleid"`
	NobleIDURI         string `json:"nobleid_uri"`
	Name               string `json:"name,omitempty"`
	GivenName          string `json:"given_name,omitempty"`
	FamilyName         string `json:"family_name,omitempty"`
	PreferredUsername  string `json:"preferred_username,omitempty"`
	Profile            string `json:"profile,omitempty"`
	Picture            string `json:"picture,omitempty"`
	Website            string `json:"website,omitempty"`
	Email              string `json:"email,omitempty"`
	EmailVerified      bool   `json:"email_verified,omitempty"` // link accounts by email only when true
	IdentityVerified   bool   `json:"identity_verified,omitempty"`
	VerifiedResearcher bool   `json:"nobleid_verified_researcher,omitempty"`
	ORCID              string `json:"orcid,omitempty"`
	ORCIDVerified      bool   `json:"orcid_verified,omitempty"`
	UpdatedAt          int64  `json:"updated_at,omitempty"`
	// profile scope. VerificationLevel is "profile" < "orcid" < "authorship"
	// ("incomplete" only on refresh); it is not an identity check.
	ProfileComplete   bool   `json:"profile_complete,omitempty"`
	VerificationLevel string `json:"verification_level,omitempty"`
	// affiliations scope: the primary affiliation as entered. Self-declared.
	Affiliation *Affiliation `json:"affiliation,omitempty"`
	AuthTime    int64        `json:"auth_time,omitempty"`
	AMR         []string     `json:"amr,omitempty"`

	Raw map[string]any `json:"-"`
}

// Affiliation is the primary affiliation as the person entered it. ROR is a
// https://ror.org/ URL, present only when they chose one. Not verified.
type Affiliation struct {
	Name string `json:"name"`
	ROR  string `json:"ror,omitempty"`
}

// SignIn is the result of a completed sign-in.
type SignIn struct {
	Tokens *Tokens
	Claims *Claims
}

// Error is an OAuth-style error. Code is the OAuth error code (for example
// access_denied, invalid_grant, slow_down) or one of this package's own codes
// (invalid_state, invalid_issuer, expired, invalid_id_token, server_error).
// It never contains token values.
type Error struct {
	Code        string
	Description string
	Status      int           // HTTP status from the provider, when there was one
	RetryAfter  time.Duration // set on 429 slow_down when the provider sent Retry-After
	err         error
}

func (e *Error) Error() string {
	if e.Description != "" {
		return "nobleid: " + e.Code + ": " + e.Description
	}
	return "nobleid: " + e.Code
}

// Unwrap returns the underlying library error, if any. Library errors are
// kept out of Error() so nothing they might echo ends up in a log line.
func (e *Error) Unwrap() error { return e.err }

func newErr(code, desc string) *Error { return &Error{Code: code, Description: desc} }

func isLocalHost(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

// New discovers the provider and returns a Client.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.ClientID == "" {
		return nil, newErr("invalid_request", "ClientID is required")
	}
	if cfg.RedirectURL == "" {
		return nil, newErr("invalid_request", "RedirectURL is required")
	}
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = DefaultIssuer
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return nil, newErr("invalid_request", "Issuer is not a URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLocalHost(u.Hostname())) {
		return nil, newErr("invalid_request", "the issuer must be https (http is allowed only for localhost)")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{
			Timeout: 10 * time.Second,
			// Never follow a redirect: the 3xx itself is returned and treated as an error.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	// go-oidc keeps this context for JWKS refreshes, so drop its cancellation.
	pctx := oidc.ClientContext(context.WithoutCancel(ctx), hc)
	provider, err := oidc.NewProvider(pctx, issuer)
	if err != nil {
		return nil, &Error{Code: "server_error", Description: "discovery failed", err: err}
	}
	var meta struct {
		Issuer     string `json:"issuer"`
		Revocation string `json:"revocation_endpoint"`
		UserInfo   string `json:"userinfo_endpoint"`
		JWKS       string `json:"jwks_uri"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, &Error{Code: "server_error", Description: "discovery document unreadable", err: err}
	}
	// Tokens and secrets go to these endpoints: https only (http only when the
	// issuer itself is a localhost mock, and then only to localhost).
	for _, raw := range []string{provider.Endpoint().AuthURL, provider.Endpoint().TokenURL, meta.UserInfo, meta.Revocation, meta.JWKS} {
		if raw == "" {
			continue
		}
		e, err := url.Parse(raw)
		if err != nil || e.Host == "" || !(e.Scheme == "https" || (u.Scheme == "http" && e.Scheme == "http" && isLocalHost(e.Hostname()))) {
			return nil, newErr("invalid_request", "discovery lists an endpoint that is not https")
		}
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes
	}
	if !slices.Contains(scopes, oidc.ScopeOpenID) {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}

	ep := provider.Endpoint()
	switch {
	case cfg.ClientSecret == "":
		ep.AuthStyle = oauth2.AuthStyleInParams // public client: client_id in the body, no secret
	case cfg.AuthMethod == ClientSecretPost:
		ep.AuthStyle = oauth2.AuthStyleInParams
	default:
		// Set explicitly so x/oauth2 never auto-probes (it would try both styles).
		ep.AuthStyle = oauth2.AuthStyleInHeader
	}

	return &Client{
		issuer:       meta.Issuer,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		authMethod:   cfg.AuthMethod,
		httpClient:   hc,
		provider:     provider,
		// NobleID signs ID tokens with ES256 only; go-oidc checks iss, aud and
		// exp, and its RemoteKeySet re-fetches the JWKS on an unknown kid.
		verifier: provider.Verifier(&oidc.Config{
			ClientID:             cfg.ClientID,
			SupportedSigningAlgs: []string{oidc.ES256},
		}),
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     ep,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
		userinfoURL:   meta.UserInfo,
		revocationURL: meta.Revocation,
		worksURL:      strings.TrimSuffix(meta.Issuer, "/") + "/oauth/works",
		refreshing:    map[string]*refreshCall{},
		now:           time.Now,
	}, nil
}

// Issuer returns the discovered issuer identifier.
func (c *Client) Issuer() string { return c.issuer }

func randomString() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// StartSignIn returns the authorization URL to redirect the browser to, and
// the Transaction to keep in the server-side session until the callback.
func (c *Client) StartSignIn(extra ...oauth2.AuthCodeOption) (string, Transaction) {
	tx := Transaction{
		State:     randomString(),
		Nonce:     randomString(),
		Verifier:  oauth2.GenerateVerifier(),
		CreatedAt: c.now(),
	}
	opts := append([]oauth2.AuthCodeOption{oidc.Nonce(tx.Nonce), oauth2.S256ChallengeOption(tx.Verifier)}, extra...)
	return c.oauth.AuthCodeURL(tx.State, opts...), tx
}

// FinishSignIn completes sign-in on the redirect URI. query is the callback's
// query string (r.URL.Query()); tx is what StartSignIn returned. Delete tx from
// the session before calling, whatever the outcome.
//
// It checks, in this order: a sign-in is in progress, state matches, iss is
// the issuer (a missing iss is rejected), then surfaces any error the provider
// sent, then requires a code and a flow younger than MaxFlowAge. Only then does
// it exchange the code (with the PKCE verifier) and verify the ID token (ES256
// signature via JWKS, iss, aud, exp) and its nonce.
func (c *Client) FinishSignIn(ctx context.Context, query url.Values, tx *Transaction) (*SignIn, error) {
	if tx == nil || tx.State == "" || tx.Verifier == "" || tx.Nonce == "" {
		return nil, newErr("invalid_state", "no sign-in in progress")
	}
	if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(tx.State)) != 1 {
		return nil, newErr("invalid_state", "state does not match")
	}
	if iss := query.Get("iss"); iss == "" || iss != c.issuer {
		return nil, newErr("invalid_issuer", "the response did not come from the expected issuer")
	}
	if e := query.Get("error"); e != "" {
		return nil, newErr(e, query.Get("error_description"))
	}
	code := query.Get("code")
	if code == "" {
		return nil, newErr("invalid_request", "no authorization code")
	}
	if c.now().Sub(tx.CreatedAt) > MaxFlowAge {
		return nil, newErr("expired", "sign-in took too long; start again")
	}

	tok, err := c.oauth.Exchange(c.ctx(ctx), code, oauth2.VerifierOption(tx.Verifier))
	if err != nil {
		return nil, wrap(err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return nil, newErr("invalid_id_token", "the token response has no id_token")
	}
	claims, err := c.verifyIDToken(ctx, rawID)
	if err != nil {
		return nil, err
	}
	n, _ := claims.Raw["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(n), []byte(tx.Nonce)) != 1 {
		return nil, newErr("invalid_id_token", "nonce does not match")
	}
	t := toTokens(tok, rawID)
	if len(t.Scope) == 0 {
		t.Scope = slices.Clone(c.oauth.Scopes) // RFC 6749 5.1: omitted scope = as requested
	}
	return &SignIn{Tokens: t, Claims: claims}, nil
}

func (c *Client) verifyIDToken(ctx context.Context, raw string) (*Claims, error) {
	idt, err := c.verifier.Verify(c.ctx(ctx), raw)
	if err != nil {
		return nil, &Error{Code: "invalid_id_token", Description: "ID token verification failed", err: err}
	}
	var cl Claims
	if err := idt.Claims(&cl); err != nil {
		return nil, &Error{Code: "invalid_id_token", Description: "ID token claims unreadable", err: err}
	}
	if err := idt.Claims(&cl.Raw); err != nil {
		return nil, &Error{Code: "invalid_id_token", Description: "ID token claims unreadable", err: err}
	}
	if err := checkSubAndAzp(cl.Raw, idt.Audience, c.clientID); err != nil {
		return nil, err
	}
	return &cl, nil
}

// checkSubAndAzp requires a non-empty sub and, when the token names more than
// one audience or carries azp at all, requires azp to be this client
// (OpenID Connect Core 3.1.3.7, steps 4 and 5).
func checkSubAndAzp(raw map[string]any, aud []string, clientID string) error {
	if sub, _ := raw["sub"].(string); sub == "" {
		return newErr("invalid_id_token", "the ID token has no sub")
	}
	azpRaw, hasAzp := raw["azp"]
	if len(aud) > 1 || hasAzp {
		if azp, _ := azpRaw.(string); azp != clientID {
			return newErr("invalid_id_token", "the ID token was issued to another client (azp)")
		}
	}
	return nil
}

// UserInfo returns the userinfo response as a raw JSON object, so that
// userinfo-only claims (research_interests, affiliations,
// verified_authorship_count, ...) are kept. If expectedSub is not empty, the
// response's sub must equal it (pass the ID token's sub).
func (c *Client) UserInfo(ctx context.Context, accessToken, expectedSub string) (map[string]any, error) {
	if c.userinfoURL == "" {
		return nil, newErr("server_error", "the provider has no userinfo_endpoint")
	}
	var m map[string]any
	if err := c.getJSON(ctx, c.userinfoURL, accessToken, &m); err != nil {
		return nil, err
	}
	if expectedSub != "" {
		if sub, _ := m["sub"].(string); sub != expectedSub {
			return nil, newErr("invalid_token", "userinfo sub does not match the ID token")
		}
	}
	return m, nil
}

// Works lists the user's registered works (needs the works scope).
// limit is 1..100, offset >= 0. The JSON object is returned as is.
func (c *Client) Works(ctx context.Context, accessToken string, limit, offset int) (map[string]any, error) {
	if limit < 1 || limit > 100 || offset < 0 {
		return nil, newErr("invalid_request", "limit must be 1..100 and offset >= 0")
	}
	u := c.worksURL + "?" + url.Values{"limit": {strconv.Itoa(limit)}, "offset": {strconv.Itoa(offset)}}.Encode()
	var m map[string]any
	if err := c.getJSON(ctx, u, accessToken, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// Refresh uses a refresh token and returns the new tokens, including the
// ROTATED refresh token: store it and discard the old one. Presenting a used
// refresh token again revokes the whole session, so calls here with the same
// token share one request (run in its own goroutine, so a caller whose ctx
// is cancelled does not cancel it); across processes or servers, serialise refreshes
// per session yourself. On an *Error with Code "invalid_grant", sign the user
// out. An ID token in the response is verified (it carries no nonce), and its
// sub must equal expectedSub: pass the sub of the signed-in user (from the ID
// token at sign-in). A different sub fails with Code "invalid_id_token".
func (c *Client) Refresh(ctx context.Context, refreshToken, expectedSub string) (*Tokens, error) {
	if refreshToken == "" {
		return nil, newErr("invalid_request", "no refresh token")
	}
	if expectedSub == "" {
		return nil, newErr("invalid_request", "no expected sub")
	}
	sum := sha256.Sum256([]byte(refreshToken))
	key := hex.EncodeToString(sum[:])

	c.mu.Lock()
	call, ok := c.refreshing[key]
	if !ok {
		call = &refreshCall{done: make(chan struct{})}
		c.refreshing[key] = call
		// The request runs on its own, detached from this caller's context and
		// bounded by refreshTimeout: a caller that gives up must not cancel it
		// half-way, or the next caller would send the same token again.
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
		go func() {
			defer cancel()
			call.tok, call.sub, call.err = c.doRefresh(rctx, refreshToken)
			// Publish, then remove: a caller arriving in between shares this
			// result instead of sending the spent token again.
			close(call.done)
			c.mu.Lock()
			delete(c.refreshing, key)
			c.mu.Unlock()
		}()
	}
	c.mu.Unlock()

	select {
	case <-call.done:
		return checkRefreshSub(call, expectedSub)
	case <-ctx.Done():
		return nil, &Error{Code: "server_error", Description: "cancelled", err: ctx.Err()}
	}
}

// checkRefreshSub is applied per caller, so a shared request is checked
// against each caller's own user.
func checkRefreshSub(call *refreshCall, expectedSub string) (*Tokens, error) {
	if call.err != nil {
		return nil, call.err
	}
	if call.tok.IDToken != "" && call.sub != expectedSub {
		return nil, newErr("invalid_id_token", "refreshed ID token is for a different user")
	}
	return call.tok, nil
}

func (c *Client) doRefresh(ctx context.Context, refreshToken string) (*Tokens, string, error) {
	// An empty access token makes the source refresh immediately.
	tok, err := c.oauth.TokenSource(c.ctx(ctx), &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return nil, "", wrap(err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	sub := ""
	if rawID != "" {
		claims, err := c.verifyIDToken(ctx, rawID)
		if err != nil {
			return nil, "", err
		}
		sub = claims.Subject
	}
	return toTokens(tok, rawID), sub, nil
}

// Revoke revokes a token (RFC 7009) at the discovered revocation_endpoint.
// hint is "refresh_token", "access_token" or "". Revoking a refresh token also
// ends the access tokens issued from it. NobleID has no end-session endpoint:
// sign-out is revoke plus clearing your own session.
func (c *Client) Revoke(ctx context.Context, token, hint string) error {
	if c.revocationURL == "" {
		return newErr("server_error", "the provider has no revocation_endpoint")
	}
	form := url.Values{"token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	useBasic := c.clientSecret != "" && c.authMethod == ClientSecretBasic
	if !useBasic {
		form.Set("client_id", c.clientID)
		if c.clientSecret != "" {
			form.Set("client_secret", c.clientSecret)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.revocationURL, strings.NewReader(form.Encode()))
	if err != nil {
		return &Error{Code: "server_error", Description: "could not build the revocation request"}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if useBasic {
		// RFC 6749 2.3.1: form-urlencode id and secret, then base64.
		req.SetBasicAuth(url.QueryEscape(c.clientID), url.QueryEscape(c.clientSecret))
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &Error{Code: "server_error", Description: "revocation request failed", err: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return httpError(resp, body)
}

func (c *Client) getJSON(ctx context.Context, u, accessToken string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return &Error{Code: "server_error", Description: "could not build the request"}
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &Error{Code: "server_error", Description: "request failed", err: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return httpError(resp, body)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return &Error{Code: "server_error", Description: "response is not JSON", Status: resp.StatusCode}
	}
	return nil
}

// ctx makes x/oauth2 and go-oidc use our HTTP client.
func (c *Client) ctx(ctx context.Context) context.Context {
	return oidc.ClientContext(context.WithValue(ctx, oauth2.HTTPClient, c.httpClient), c.httpClient)
}

func toTokens(t *oauth2.Token, idToken string) *Tokens {
	out := &Tokens{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		IDToken:      idToken,
		TokenType:    t.TokenType,
		Expiry:       t.Expiry,
	}
	if s, ok := t.Extra("scope").(string); ok {
		out.Scope = strings.Fields(s) // space-separated
	}
	return out
}

func retryAfter(resp *http.Response) time.Duration {
	if resp == nil {
		return 0
	}
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t)
	}
	return 0
}

func httpError(resp *http.Response, body []byte) *Error {
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &e)
	if e.Error == "" {
		// Bearer errors may arrive only in WWW-Authenticate.
		if h := resp.Header.Get("WWW-Authenticate"); strings.Contains(h, `error="`) {
			rest := h[strings.Index(h, `error="`)+7:]
			if i := strings.IndexByte(rest, '"'); i > 0 {
				e.Error = rest[:i]
			}
		}
	}
	if e.Error == "" {
		e.Error = "http_" + strconv.Itoa(resp.StatusCode)
	}
	return &Error{Code: e.Error, Description: e.Description, Status: resp.StatusCode, RetryAfter: retryAfter(resp)}
}

// wrap turns x/oauth2 errors into *Error without copying response bodies.
func wrap(err error) error {
	var oe *Error
	if errors.As(err, &oe) {
		return oe
	}
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		e := &Error{Code: re.ErrorCode, Description: re.ErrorDescription, err: errors.New("token endpoint error")}
		if re.Response != nil {
			e.Status = re.Response.StatusCode
			e.RetryAfter = retryAfter(re.Response)
		}
		if e.Code == "" {
			e.Code = fmt.Sprintf("http_%d", e.Status)
		}
		return e
	}
	return &Error{Code: "server_error", Description: "token request failed", err: err}
}
