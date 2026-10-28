# nobleid.org/signin (Go)

A thin server-side helper for "Sign in with NobleID", built on
[`github.com/coreos/go-oidc/v3`](https://github.com/coreos/go-oidc) and
[`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2). It does no
cryptography of its own; it configures those libraries for NobleID and adds
the checks they leave to you.

> **Not yet published.** `nobleid.org/signin` does not resolve with `go get`
> today, and no other module path is ours. Copy this directory into your project (or clone this repository) and
> point your module at it with a `replace` directive:
>
> ```
> require nobleid.org/signin v0.0.0
>
> replace nobleid.org/signin => ./third_party/nobleid-signin
> ```

Requires Go 1.25 or later. Dependencies are pinned in `go.mod` / `go.sum`.

## What it sets for you

| Setting | Why |
|---|---|
| Discovery from `{issuer}/.well-known/openid-configuration` | Endpoints live on more than one host. Never hardcode them. |
| `SupportedSigningAlgs: ["ES256"]` | NobleID signs ID tokens with ES256 only. The JWKS is re-fetched on an unknown `kid`. |
| PKCE S256 (`oauth2.GenerateVerifier`, `S256ChallengeOption`) | Sent even by confidential clients. |
| `state` and `nonce` | Random per sign-in; `state` compared in constant time, `nonce` checked against the ID token. |
| RFC 9207 `iss` check | Checked before anything else in the response is trusted. A missing `iss` is rejected. |
| `AuthStyle` set explicitly | `AuthStyleInHeader` (client_secret_basic, id and secret form-urlencoded) or `AuthStyleInParams` (client_secret_post). Never auto-probed, never both. |
| `sub` required; `azp` checked | An ID token with several audiences, or with `azp` at all, must name this client in `azp`. |
| Redirects never followed | The default HTTP client returns the 3xx itself, which is treated as an error. |
| Granted scope read from the token response | Users can untick scopes other than `openid`. |
| Expiry read from `expires_in` | Access tokens are short-lived; never assume a lifetime. |

## Use

```go
client, err := nobleid.New(ctx, nobleid.Config{
	// Issuer defaults to https://id.nobleid.org. http is accepted only for localhost / 127.0.0.1.
	ClientID:     os.Getenv("CLIENT_ID"),     // nbcl_...
	ClientSecret: os.Getenv("CLIENT_SECRET"), // nbcs_...
	RedirectURL:  "https://app.example.com/callback",
	Scopes:       []string{"openid", "profile", "email", "orcid", "affiliations", "works", "offline_access"},
})

// GET /login
authURL, tx := client.StartSignIn()
session.Transaction = &tx // server-side session only
http.Redirect(w, r, authURL, http.StatusSeeOther)

// GET /callback
tx := session.Transaction
session.Transaction = nil // single use
res, err := client.FinishSignIn(r.Context(), r.URL.Query(), tx)
if err != nil { /* *nobleid.Error: show err.Code; do not sign in */ }
info, err := client.UserInfo(r.Context(), res.Tokens.AccessToken, res.Claims.Subject)
// Key accounts on res.Claims.Subject. Link by email only if EmailVerified is true.
// Regenerate the session id here.
```

`FinishSignIn` checks, in this order: a sign-in is in progress, `state`
matches, `iss` equals the issuer, then any `error` the provider sent, then that
a `code` is present and the flow is under 10 minutes old. Only then does it
exchange the code (with the PKCE verifier) and verify the ID token: ES256
signature via JWKS, `iss`, `aud`, `exp`, then `nonce`.

`res.Claims` has the ID token claims as fields (`sub`, `nobleid`,
`nobleid_uri`, `name`, `email`, `email_verified`, `identity_verified`,
`nobleid_verified_researcher`, `profile_complete`, `verification_level`,
`affiliation`, `orcid`, `orcid_verified`, `amr`, ...) and all
of them in `Claims.Raw`. `UserInfo` returns the raw JSON object, so
userinfo-only claims (`research_interests`, `affiliations`,
`works_count`, `verified_authorship_count`) are kept; it rejects a response whose `sub`
differs from the one you pass.

### Works

```go
works, err := client.Works(ctx, accessToken, 50, 0) // limit 1..100, offset >= 0; needs the works scope
```

### Refresh

```go
t, err := client.Refresh(ctx, tokens.RefreshToken, claims.Subject) // the signed-in user's sub
var e *nobleid.Error
if errors.As(err, &e) && e.Code == "invalid_grant" { /* sign the user out */ }
tokens = t // t.RefreshToken is the NEW refresh token: store it, drop the old one
```

Refresh tokens are issued only with `offline_access` and rotate on every use.
Presenting an old one again revokes the whole session. `Refresh` shares one
request between concurrent calls with the same token in this process. The
request runs on its own (bounded by a 30 second timeout), so a caller whose
context is cancelled does not cancel it or cause the token to be sent again;
across
processes or servers, serialise refreshes per session yourself (for example a
per-session lock). An ID token in a refresh response is verified, and its `sub`
must equal the one you pass (otherwise `invalid_id_token`); it carries no
`nonce`, `auth_time` or `amr`.

### Sign out

```go
_ = client.Revoke(ctx, tokens.RefreshToken, "refresh_token") // also ends its access tokens
_ = client.Revoke(ctx, tokens.AccessToken, "access_token")
// then clear your session
```

NobleID has no end-session endpoint. Sign-out is revocation (RFC 7009, at the
discovered `revocation_endpoint`) plus clearing your own session.

### Your own HTTP client

`Config.HTTPClient` is used for every request to NobleID. If you supply one,
give it a `Timeout` and make it refuse redirects, as the default does, so a
token or client secret is never sent on to another URL:

```go
hc := &http.Client{
	Timeout:       10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}
```

### Fill your app's profile

`nobleid.ProfileFromClaims(signIn.Claims.Raw, info)` returns a plain
`*Profile` (`Name`, `GivenName`, `Picture`, `ORCID`, `Affiliation`,
`Affiliations`, …); `""`, `0`, `nil` or `false` when not shared. `ORCID` is
set only when proven through ORCID. Code `invalid_token` if userinfo is for
another `sub`. Fill only empty fields with it:
[docs/profile-data.md](../../docs/profile-data.md).

### Errors

Every error is a `*nobleid.Error` with `Code` (the OAuth error code, or
`invalid_state`, `invalid_issuer`, `expired`, `invalid_id_token`,
`server_error`), `Description`, `Status` and, on `429 slow_down`,
`RetryAfter`. Back off when you see `slow_down`. Error strings never contain
token values; the underlying library error is available through
`errors.Unwrap` and is kept out of `Error()`.

## Test

```
go vet ./...
go test -race ./...
```

The tests run against a small in-process provider (`httptest`) and cover the
check order, PKCE, client authentication, nonce, audience, `azp` and `sub`
rejection, refresh rotation and serialisation (including a cancelled caller),
redirects, and revocation.
