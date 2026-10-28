# Sign in with NobleID: Go (net/http)

A minimal confidential-client web app using only the standard library
(`net/http`, `html/template`) and the [`nobleid.org/signin`](../../packages/go)
helper, which wraps `go-oidc` and `x/oauth2`. The client secret and all tokens
stay on the server; the browser only holds an opaque, random, `HttpOnly`,
`SameSite=Lax` session cookie (`Secure` when the redirect URI is https).

`nobleid.org/signin` is not published yet, so `go.mod` builds it from this
repository with a `replace` directive.

## Run

Requires Go 1.25 or later.

```
cp .env.example .env    # fill in your client id and secret
set -a; . ./.env; set +a
go run .
```

Open http://localhost:3000. Register `http://localhost:3000/callback` as a
redirect URI for your client.

| Variable | Default |
|---|---|
| `ISSUER` | `https://id.nobleid.org` |
| `CLIENT_ID` | required |
| `CLIENT_SECRET` | required |
| `REDIRECT_URI` | `http://localhost:3000/callback` |
| `PORT` | `3000` |
| `SCOPE` | `openid profile email orcid affiliations works offline_access` |

## Routes

| Route | What it does |
|---|---|
| `GET /` | Signed out: a sign-in link. Signed in: the ID token claims merged with userinfo, and the granted scope. |
| `GET /login` | Creates `state`, `nonce` and a PKCE S256 verifier, keeps them in the server-side session, redirects to NobleID. |
| `GET /callback` | Checks `state`, then `iss`, then `error`; exchanges the code; verifies the ES256 ID token and nonce; calls userinfo; issues a new session id. |
| `GET /works` | The user's works (needs the `works` scope). |
| `POST /refresh` | Refresh-token grant. Stores the rotated refresh token; one refresh per session at a time; `invalid_grant` signs the user out. |
| `POST /logout` | Revokes the refresh and access tokens, then clears the session. |

POST routes require the hidden CSRF token from the page and, when the browser
sends one, a same-origin `Origin` header.

Sessions live in memory and vanish on restart. Use a real session store in
production, and keep it server-side: it holds tokens.

## Test

From the repository root, against the local mock provider:

```
node test/run-example.mjs go-nethttp
```
