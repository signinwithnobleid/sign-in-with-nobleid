# Rust example (axum + openidconnect)

A minimal server-rendered app using [axum](https://crates.io/crates/axum) and
[`nobleid-signin`](../../packages/rust/), which wraps
[`openidconnect`](https://crates.io/crates/openidconnect) 4.0.1.
Confidential client: the secret and the tokens stay on the server.

## Run against NobleID

1. Register a confidential app at https://www.nobleid.org/dashboard/oauth-apps
   with redirect URI `http://localhost:3000/callback` (loopback `http` is
   allowed for development; use `https` in production).
2. ```sh
   cd examples/rust-axum
   cp .env.example .env    # fill in CLIENT_ID and CLIENT_SECRET
   set -a; . ./.env; set +a
   cargo run --release --locked
   ```
3. Open http://localhost:3000.

Rust 1.88 or newer.

## Run against the local mock

```sh
node test/run-example.mjs rust-axum
```

The build goes to `$CARGO_TARGET_DIR`, or `test/.build/rust` when that is unset.

## What it shows

| Route | |
|---|---|
| `GET /` | Signed out, or the merged ID-token and userinfo claims |
| `GET /login` | state + nonce + PKCE S256, redirect to NobleID |
| `GET /callback` | state → iss → error → code exchange → ID token verified (ES256 via JWKS) → userinfo; new session id |
| `GET /works` | `/oauth/works` |
| `POST /refresh` | refresh grant; stores the rotated refresh token |
| `POST /logout` | revoke refresh + access token, clear the session |

The session store is in memory: use a real one in production. Sessions are
keyed by a random `HttpOnly`, `SameSite=Lax` cookie (`Secure` on https). POST
routes check a CSRF token and the `Origin` header. Everything rendered is
HTML-escaped. Tokens, codes and secrets are never logged.

Environment: `ISSUER` (default `https://id.nobleid.org`), `CLIENT_ID`,
`CLIENT_SECRET`, `REDIRECT_URI`, `PORT`, `SCOPE`.
