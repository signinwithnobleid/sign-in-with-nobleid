# Sign in with NobleID: Ruby (Sinatra + OmniAuth)

A small Sinatra app that signs users in with NobleID through
[OmniAuth](https://github.com/omniauth/omniauth) and
[omniauth_openid_connect](https://github.com/omniauth/omniauth_openid_connect).
It is a confidential client: the client secret and all tokens stay on the
server, and the browser holds only an opaque session id.

Ruby 3.2 or later.

```sh
cp .env.example .env        # then fill in your client id and secret
set -a; . ./.env; set +a
bundle install
bundle exec puma -b tcp://localhost:3000 config.ru
# open http://localhost:3000
```

Register `http://localhost:3000/auth/nobleid/callback` as a redirect URI for
your application. `REDIRECT_URI` must match it exactly.

| Variable | Example |
|---|---|
| `ISSUER` | `https://id.nobleid.org` |
| `CLIENT_ID` | `nbcl_your_client_id` |
| `CLIENT_SECRET` | `nbcs_your_client_secret` |
| `REDIRECT_URI` | `http://localhost:3000/auth/nobleid/callback` |
| `SCOPE` (optional) | `openid profile email orcid affiliations works offline_access` |

## Routes

| Route | What it does |
|---|---|
| `GET /` | Signed out, or the ID-token claims merged with userinfo |
| `GET /login` | Starts sign-in: state, nonce, PKCE S256, redirect to NobleID |
| `GET /auth/nobleid/callback` | Checks the response, exchanges the code, verifies the ID token, calls userinfo |
| `GET /works` | The user's registered works (`works` scope) |
| `POST /refresh` | Refresh-token grant; stores the rotated refresh token |
| `POST /logout` | Revokes the refresh and access tokens, clears the session |

## Settings NobleID needs

All in `app.rb`, on the `provider :nobleid` line:

| Setting | Why |
|---|---|
| `discovery: true`, `issuer: ISSUER` | Endpoints and keys come from `{issuer}/.well-known/openid-configuration`. The authorization endpoint is on a different host from the issuer; that is expected. The discovery document's `issuer` must equal `ISSUER`. |
| `client_signing_alg: :ES256` | NobleID signs ID tokens with ES256 only. With this set, any other `alg` (including `none` and `HS256`) is rejected before verification. The signature is checked against the JWKS, which is fetched on every callback, so a new signing key is picked up at once. |
| `response_type: :code`, `pkce: true` | Authorization code flow with PKCE S256, sent by confidential clients too. |
| `send_nonce: true` | The nonce is checked against the one stored in the session. |
| `client_auth_method: :basic` | `client_secret_basic`. The underlying client form-urlencodes the id and secret before base64, as RFC 6749 requires. Use `:post` for `client_secret_post`; never both. |
| `send_scope_to_token_endpoint: false` | The code exchange does not take a scope. |
| `scope:` | An array; it is sent space-separated. Users may untick any scope except `openid`, so the app reads the granted `scope` from the token response. |
| `request_path: "/login"`, `callback_path:` | OmniAuth reuses `request_path` as the callback path unless `callback_path` is set too. |

There is no end-session endpoint. Do not configure one, and do not use the
gem's `/logout` redirect; sign out by revoking tokens (below).

## What `nobleid_strategy.rb` adds

The gem does not check the RFC 9207 `iss` parameter, and it surfaces `error`
before it checks `state`. It also reads `nonce`, `code_verifier` and
`redirect_uri` from the callback URL when they are present, which would let a
crafted callback bypass those checks. `OmniAuth::Strategies::NobleID`
subclasses the gem's strategy and, on every callback, in this order:

1. requires a sign-in in progress and a matching `state` (constant-time compare),
2. requires `iss` to equal the issuer (a missing `iss` is rejected),
3. rejects callbacks that carry `nonce`, `code_verifier`, `redirect_uri`, `id_token` or `error_reason`,
4. rejects flows older than ten minutes,
5. then lets the gem surface `error` (e.g. `access_denied`) or exchange the code,
6. verifies the ID token (ES256 via JWKS, `iss`, `aud`, `exp`, and the nonce from the session only),
7. requires the userinfo `sub` to equal the ID token's `sub`.

Any failure renders a page with `id="error"` and the error code
(`OmniAuth.config.on_failure`), clears the sign-in attempt, and signs no one in.

The subclass overrides some private methods of `omniauth_openid_connect`
0.8.0. The Gemfile pins exact versions. Re-read the subclass before upgrading
the gem.

## Sessions and CSRF

- `MemorySessionStore` (in `app.rb`) keeps session data in server memory. The
  cookie holds a random id, with `HttpOnly`, `SameSite=Lax`, and `Secure` and
  the `__Host-` prefix when `REDIRECT_URI` is https. Nothing is stored for a
  visitor until sign-in starts at `GET /login`; sessions idle for 8 hours are
  dropped by a sweep that runs at most every 10 minutes. It is single-process
  only: with several processes or servers, use a shared server-side store.
- The session id is renewed after sign-in, and dropped on sign-out.
- POST routes require a hidden `authenticity_token` and, when the browser sends one, a same-origin `Origin`
  header (`Rack::Protection`).
- All output is HTML-escaped. Tokens, codes and secrets are never logged.

### Login CSRF and `GET /login`

OmniAuth 2 starts sign-in on POST only by default (CVE-2015-9284). This
example starts it on `GET /login` so that a plain link works. That means
another site can send a visitor to `/login`. Here that can only sign the visitor
in as themselves, because:

- `state` is bound to the visitor's own session, so an attacker cannot finish
  sign-in into the attacker's account (the classic login CSRF);
- every sign-in replaces the session, and nothing links a NobleID account to an
  already signed-in local account;
- a navigation that the browser labels `Sec-Fetch-Site: cross-site` is refused.

If your app links NobleID to an account that is already signed in, start
sign-in with a POST form that carries an authenticity token instead. Remove
`request_path` and `allowed_request_methods`, and keep OmniAuth's default
`request_validation_phase`.

## Tokens

- The access token lasts `expires_in` seconds, read from the token response.
  `/works` refreshes first if it has expired.
- A refresh token is issued only with `offline_access`. It rotates on every
  use: the new one replaces the old one. Presenting a used refresh token ends
  the whole session, so refreshes of the same token in one process share a
  single request. Across processes, serialise refreshes yourself.
- On `invalid_grant` during a refresh, the app signs the user out. Any other
  refresh failure signs the user out too, because NobleID may already have
  rotated the refresh token the session holds.
- Refresh-issued ID tokens have no `nonce`, `auth_time` or `amr`.
- Sign-out revokes the refresh token (which also ends its access tokens) and
  the access token at the discovered `revocation_endpoint`, then clears the
  session.
- When the rate limit is hit, NobleID answers `429` with `{"error":"slow_down"}`,
  sometimes with `Retry-After`. Back off before trying again.

## Claims

Key accounts on `sub`, never on `email`. Link by email only when
`email_verified` is `true`. `research_interests`, `affiliations` and
`works_count` come from userinfo only; the app merges userinfo
with the ID-token claims.

## Testing

From the repository root, against the local mock provider:

```sh
node test/run-example.mjs ruby-sinatra
```
