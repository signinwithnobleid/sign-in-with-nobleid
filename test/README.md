# Tests

Everything runs against the local mock provider in `mock-oidc/`. No real
NobleID credentials are used or needed, anywhere.

| Command | What it runs |
|---|---|
| `npm test` | everything below that the local machine has a toolchain for |
| `npm run test:mock` | protocol conformance of the mock itself |
| `npm run test:sdk` | the browser SDK and researcher badge, in Node with small DOM shims |
| `node test/run-example.mjs <name>` | one server example, end to end |
| `node test/run-example.mjs --all` | every server example |
| `node test/wordpress.test.mjs` | the WordPress plugin's exact request shape |

Examples whose toolchain is missing are reported as `SKIPPED`, never as passed.

## How an example is tested

`test/run-example.mjs` starts the mock in-process, runs the example's `setup`
commands, starts the example on a free port, then plays the browser and the
user (`test/e2e/driver.mjs`) while asking the mock what actually happened.

Each server example has an `e2e.json`:

```json
{
  "lang": "go",
  "requires": ["go"],
  "setup": ["go build -o {ROOT}/test/.bin/go-example ."],
  "start": ["{ROOT}/test/.bin/go-example"],
  "callbackPath": "/callback",
  "client": "confidential",
  "readyTimeout": 60,
  "env": { "EXTRA_VAR": "{APP_URL}" },
  "profile": { "login": "/login" }
}
```

The example receives `ISSUER`, `CLIENT_ID`, `CLIENT_SECRET`, `REDIRECT_URI`,
`PORT` and `APP_URL` in its environment. `{ROOT}`, `{PORT}`, `{ISSUER}` and
`{APP_URL}` are substituted in `setup`, `start` and `env`.

### The contract every server example follows

| Route | Behaviour |
|---|---|
| `GET /` | Signed out: the page contains `id="signed-out"`. Signed in: `<pre id="claims">` with the HTML-escaped JSON of the ID-token claims merged with the userinfo response. |
| `GET /login` | Starts sign-in: state, nonce and PKCE S256, then redirects to the authorization endpoint. |
| callback | Validates, in this order: state, `iss` (RFC 9207), then any `error`; exchanges the code; verifies the ID token (ES256 via JWKS, iss, aud, exp, nonce); calls userinfo; redirects to `/`. Any failure renders a page containing `id="error"` and the OAuth error code when the provider sent one, and never signs the user in. |
| `GET /works` | `<pre id="works">` with the JSON from `/oauth/works`. |
| `POST /refresh` | Refresh-token grant; stores the rotated refresh token. |
| `POST /logout` | Revokes the refresh token (and access token), clears the session. |

POST forms may carry hidden CSRF inputs; the driver submits every hidden input
of the form and sends a same-origin `Origin` header.

### Scenarios

1. Sign-in, claims shown (including the userinfo-only `verified_authorship_count`),
   works list, refresh rotates the token, logout revokes every token.
2. Wrong `state` is rejected.
3. Wrong `iss` and missing `iss` are rejected.
4. Denied consent shows `access_denied`.
5. ID token with the wrong `nonce` or `aud` is rejected.
6. The user unticks `email` and `offline_access`: still signed in, no email, no refresh token.

## Mock test controls

Only the mock has these (`/__mock/...`): `state`, `reset`, `next-authorize`
(`deny`, `badIss`, `omitIss`, `badNonce`, `badAud`, `untick`, `loginRequired`,
`consentRequired`, `error`), `config`, `rate-limit`, `rotate-key`,
`expire-codes`. See `mock-oidc/README.md`.
