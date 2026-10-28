# Sign in with NobleID: Next.js + Auth.js

A Next.js (App Router) app that signs users in with NobleID using
[Auth.js](https://authjs.dev) v5 (`next-auth@5.0.0-beta.32`) and a custom
OpenID Connect provider. Confidential client: the client secret stays on the
server. The tokens are kept in the encrypted Auth.js session cookie (see
[Tokens and the session](#tokens-and-the-session)): the browser holds them,
but cannot read them without `AUTH_SECRET`.

> **Auth.js v5 is still a beta.** This example pins `next-auth@5.0.0-beta.32`
> exactly. Re-test before you move to another beta. For **v4**, see
> [next-auth v4](#next-auth-v4) below.

| Package | Version |
|---|---|
| next | 16.4.2 (postcss overridden to 8.5.31) |
| react, react-dom | 19.2.8 |
| next-auth | 5.0.0-beta.32 (uses @auth/core 0.41.3, oauth4webapi 3.x) |
| jose | 6.2.12 |

## Run it

```sh
cp .env.example .env.local   # fill in CLIENT_ID, CLIENT_SECRET, AUTH_SECRET
npm ci
npm run build && npm start -- -p 3000   # listens on localhost only
```

Register `http://localhost:3000/api/auth/callback/nobleid` as a redirect URI
for your NobleID client. The redirect URI is always
`AUTH_URL + /api/auth/callback/nobleid`.

To try it without credentials, run the kit's local mock and end-to-end test
from the repository root: `node test/run-example.mjs nextjs-authjs`.

## Routes

| Route | What it does |
|---|---|
| `GET /` | Signed out: a "Sign in with NobleID" button. Signed in: the ID-token claims merged with userinfo, in `<pre id="claims">`. |
| `POST /api/auth/signin/nobleid` | Auth.js: starts sign-in (state, nonce, PKCE S256) and redirects to NobleID. The button posts here through a server action. |
| `GET /api/auth/callback/nobleid` | Auth.js: the redirect URI. |
| `GET /works` | The user's works from `/oauth/works` (needs the `works` scope). |
| `POST /refresh` | One refresh-token grant; stores the rotated refresh token. |
| `POST /logout` | Revokes the refresh and access tokens, clears the session cookie. |
| `/signin` | Error page (`id="error"`) and sign-in button. |

## The provider

```ts
{
  id: "nobleid",
  type: "oidc",
  issuer: process.env.ISSUER ?? "https://id.nobleid.org",
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  checks: ["pkce", "state", "nonce"],
  authorization: { params: { scope: "openid profile email orcid affiliations works offline_access" } },
  client: { token_endpoint_auth_method: "client_secret_basic", id_token_signed_response_alg: "ES256" },
}
```

Auth.js reads every endpoint from discovery, including the authorization
endpoint, which is on a different host than the issuer. Nothing is hardcoded.

## What Auth.js checks, and what this example adds

Read from `@auth/core` 0.41.3 / `oauth4webapi`, and exercised by the kit's tests.

| Check | Who |
|---|---|
| A sign-in is in progress (state cookie present) | Auth.js |
| `iss` on the callback equals the issuer (RFC 9207); a missing `iss` is rejected because discovery says `authorization_response_iss_parameter_supported` | Auth.js (oauth4webapi). It checks `iss` just before `state`; both come before any `error` and before the code exchange. |
| `state` matches | Auth.js |
| `error` from NobleID surfaced only after the two checks above | Auth.js |
| PKCE S256, nonce, `aud`, `iss`, `exp` of the ID token, `alg` = ES256 | Auth.js |
| **ID token signature** (ES256, key from `jwks_uri`, re-fetched on an unknown `kid`) | **This example** (`jose`, in the `jwt` callback). Auth.js does not verify the signature of an ID token from the token endpoint; it relies on TLS (OIDC Core 3.1.3.7). |
| userinfo `sub` equals the ID token `sub` | This example |
| Issuer must be https (http only for a loopback issuer, i.e. the local mock) | This example. Auth.js allows http to any host. |

Account keys: use `sub`, never `email`. Only link by email when
`email_verified` is true.

## Tokens and the session

`session: { strategy: "jwt", maxAge: 8 * 60 * 60 }`. The access token,
refresh token and their expiry are kept only in the Auth.js session cookie,
which is encrypted (JWE) with `AUTH_SECRET`, HttpOnly and SameSite=Lax (Secure
on https). Nothing is stored on the server, so the tokens travel with every
request and a copied cookie keeps working until it expires (8 hours) or the
refresh token is revoked. Signing out revokes the tokens at NobleID, which
makes a copied cookie useless for API calls, but the app cannot revoke the
cookie itself. If you need server-side revocation of sessions, use an Auth.js
database adapter (`session: { strategy: "database" }`) and keep the tokens in
your database instead. The
`session` callback returns claims and flags only, so neither `auth()` nor
`/api/auth/session` ever returns a token. Server code that needs the access
token (`/works`, `/refresh`, `/logout`) decrypts the cookie with
`getToken()` from `next-auth/jwt`.

The granted scope is read from the token response, because the user can untick
scopes on the consent screen. Without `offline_access` there is no refresh
token and no refresh button.

## Why refresh is an explicit POST, not automatic

A common Auth.js pattern refreshes the access token inside the `jwt` callback
whenever it has expired. **Do not do that with NobleID.** The `jwt` callback
runs on every session read: every server component, route handler and
`/api/auth/session` call, often several in parallel for one page. NobleID
rotates the refresh token on every use and treats a second use of an old one
as theft, revoking the whole session. Parallel reads would each spend the same
refresh token. And a server component cannot write cookies, so even a single
successful refresh there would lose the rotated token, and the next read would
replay the old one.

So this example refreshes in one place: `POST /refresh` (a route handler)
checks the origin and a CSRF token, then calls `unstable_update({ refresh: true })`.
That runs the `jwt` callback once with `trigger: "update"`; it performs one
refresh-token grant and returns the new tokens, and Auth.js writes them to the
cookie. Concurrent refreshes of the same token inside one process share one
request. On `invalid_grant` the callback returns `null`, which signs the user
out. Other failures (such as `slow_down`) keep the session and are shown.

`/works` never refreshes: if the access token has expired (read `expires_in`,
15 minutes today) it asks the user to refresh first. In a real app, refresh
from one serialised place (a route handler, a server action, or a background
job holding a per-user lock) shortly before expiry.

## Errors

`pages.signIn` and `pages.error` both point at `/signin`, which renders
`id="error"`. Auth.js puts its own error type in `?error=`:

| `?error=` | Meaning |
|---|---|
| `OAuthCallbackError` | NobleID redirected back with an `error`, after `state` and `iss` passed. Auth.js drops the provider's code; the route handler in `app/api/auth/[...nextauth]/route.ts` adds it back as `provider_error` (e.g. `access_denied`), only in that case. |
| `Configuration` | Anything else: wrong `state`, wrong or missing `iss`, bad nonce, `aud` or signature, a failed exchange, or a misconfigured app. Auth.js does not distinguish these to the browser; the server log has the reason. |

## Sign-out

NobleID has no end-session endpoint. `POST /logout` checks the origin and the
CSRF token and calls Auth.js `signOut()`. Its `events.signOut` revokes the
refresh token (which also ends its access tokens) and the access token at the
revocation endpoint (RFC 7009), then Auth.js clears the session cookie.

## CSRF

- Auth.js routes: its own double-submit CSRF token.
- Server actions (the sign-in button): Next.js compares `Origin` with the host.
- `POST /refresh` and `POST /logout`: `Origin` must equal the app origin, and
  the hidden `csrf` input must match a random value stored in the session.

## next-auth v4

v4 uses `openid-client` v5 and needs the ID-token settings spelled out:

```js
{
  id: "nobleid",
  name: "NobleID",
  type: "oauth",
  wellKnown: "https://id.nobleid.org/.well-known/openid-configuration",
  idToken: true,
  checks: ["pkce", "state", "nonce"],
  client: { id_token_signed_response_alg: "ES256" }, // v4 does not accept ES256 unless told
  authorization: { params: { scope: "openid profile email orcid affiliations works offline_access" } },
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  profile(p) { return { id: p.sub, name: p.name, email: p.email, image: p.picture }; },
}
```

The same refresh advice applies to v4.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `unexpected JWT "alg" header parameter` | The client expects a different algorithm. Set `id_token_signed_response_alg: "ES256"`. |
| `?error=Configuration` right after NobleID | Validation failed; read the server log. Check `ISSUER` matches discovery exactly (no trailing slash). |
| Signed out after a refresh | `invalid_grant`: the refresh token was used twice, or the user removed the app. Don't refresh in parallel. |
| No refresh button | `offline_access` was not granted. |
| `redirect_uri` rejected | Register `AUTH_URL/api/auth/callback/nobleid` exactly. |
