# Local mock provider

A small stand-in for the Sign in with NobleID provider, for development and
automated tests. Node 22+, no dependencies.

```sh
node mock-oidc/server.mjs --port 9400 --clients test/clients.json
```

- Issuer: `http://localhost:9400`. Discovery at
  `/.well-known/openid-configuration` and
  `/.well-known/oauth-authorization-server`.
- Authorization endpoint: `http://127.0.0.1:9400/oauth/authorize`, a
  different host from the issuer, as in production. Use discovery.
- A fresh ES256 (P-256) signing key is generated at every start; its `kid`
  is the RFC 7638 thumbprint. No key is ever written to disk.
- `/oauth/authorize` signs in a fixed test user and approves every requested
  scope, unless a test control says otherwise.
- Clients come from a JSON file (see [`test/clients.json`](../test/clients.json)):
  `client_id`, `client_secret` (confidential only), `type`
  (`confidential` | `public`), `redirect_uris`. The bundled ones are fake and
  work nowhere else.

It mirrors the provider's public behaviour: code flow only, `iss` on every
redirect (errors included), errors before the client and redirect URI match
shown instead of redirected, PKCE S256 rules (required for public clients,
enforced when sent, downgrade refused), code single use (replay revokes),
token lifetimes (`expires_in: 900`, ID token 10 minutes, code 120 seconds),
refresh rotation with reuse detection, scope narrowing, both client
authentication methods and the exact `invalid_client` body, form-only token
requests, userinfo (header or form, never query), `/oauth/works`,
revocation, introspection, PAR, `429 slow_down` with `Retry-After`, and CORS.

It emits `verified_authorship_count` in userinfo under the `works` scope,
and `profile_complete`, `verification_level` (`profile` scope) and
`affiliation` (`affiliations` scope) in the ID token and userinfo, as NobleID
does.

It is not the provider. It has no persistence, no rate limiting unless asked,
and no real accounts.

**It signs anyone in, without a password.** It answers only clients on this
machine: a request from another address, addressed to a host name other than
`localhost`/`127.0.0.1`/`[::1]`, or carrying a proxy's forwarding header gets
`403`, and the test controls refuse requests from web pages. Do not put it
behind a proxy, tunnel or port forward. Its issuer is always
`http://localhost:<port>`, so a client configured for it cannot be pointed at
NobleID by accident, and NobleID's tokens are never accepted by it.

## Test controls

Only the mock has these. JSON in, JSON out.

| Endpoint | Body | Effect |
|---|---|---|
| `POST /__mock/next-authorize` | `{ "deny": true }` | Next authorize: `access_denied` |
| | `{ "badIss": "https://evil.example" }`, `{ "omitIss": true }` | Next authorize: wrong or missing `iss` |
| | `{ "badNonce": true }`, `{ "badAud": true }` | Next ID token: wrong `nonce` / `aud` |
| | `{ "untick": ["email", "offline_access"] }` | The user unticks scopes |
| | `{ "loginRequired": true }`, `{ "consentRequired": true }` | For `prompt=none` |
| | `{ "error": "server_error", "error_description": "…" }` | Any error redirect |
| `POST /__mock/config` | `{ "cfg": { "accessTokenTtl": 5 }, "user": { "orcid": null } }` | Change lifetimes or the test user |
| `POST /__mock/rate-limit` | `{ "count": 1, "retryAfter": 3 }` | Next N protocol requests get `429` |
| `POST /__mock/rotate-key` | | New signing key; the old one stays in the JWKS |
| `POST /__mock/expire-codes` | | Expire outstanding codes |
| `POST /__mock/reset` | | Forget all tokens, grants and overrides |
| `GET /__mock/state` | | Live token counts and refresh families per client, last authorize parameters, last token request's auth method |

## As a library

```js
import { createMock } from "./mock-oidc/server.mjs";
const mock = createMock({ clients });
await mock.listen(0);          // random port
console.log(mock.issuer);
await mock.close();
```
