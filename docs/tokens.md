# Tokens

| Token | Prefix | Lifetime | Notes |
|---|---|---|---|
| Authorization code | `nbac_` | 120 seconds, single use | A replayed code is refused and the tokens it already minted are revoked. |
| Access token | `nbat_` | 15 minutes (`expires_in: 900`) | Opaque. Read `expires_in` from each response; do not hardcode it. |
| ID token | (JWT) | 10 minutes | Read it once, at sign-in. Not a session token, not an API credential. |
| Refresh token | `nbrt_` | Until unused for a long period, revoked, or the person removes your app | Only with `offline_access`, and only if the person left it ticked. |
| Client secret | `nbcs_` | Until you rotate it | Confidential clients only. |
| Client id | `nbcl_` | — | Public, not a secret. |

The prefixes exist so that a leaked value is easy to recognise, for you and
for secret scanners. Never log tokens, codes or secrets.

## Endpoints

Use discovery: `https://id.nobleid.org/.well-known/openid-configuration`
(also served as `/.well-known/oauth-authorization-server`).

| Purpose | URL |
|---|---|
| Issuer | `https://id.nobleid.org` |
| Authorization | `https://www.nobleid.org/oauth/authorize` (a **different host** from the issuer: it is the consent page) |
| Token | `https://id.nobleid.org/oauth/token` |
| Userinfo | `https://id.nobleid.org/oauth/userinfo` |
| Works | `https://id.nobleid.org/oauth/works` |
| Revocation | `https://id.nobleid.org/oauth/revoke` |
| Introspection | `https://id.nobleid.org/oauth/introspect` |
| Pushed authorization requests | `https://id.nobleid.org/oauth/par` |
| JWKS | `https://id.nobleid.org/.well-known/jwks.json` |

Only `response_type=code` and `response_mode=query` are supported.
On the authorization request, send each parameter once (if one is repeated,
only the first is used).

## Token endpoint rules

- Body must be `application/x-www-form-urlencoded`. JSON is refused
  (`400 invalid_request`). Repeated parameters are refused.
- Client authentication: `client_secret_basic`, `client_secret_post`, or
  `none` for public clients. Never both methods in one request
  (`400 invalid_request`).
  For `client_secret_basic`, form-urlencode the client id and secret before
  joining them with `:` and base64-encoding (RFC 6749 §2.3.1).
- A wrong or unknown client id or secret is `401`
  `{"error":"invalid_client","error_description":"Client authentication failed"}`.
- PKCE: `S256` only (`plain` is refused). Required for public clients,
  optional for confidential clients, and recommended for everyone. If you sent
  a `code_challenge`, the `code_verifier` is always enforced. Sending a
  `code_verifier` for a code issued without a challenge is refused.

## ID token verification checklist

Your OIDC library should do all of this; make sure it is configured to.

1. Signature: `ES256` only, key from the JWKS by `kid`. Keys are P-256;
   `kid` is the RFC 7638 thumbprint. If the `kid` is unknown, fetch the JWKS
   again (keys rotate; retired keys stay published for a while). Never accept
   `alg: none` or any other algorithm.
2. `iss` is exactly `https://id.nobleid.org`.
3. `aud` contains your client id (and `azp`, if present, equals it).
4. `exp` is in the future (allow a small clock skew); `iat` is not in the future.
5. `nonce` equals the one you sent, if you sent one. NobleID includes it in
   the ID token from sign-in. Send one.
6. Optional: `auth_time` against your `max_age`; `amr` contains `"otp"` if
   you require a second factor.

ID tokens issued on refresh omit `auth_time`, `nonce` and `amr`. Do not
require a nonce on them.

## Refresh tokens

- **Rotation.** A refresh returns a new refresh token. Store it and
  discard the old one, which is now dead. (If the person has since withdrawn
  `offline_access`, no new refresh token comes back: they must sign in again
  once the access token expires.)
- **Reuse detection.** Presenting a refresh token that was already used
  revokes the whole family: every refresh token and every access token that
  descends from that sign-in. Treat it as "signed out".
- **Serialise refreshes.** Never run two refreshes of the same token at the
  same time (two browser tabs, two server workers, a middleware and a page
  both refreshing). The second one is a reuse. Use a per-session lock, or
  refresh in one place only.
- **Narrowing.** A refresh may ask for a subset of the granted scope with
  `scope=`. It can never widen it (`invalid_scope`).
- **Expiry.** Refresh tokens expire if they go unused for a long period.
- **Removal.** People can remove your app at any time under NobleID
  Settings → Connected apps. That revokes every token immediately. On
  `invalid_grant` from a refresh, sign the person out of your app.

## Revocation (RFC 7009)

`POST /oauth/revoke` with `token` and optional `token_type_hint`, using the
same client authentication as the token endpoint. Public clients send only
`client_id`.

- `200 {}` for any token, known or not, including tokens that belong to
  another client. Failed client authentication and rate limits still get
  their usual errors (`401 invalid_client`, `429 slow_down`), so check the
  status: a non-2xx response means nothing was revoked.
- Revoking a refresh token revokes its family and the access tokens minted
  from it.

## Introspection (RFC 7662)

`POST /oauth/introspect`, confidential clients only (a public client gets
`401 invalid_client`). Returns `{"active": false}` for anything that is not
one of your own live tokens.

## Userinfo

`GET` or `POST {issuer}/oauth/userinfo`.

- Token in `Authorization: Bearer …`, or (POST only) in a form body
  `access_token=…` (RFC 6750 §2.2). The form-body variant is a CORS simple
  request, useful from a browser.
- Never in the query string: a token there is ignored, so the request is
  unauthenticated. Never in both the header and the body
  (`400 invalid_request`).
- Responses are `Cache-Control: no-store`.
- Protocol endpoints answer CORS with `Access-Control-Allow-Origin: *` and no
  credentials.

## prompt and max_age

| Value | Effect |
|---|---|
| `prompt=none` | No screens. Redirects with `login_required` or `consent_required` if a screen would be needed. Cannot be combined with `login` or `consent`. |
| `prompt=login` | Asks for a fresh NobleID sign-in, unless the person signed in moments ago. To require a recent sign-in, also check the ID token's `auth_time` and reject it if it is older than you accept. |
| `prompt=consent` | Shows the consent screen even if a grant exists. |
| `prompt=select_account` | Accepted; no effect. |
| `max_age=<seconds>` | Forces a fresh sign-in if the last one is older. Do not rely on `max_age=0` yet: send `prompt=login` and check `auth_time` instead. |

A returning person who already granted your app the requested scopes is
signed in without a screen, except for public clients redirecting to a
loopback address or a custom scheme.
