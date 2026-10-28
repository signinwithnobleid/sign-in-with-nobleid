# Security for integrators

A threat model for apps that use Sign in with NobleID, and the checklist
that follows from it. To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

## What you are protecting

- The person's account in **your** app (session takeover, account linking abuse).
- The tokens NobleID gave you (they read the person's claims and works).
- Your client secret (it lets anyone act as your app).

## Threats and defences

| Threat | Defence |
|---|---|
| **Login CSRF / forged callback**: an attacker makes the victim's browser complete a sign-in the attacker started, or feeds a crafted `error`. | Random `state` per sign-in, stored server-side (or in `sessionStorage` for a browser app), compared in constant time, used once. Check it **before** anything else in the callback, including `error`. |
| **Mix-up**: a response from another provider (or a lookalike) is accepted as NobleID's. | Check the `iss` response parameter equals `https://id.nobleid.org` (RFC 9207); reject a missing `iss`. Check the ID token `iss` too. |
| **Code interception**: the authorization code leaks (logs, referrer, a malicious app on the device). | PKCE S256 on every sign-in, confidential clients included. Codes are single use and short-lived. |
| **ID token replay / substitution** | Verify ES256 signature against the JWKS, `iss`, `aud`, `exp`, and `nonce`. Use a library. |
| **Open redirect into your callback** | Register exact redirect URIs. Never build the redirect URI from request data. After sign-in, redirect only to same-site paths you validate. |
| **Token theft from the browser** (XSS, extensions, shared machines) | Keep tokens on your server (confidential client or a backend-for-frontend). A browser-only app should keep tokens in memory, never in `localStorage`, URLs or logs, and should not request `offline_access`. Strict Content-Security-Policy. |
| **Refresh token theft** | Rotation plus reuse detection: a stolen refresh token used after yours (or before) revokes the family. Store refresh tokens encrypted at rest; serialise refreshes so your own app never trips reuse detection. |
| **Secret leakage** | Secret in a secret manager or environment, never in source control or client-side code. Prefixes (`nbcs_`, `nbat_`, `nbrt_`) make leaks greppable: add them to your secret scanning. Rotate in the dashboard (the old secret works for 24 hours, until you press **Revoke previous secret**); if it leaked, tick **Stop accepting the current secret now** when you rotate. |
| **Account takeover through email linking** | Key on `sub`. Link by email only when `email_verified` is `true`, ideally with the person confirming while signed in to both accounts. |
| **Over-trusting claims** | `affiliations` are self-asserted. Absent claims mean "unknown", not "false". Do not treat `preferred_username` or `name` as identifiers. |
| **Session fixation** | Issue a new session id after sign-in. Cookies `HttpOnly`, `Secure`, `SameSite=Lax`. |
| **CSRF on your own POST routes** (logout, refresh) | CSRF tokens and/or `Origin` checks. |
| **Clickjacking of your sign-in page** | `frame-ancestors 'none'` (or `X-Frame-Options: DENY`). |
| **Stale sessions after the person removes your app** | Treat `invalid_grant` on refresh and `invalid_token` from userinfo as "signed out". |
| **Rate limiting** | Back off on `429 slow_down`, honour `Retry-After`, cache discovery and JWKS. |

## Checklist

- [ ] Authorization code flow with PKCE S256, `state` and `nonce` on every sign-in.
- [ ] Callback checks, in order: sign-in in progress → `state` → `iss` → `error` → code.
- [ ] ID token verified by a library: ES256 via JWKS, `iss`, `aud`, `exp`, `nonce`.
- [ ] Granted `scope` read from the token response; missing claims handled.
- [ ] Accounts keyed on `sub`; email linking only when `email_verified` is `true`.
- [ ] Tokens stored server-side; never in URLs, logs, analytics or error reports.
- [ ] Refresh tokens rotated and stored; refreshes serialised; `invalid_grant` signs the person out.
- [ ] Logout revokes the refresh token, then clears your session.
- [ ] Exact redirect URIs registered; no wildcards; `http` only for loopback in development.
- [ ] Secret in a secret manager; rotation rehearsed.
- [ ] Session cookies `HttpOnly`, `Secure`, `SameSite=Lax`; new session id after sign-in; CSRF on POST routes.
- [ ] `429 slow_down` handled with backoff.
- [ ] Dependencies pinned and updated; your OIDC library configured for ES256 (see [troubleshooting](troubleshooting.md)).

## Single-page apps

Prefer a backend-for-frontend: your server is a confidential client, holds
the tokens, and gives the browser only an `HttpOnly` session cookie. If you
truly have no server, the browser SDK's public-client mode is safe when used
as documented: tokens in memory, no refresh tokens, a strict CSP, and no
third-party scripts on the callback page (serve the SDK itself from your own
site there).

## The browser SDK's own hardening

The SDK (`sdk/nobleid-auth.js`): checks `state` (constant time), then `iss`,
then `error`; uses each sign-in once; checks the ID token's `iss`, `aud`,
`nonce`, `exp`; sends tokens only in request bodies with
`credentials: "omit"`; never writes tokens to storage or the URL; builds all
DOM with text APIs (no `innerHTML`, no `eval`); accepts only same-site or
https `loginUrl` values; and the researcher badge links only to
`https://www.nobleid.org/` and `https://orcid.org/`.
