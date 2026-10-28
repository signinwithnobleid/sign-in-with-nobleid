# nobleid-signin (Rust)

A thin server-side helper for **Sign in with NobleID**, built on
[`openidconnect`](https://crates.io/crates/openidconnect) 4.0.1 with NobleID's
settings already chosen. It does no cryptography of its own.

- Discovery from `{issuer}/.well-known/openid-configuration`; its `issuer` and
  every endpoint (https only) are checked before the JWKS is fetched.
- ID tokens verified with **ES256 only** (the crate defaults to RS256) against
  the JWKS, which is fetched again once when a token carries an unknown `kid`;
  plus `iss`, `aud`, `exp` and `nonce`.
- PKCE S256, `state` and `nonce` on every sign-in.
- The RFC 9207 `iss` check on every callback, before any `error` is surfaced.
  `openidconnect` does not check `iss`; this crate does.
- Refresh-token rotation without tripping reuse detection inside one process.
- Revocation (RFC 7009).
- `reqwest` with rustls (no native TLS) and redirects disabled.

## Install

Not yet published on crates.io: use it from a checkout of this repository,
by path. Do not install a crate of this name from a registry; it is not ours.

```toml
[dependencies]
nobleid-signin = { path = "path/to/packages/rust" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Rust 1.88 or newer.

## Use

```rust
use nobleid_signin::{Config, NobleId, TokenTypeHint};

// Once, at startup. Read the secret from the environment.
let nobleid = NobleId::discover(Config::new(
    "https://id.nobleid.org",
    std::env::var("CLIENT_ID")?,
    std::env::var("CLIENT_SECRET").ok(),
    "https://app.example.com/callback",
)).await?;

// GET /login
let (url, transaction) = nobleid.start_sign_in(&["openid", "profile", "email", "offline_access"]);
// store `transaction` in the server-side session, then redirect to `url`

// GET /callback  (take the transaction out of the session first: single use)
let signin = nobleid.finish_sign_in(raw_query, session.take_transaction()).await?;
let sub = signin.claims.subject().as_str();           // key accounts on sub
let info = nobleid.userinfo(&signin.tokens.access_token, Some(sub)).await?;

// Works (scope `works`), 1..=100 per page
let page = nobleid.works(&signin.tokens.access_token, 50, 0).await?;

// Refresh (only with `offline_access`): store the rotated refresh token
if let Some(rt) = &signin.tokens.refresh_token {
    let r = nobleid.refresh(rt, Some(sub)).await?;
}

// Logout: there is no end-session endpoint. Revoke, then clear your session.
nobleid.revoke(refresh_token.secret(), TokenTypeHint::RefreshToken).await?;
nobleid.revoke(access_token.secret(), TokenTypeHint::AccessToken).await?;
```

A complete app is in [`examples/rust-axum`](../../examples/rust-axum/).

## API

| | |
|---|---|
| `NobleId::discover(Config)` | Discovery + JWKS. `http://` issuers only for `localhost`, `127.0.0.1`, `[::1]` (a local mock). `Config::client_auth` is `SecretBasic` (default) or `SecretPost`; `client_secret: None` makes a public client. |
| `start_sign_in(&[&str]) -> (Url, Transaction)` | `openid` is always sent. `Transaction { state, nonce, pkce_verifier, created_at, scopes }` is `Serialize`/`Deserialize` for any session store. |
| `finish_sign_in(query, Option<Transaction>) -> SignIn` | Checks, in order: a sign-in is in progress, `state` (constant time), `iss` equals the issuer (missing `iss` is rejected), then `error`, then `code`, then flow age (10 minutes). Then the code exchange and ID-token verification. Repeated callback parameters are rejected. |
| `userinfo(&AccessToken, Option<&str>) -> NobleIdUserInfo` | `GET` with Bearer. Pass the ID token's `sub`; a different `sub` is rejected. |
| `works(&AccessToken, limit, offset) -> WorksPage` | `/oauth/works`, scope `works`. |
| `refresh(&RefreshToken, Option<&str>) -> Refreshed` | Rotation; see below. The refresh-issued ID token is verified without a nonce. |
| `revoke(&str, TokenTypeHint)` | RFC 7009. |

`SignIn { tokens, claims }`. `TokenSet` has `access_token`, `refresh_token`
(only with `offline_access`), `id_token()`, `expires_at` (from `expires_in`,
never hardcoded) and `scopes` — the **granted** scopes: the user may untick
any scope except `openid`, so check `has_scope("works")` before calling
`works`.

NobleID claims are in `claims.additional_claims()` / `info.additional_claims()`
(`NobleIdClaims`): `nobleid`, `nobleid_uri`, `identity_verified`,
`nobleid_verified_researcher`, `profile_complete`, `verification_level`,
`affiliation` (self-declared), `orcid`, `orcid_verified`, and on userinfo only
`research_interests`, `affiliations` (self-asserted), `works_count`,
`works_endpoint` and `verified_authorship_count`. Absent means unknown, not false.
Link accounts by email only when `email_verified` is `true`.

Fill your app's profile: `profile_from_claims(&sign_in.claims, Some(&info))`
(or `profile_from_json` on raw claim sets) returns a plain `Profile`: every
field present, `None`, empty or `false` when not shared, `orcid` only when
proven through ORCID. Code `invalid_token` if userinfo is for another `sub`.
`Affiliation::start_year` also reads the string form older servers sent,
instead of failing the userinfo call. Fill only empty fields with it:
[docs/profile-data.md](../../docs/profile-data.md).

## Refresh tokens rotate

Every refresh returns a new refresh token; store it and drop the old one.
Presenting a used refresh token again ends the whole session. Inside one
process, concurrent `refresh` calls with the same token share one request,
which runs in its own task: a caller that is cancelled does not cause the
token to be sent again. Each caller verifies the refresh-issued ID token
itself; pass the `sub` you stored at sign-in as `expected_sub`.
Across processes or hosts, serialise refreshes yourself (for example a
per-session lock in your session store) and re-read the stored token after
taking the lock. On `invalid_grant`, sign the user out.

## Errors

`Error::code()` is the OAuth error code from NobleID (`access_denied`,
`invalid_grant`, `slow_down`, `invalid_token`, `insufficient_scope`, ...) or a
local one: `invalid_state`, `invalid_issuer`, `invalid_request`, `expired`,
`invalid_id_token`, `invalid_configuration`, `server_error`.
`Error::retry_after()` carries `Retry-After` where the response is read by this
crate (works, revoke); on `slow_down`, back off.

No error, and no `Debug` output of `Transaction`, `TokenSet` or `Config`,
contains a token, code or secret.

## Notes on `openidconnect`

- `IdTokenVerifier` allows RS256 only unless told otherwise; this crate sets
  ES256 (`CoreJwsSigningAlgorithm::EcdsaP256Sha256`) and nothing else.
- `openidconnect` does not check the `iss` authorization-response parameter.
- `oauth2`'s revocation helper refuses non-https endpoints, so `revoke` makes
  the RFC 7009 request itself with the same client authentication.
- `revocation_endpoint` is read through custom discovery metadata.
- Scopes are added one by one; the URL carries them space-separated.

## Tests

```sh
cargo test
```

Unit tests cover the order of the callback checks, that discovery checks the
issuer and endpoints before fetching the JWKS, that a cancelled refresh is not
sent twice, and that `Debug` never prints secrets. The end-to-end test against the local mock is
`node test/run-example.mjs rust-axum` from the repository root.
