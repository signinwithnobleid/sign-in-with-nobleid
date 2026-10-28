# Rust

Helper: [`packages/rust`](../../packages/rust/README.md) (crate
`nobleid-signin`, not yet on crates.io: use a path or git dependency), over
`openidconnect` 4.0.1 with `reqwest` + rustls. Example:
[`examples/rust-axum`](../../examples/rust-axum/README.md) (axum 0.8).

```rust
let nobleid = NobleId::discover(Config::new(
    "https://id.nobleid.org",
    std::env::var("CLIENT_ID")?,
    std::env::var("CLIENT_SECRET").ok(),
    std::env::var("REDIRECT_URI")?,
)).await?;

let (url, transaction) = nobleid.start_sign_in(&["openid", "profile", "email"]);
// … keep `transaction` server-side, redirect to `url` …
let signin = nobleid.finish_sign_in(raw_query, transaction).await?;   // state → iss → error → code → ID token
let info = nobleid.userinfo(&signin.tokens.access_token, Some(signin.claims.subject().as_str())).await?;
```

Using openidconnect directly:

- `client.id_token_verifier().set_allowed_algs(vec![CoreJwsSigningAlgorithm::EcdsaP256Sha256])`:
  the default allows RS256 only.
- Define an `AdditionalClaims` type for `nobleid`, `orcid`, `identity_verified`
  and the rest; the core types drop them.
- PKCE: `PkceCodeChallenge::new_random_sha256()`, also for confidential clients.
- Check the `iss` callback parameter yourself.
- `revocation_endpoint` is not in `CoreProviderMetadata`; read it as
  additional metadata. oauth2 5's `revoke_token` refuses non-https URLs.
- Use an HTTP client with redirects disabled.
