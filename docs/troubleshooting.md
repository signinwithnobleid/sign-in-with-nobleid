# Troubleshooting

## Symptoms

| Symptom | Likely cause | Fix |
|---|---|---|
| NobleID shows an error page and never redirects back | Unknown `client_id`, or the `redirect_uri` is not registered exactly | Compare scheme, host, port, path and query with the app settings. |
| "invalid signature" / "unexpected alg" / "no matching key" on the ID token | Library expects RS256 by default | Configure ES256 (table below). |
| ID token fails after NobleID rotates keys | JWKS cached without re-fetch on unknown `kid` | Re-fetch the JWKS when the `kid` is unknown (most libraries do; some throttle re-fetches). |
| Issuer mismatch | Issuer derived from the authorization endpoint's host (`www.nobleid.org`) | The issuer is `https://id.nobleid.org`. Use discovery or set it explicitly. |
| `invalid_request` at authorize: PKCE | Public client without PKCE, or `plain` | Send `code_challenge` with `code_challenge_method=S256`. |
| `invalid_grant` at the token endpoint | Code older than 120 s, used twice, wrong `redirect_uri`, or a PKCE verifier that does not match (or is sent for a code issued without a challenge) | Exchange once, promptly, with the same `redirect_uri`. |
| `400 invalid_request` at the token endpoint | JSON body, a repeated parameter, or both Basic and `client_secret` (or a different `client_id`) in one request | Send `application/x-www-form-urlencoded`, each parameter once, one authentication method. |
| `401 invalid_client` | Wrong or unknown client id or secret, a secret sent by a public client, or malformed Basic credentials | Check the id and secret; see the table below. |
| Response mode error | Library defaults to `form_post` or `fragment` | Use `response_mode=query`. |
| Refresh worked once, then everything fails with `invalid_grant` | Two refreshes with the same refresh token (reuse detection revoked the family), or the old refresh token was kept | Store the rotated refresh token; serialise refreshes. |
| No refresh token | `offline_access` not requested, or the person unticked it | Read the granted `scope`; work without a refresh token. |
| Claims missing (`email`, `orcid`, …) | Scope not granted, or (for `orcid`) not connected through ORCID sign-in | Read `scope`; treat absent claims as unknown. |
| `affiliations`, `research_interests`, works claims missing from the ID token | They are userinfo-only | Call userinfo. |
| `403 insufficient_scope` | userinfo without `openid`, or works without `works` | Request the scope. |
| `429 slow_down` | Rate limited | Back off; honour `Retry-After`. |
| The person is signed straight back in after logout | They are still signed in to NobleID and already approved your app | Expected. To require a fresh sign-in, send `prompt=login` and check `auth_time` in the ID token. |
| Library wants an `end_session_endpoint` | There is none | Leave it empty; revoke tokens and clear your session. |

## Library settings

Settings verified by the examples in this kit against the local mock, plus
notes from NobleID's own testing.

| Library | Settings NobleID needs |
|---|---|
| **openid-client v6** (Node) | Client metadata `id_token_signed_response_alg: "ES256"`; `enableNonRepudiationChecks(config)` to verify ID token signatures; PKCE via `calculatePKCECodeChallenge`. Checks the `iss` response parameter itself. `ClientSecretBasic` form-urlencodes correctly. |
| **openid-client v5** / **next-auth v4** | `id_token_signed_response_alg: "ES256"` (the default is RS256). next-auth v4: `idToken: true`, `checks: ["pkce","state","nonce"]`. |
| **Auth.js v5** (`next-auth@5` beta, `@auth/core` 0.41) | `client: { id_token_signed_response_alg: "ES256", token_endpoint_auth_method: "client_secret_basic" }`, `checks: ["pkce","state","nonce"]`. Checks `iss`. Does **not** verify the ID token signature and never calls userinfo for `oidc` providers: do both yourself. Accepts `http` issuers for any host. Provider error codes are replaced by Auth.js types (`OAuthCallbackError`, `Configuration`). Its default JWT `sub` is a random id, not NobleID's `sub`. |
| **Authlib** (Python) | `code_challenge_method="S256"` in `client_kwargs`, or it silently sends no PKCE. ES256 comes from discovery. Does not check `iss`; reports `error` before checking `state`. Its `client_secret_basic` does not form-urlencode the credentials (use `client_secret_post`). |
| **openidconnect 4** (Rust) | `id_token_verifier().set_allowed_algs(vec![CoreJwsSigningAlgorithm::EcdsaP256Sha256])` (default allows RS256 only). Custom `AdditionalClaims` type, or NobleID claims are dropped. Does not check `iss`. `revocation_endpoint` is not in core metadata. oauth2 5's `revoke_token` refuses non-https URLs, even localhost. |
| **go-oidc v3 + x/oauth2** (Go) | `SupportedSigningAlgs: []string{oidc.ES256}`. Set `Endpoint.AuthStyle` explicitly. Neither checks `iss` nor (go-oidc) `nonce`. x/oauth2 has no revocation. |
| **league/oauth2-client** (PHP) | `scopeSeparator => ' '` (space-separated scopes), `pkceMethod => 'S256'`, `approval_prompt => null`. Its HTTP Basic provider does not form-urlencode the credentials. No ID token handling: verify with `firebase/php-jwt` (ES256 keys only) and check `iss`, `aud`, `nonce` yourself. |
| **jumbojett/openid-connect-php** | Cannot verify ES256 ID tokens (1.0.2). Not usable with NobleID. |
| **Spring Security** (6.5) | ES256 via `OidcIdTokenDecoderFactory.setJwsAlgorithmResolver(r -> SignatureAlgorithm.ES256)`. PKCE for confidential clients via `OAuth2AuthorizationRequestCustomizers.withPkce()`. Does not check `iss` (add a filter). `OidcUserService.setRetrieveUserInfo(r -> true)`. No revocation client. Do not configure RP-initiated logout. |
| **omniauth_openid_connect 0.8** (Ruby) | `client_signing_alg: :ES256`, `pkce: true`, `send_nonce: true`, `client_auth_method: :basic`, `send_scope_to_token_endpoint: false`, explicit `callback_path`. **Takes `nonce` and `code_verifier` from callback parameters**, does not check `iss`, surfaces `error` before `state`, does not compare the userinfo `sub`: use the example's strategy subclass. Never enable `OpenIDConnect.debug!` / `Rack::OAuth2.debug!` (they log tokens). |
| **ASP.NET Core OpenIdConnect** (.NET 10) | `ResponseMode = Query` (default is `form_post`), `UsePkce = true`, `TokenValidationParameters.ValidAlgorithms = ["ES256"]`, `MapInboundClaims = false`. Uses PAR automatically on .NET 9+ when discovery lists it. Does not check `iss`. Userinfo-only claims are dropped by default claim actions. |
| **Keycloak** (identity brokering) | PKCE S256 on, client secret sent as Basic, validate signatures with the JWKS URL, ES256. Declare `nobleid`, `orcid` and other attributes in the realm's user profile or Keycloak drops them. See [integrations/keycloak.md](integrations/keycloak.md). |
| **WordPress OpenID Connect Generic Client** (3.11) | Set the Issuer and JWKS URI fields; leave End Session empty. See [integrations/wordpress.md](integrations/wordpress.md). |

## Testing locally

Run your integration against the [local mock](../mock-oidc/README.md). Its
`/__mock/next-authorize` control can deny consent, send a wrong or missing
`iss`, a wrong `nonce` or `aud`, or untick scopes, so you can check your
error handling.
