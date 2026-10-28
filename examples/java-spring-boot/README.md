# Sign in with NobleID: Spring Boot

A minimal confidential-client web app on Spring Boot 4.1 and Spring Security's
OAuth2 client (`spring-boot-starter-security-oauth2-client`). The client secret
and the tokens stay on the server; the browser only gets an HttpOnly session
cookie.

On Spring Boot 3.5 the NobleID settings below are the same; the starters are
`spring-boot-starter-web` and `spring-boot-starter-oauth2-client`, and Jackson
is `com.fasterxml.jackson`. Boot 3.5 is past the end of its open-source
support, so use Boot 4 for anything you run.

| Route | What it does |
|---|---|
| `GET /` | Signed out, or the ID-token claims merged with userinfo |
| `GET /login` | Starts sign-in (state, nonce, PKCE S256) |
| `GET /login/oauth2/code/nobleid` | The callback, handled by Spring Security |
| `GET /works` | The user's works from `/oauth/works` |
| `POST /refresh` | Refresh-token grant now; stores the rotated refresh token |
| `POST /logout` | Revokes the refresh and access tokens, then clears the session |

## Run

Java 17 or later and Maven 3.9.

```sh
cp .env.example .env        # fill in your client id and secret
set -a; . ./.env; set +a
mvn -DskipTests package
java -jar target/nobleid-spring-boot-example.jar
```

Open http://localhost:8080. Register the redirect URI
`http://localhost:8080/login/oauth2/code/nobleid` for your application.

## The Spring settings NobleID needs

Most of the work is configuration. Each item below is in this example.

| Setting | Why |
|---|---|
| `issuer-uri: https://id.nobleid.org` | Endpoints come from discovery. The authorization endpoint is on a different host from the issuer; that is expected. |
| `client-authentication-method: client_secret_basic` | Or `client_secret_post`. Never both. |
| `scope: openid,profile,email,orcid,affiliations,works,offline_access` | Comma-separated in Spring properties; sent space-separated. |
| `redirect-uri` ending in `/login/oauth2/code/nobleid` | Spring Security only processes callbacks on `/login/oauth2/code/{registrationId}`. |
| `OidcIdTokenDecoderFactory` with `setJwsAlgorithmResolver(r -> SignatureAlgorithm.ES256)` | ID tokens are ES256. Spring defaults to RS256 and rejects them otherwise. |
| `OAuth2AuthorizationRequestCustomizers.withPkce()` | Spring adds PKCE automatically only for public clients. NobleID expects S256 from confidential clients too. |
| `CallbackIssuerFilter` before `OAuth2LoginAuthenticationFilter` | Spring Security does not check the RFC 9207 `iss` parameter. The filter checks, in order: a sign-in is in progress, `state` matches, `iss` equals the issuer (missing `iss` is rejected). Only then does Spring see `error` or the code. |
| `OidcUserService.setRetrieveUserInfo(r -> true)` | Spring calls userinfo only for some scopes by default. `research_interests`, `affiliations` and `works_count` are only in userinfo. |
| A failure handler that renders the error | The default redirects to `/login?error`, which here would start a new sign-in. |
| No `end_session_endpoint`, no `OidcClientInitiatedLogoutSuccessHandler` | NobleID has no end-session endpoint. Logout is revocation plus a local session clear. |

Nonce, `state`, ID-token signature (JWKS, re-fetched on an unknown `kid`), `iss`,
`aud` and `exp` checks are Spring's defaults; nothing to add.

### Tokens

- Tokens are stored per session (`HttpSessionOAuth2AuthorizedClientRepository`).
  Use a shared session store if you run more than one instance.
- The access token lasts minutes; its expiry comes from `expires_in`. `/works`
  refreshes first when it is about to expire.
- The refresh token rotates on every use, and replaying an old one revokes the
  whole family. Refreshes for a session are serialised and the new refresh
  token is stored before anything else can use the old one.
- `invalid_grant` on refresh means the grant is gone (the user removed the app,
  or the session ended): the user is signed out locally.
- Refresh-issued ID tokens carry no `nonce`, `auth_time` or `amr`. This example
  keeps the claims from sign-in and does not replace them after a refresh.
- The user can untick any scope except `openid`. Read the granted scopes from
  the token response (`OAuth2AccessToken.getScopes()`), not from what you asked
  for. Without `offline_access` there is no refresh token.

### Claims

Key accounts on `sub`, never on `email`. Link by email only when
`email_verified` is true. `orcid` is present only when the user connected
ORCID.

### Behind a proxy

Set `server.forward-headers-strategy=native` (or `framework`) so Spring builds
https URLs. The session cookie is `Secure` whenever `REDIRECT_URI` is https.

Only do this behind a reverse proxy you control, one that overwrites (not
appends to) `Forwarded` and `X-Forwarded-*` and that is the only way to reach
the app. With either setting, Spring trusts those headers for the request's
scheme, host and client address, so a client that can reach the app directly
can set them to anything. With `native`, also restrict which proxies are
trusted (`server.tomcat.remoteip.internal-proxies`).

## Troubleshooting

| Symptom | Cause |
|---|---|
| `invalid_id_token` ... `RS256` / signature errors | The ES256 decoder factory bean is missing. |
| `invalid_grant` "PKCE verification failed" or no `code_challenge` | `withPkce()` customizer not set on the authorization request resolver. |
| Claims lack `affiliations` or `works_count` | userinfo was not called; see `setRetrieveUserInfo`. |
| 404 on the callback | `REDIRECT_URI` path is not `/login/oauth2/code/nobleid`. |
| Signed out after a refresh | The refresh token was reused (two refreshes in parallel) or revoked. |
| `slow_down` | Rate limited. Back off and retry later. |

## Test

From the kit root: `node test/run-example.mjs java-spring-boot` (needs `java`
and `mvn` on `PATH`). It runs against the local mock provider only.
