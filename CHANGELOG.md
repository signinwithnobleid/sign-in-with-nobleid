# Changelog

All notable changes to this kit. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0 a minor version may change the helpers' API.

## 0.1.0 (2 November 2026)

The first tagged release of the Sign in with NobleID client kit.

- **Server-side helpers** in five languages, each a thin layer over a
  maintained OpenID Connect library, with NobleID's settings chosen
  (authorization code + PKCE S256, ES256 ID tokens, the RFC 9207 `iss`
  check, refresh-token rotation, revocation, `profileFromClaims`):
  - JavaScript/TypeScript `packages/node` (openid-client 6.8.8), for npm as `nobleid-signin`;
  - Python `packages/python` (Authlib), for PyPI as `nobleid-signin`;
  - Rust `packages/rust` (openidconnect 4.0.1), for crates.io as `nobleid-signin`;
  - Go `packages/go` (go-oidc v3 + x/oauth2) and PHP `packages/php`
    (league/oauth2-client + firebase/php-jwt), used from this repository.
- **Browser SDK** v2.1.1 (`sdk/`): the button, the public-client flow and the
  researcher badge, with no dependencies.
- **Eleven examples**, each tested end to end against the mock: Node, Next.js
  (Auth.js), plain HTML with the SDK, Flask, axum, Go net/http, plain PHP,
  Spring Boot, Sinatra, ASP.NET Core and WordPress (configuration only).
- **A local mock provider** (`mock-oidc/`, Node, no dependencies), so an app
  can be built and tested without a NobleID account.
- **Docs**: quickstarts per language, scopes and claims, tokens, errors,
  security advice, sign-out, the brand guide, and guides for OJS, WordPress,
  DSpace, Dataverse, Moodle, Keycloak, JupyterHub and Discourse.
- **Release tooling**: `.github/workflows/publish.yml` publishes the npm, PyPI
  and crates.io packages from a GitHub release through each registry's
  trusted publishing (no stored tokens). See [RELEASING.md](RELEASING.md).

Not in this release: an independent security review of the kit or of the
provider, and OpenID certification. Internal reviews only so far.
