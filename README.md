# Sign in with NobleID — client kit

Everything you need to add **Sign in with NobleID** to an app: the official
button and browser SDK, small server-side helpers, working examples in nine
languages and frameworks, guides for research platforms, and a local mock of
the provider so you can test without an account.

NobleID is an OpenID Connect provider for researchers. Besides a stable
account id, it can tell your app whether a person's ORCID iD is verified,
whether NobleID checked a government-issued ID, whether NobleID staff
badged them as a researcher, and which works they registered. See
[what NobleID can and cannot tell you](docs/scopes-and-claims.md#what-nobleid-can-and-cannot-tell-you).

## Five-minute quickstart

1. **Register an app** at https://www.nobleid.org/dashboard/oauth-apps
   (needs a confirmed email and two-step login on your NobleID account).
   Choose *confidential* if your app has a server. Add your redirect URI,
   e.g. `http://localhost:3000/callback` for local development.
2. **Try an example against the local mock first** (Node 22+):
   ```sh
   npm ci
   node test/run-example.mjs node-openid-client
   ```
3. **Run it against NobleID**:
   ```sh
   cd examples/node-openid-client
   cp .env.example .env        # CLIENT_ID=nbcl_…, CLIENT_SECRET=nbcs_…
   node --env-file=.env server.mjs
   ```
   Open http://localhost:3000 and sign in.
4. **Add the button** to your page:
   ```html
   <div data-nobleid-login-url="/login"></div>
   <script src="https://www.nobleid.org/sdk/nobleid-auth.js" async></script>
   ```
   A script loaded from another site can do anything on your page, and this
   URL always serves the latest release. On pages with anything to protect,
   serve a reviewed copy of [`sdk/nobleid-auth.js`](sdk/) from your own site.

| | |
|---|---|
| Issuer / discovery | `https://id.nobleid.org/.well-known/openid-configuration` |
| Authorization endpoint | `https://www.nobleid.org/oauth/authorize` (a different host from the issuer) |
| Flow | Authorization code + PKCE S256, `response_mode=query` |
| ID tokens | ES256 only |
| Logout | Revoke your tokens and clear your session; there is no end-session endpoint |

## What is in the kit

| Path | What |
|---|---|
| [`sdk/`](sdk/README.md) | Browser SDK v2.1.1: button, public-client flow, researcher badge |
| [`packages/node`](packages/node/README.md) | Node/TypeScript helper (openid-client v6) |
| [`packages/python`](packages/python/README.md) | Python helper (Authlib) |
| [`packages/rust`](packages/rust/README.md) | Rust helper (openidconnect) |
| [`packages/go`](packages/go/README.md) | Go helper (go-oidc + x/oauth2) |
| [`packages/php`](packages/php/README.md) | PHP helper (league/oauth2-client + firebase/php-jwt) |
| [`examples/`](#examples) | Working apps, all tested end to end against the mock |
| [`mock-oidc/`](mock-oidc/README.md) | Local mock of the provider (Node, no dependencies) |
| [`docs/`](docs/index.md) | Guides and reference ([GUIDE.md](GUIDE.md) is the table of contents) |
| [`brand/`](brand/) | Button and mark SVGs; [brand guide](docs/brand.md) |

## Examples

| Example | Stack |
|---|---|
| [`node-openid-client`](examples/node-openid-client/) | Node `http` + openid-client 6.8.8 |
| [`nextjs-authjs`](examples/nextjs-authjs/) | Next.js 16.4 + Auth.js v5 (beta) |
| [`html-sdk`](examples/html-sdk/) | Static pages + the browser SDK (public client) |
| [`python-flask-authlib`](examples/python-flask-authlib/) | Flask 3.1 + Authlib 1.9 |
| [`rust-axum`](examples/rust-axum/) | axum + openidconnect |
| [`go-nethttp`](examples/go-nethttp/) | net/http + go-oidc v3 |
| [`php-plain`](examples/php-plain/) | Plain PHP + league/oauth2-client + firebase/php-jwt |
| [`java-spring-boot`](examples/java-spring-boot/) | Spring Boot 4.1 + Spring Security OAuth2 Client |
| [`ruby-sinatra`](examples/ruby-sinatra/) | Sinatra + omniauth_openid_connect |
| [`dotnet-aspnetcore`](examples/dotnet-aspnetcore/) | ASP.NET Core 10 OpenIdConnect handler |
| [`wordpress`](examples/wordpress/) | OpenID Connect Generic Client plugin (configuration only) |

Platform guides: OJS, WordPress, DSpace, Dataverse, JupyterHub, Discourse,
Moodle, Keycloak — see [docs/integrations](docs/integrations/README.md).

## Tests

```sh
npm ci && npm test
```

runs the mock's conformance tests, the SDK tests, and every example whose
toolchain is installed (others are reported as skipped). CI runs every
language. Details: [test/README.md](test/README.md).

## Security

Read [docs/security.md](docs/security.md) before going live. Report
vulnerabilities to info@nobleid.org — see [SECURITY.md](SECURITY.md).
Never commit real credentials; every id and secret in this repository is fake.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). The NobleID
name and mark are covered by the [brand guide](docs/brand.md), not by the
licence.
