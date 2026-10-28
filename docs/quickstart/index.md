# Quickstarts

Every quickstart follows the same steps:

1. [Register an app](../register.md). A server-side app is **confidential**;
   a browser-only or native app is **public**.
2. Register the redirect URI your framework uses, exactly.
3. Put `CLIENT_ID`, `CLIENT_SECRET` (confidential only) and `REDIRECT_URI` in
   the environment. `ISSUER` defaults to `https://id.nobleid.org`.
4. Run the example. Try it first against the [local mock](../../mock-oidc/README.md):
   `node test/run-example.mjs <example>`.

| Language | Helper | Example | Guide |
|---|---|---|---|
| JavaScript (browser) | [`sdk/`](../../sdk/README.md) | [`html-sdk`](../../examples/html-sdk/) | [javascript.md](javascript.md#browser-only) |
| JavaScript / TypeScript (Node) | [`packages/node`](../../packages/node/README.md) | [`node-openid-client`](../../examples/node-openid-client/) | [javascript.md](javascript.md#node) |
| Next.js (Auth.js v5) | — | [`nextjs-authjs`](../../examples/nextjs-authjs/) | [javascript.md](javascript.md#nextjs-with-authjs) |
| Python | [`packages/python`](../../packages/python/README.md) | [`python-flask-authlib`](../../examples/python-flask-authlib/) | [python.md](python.md) |
| Rust | [`packages/rust`](../../packages/rust/README.md) | [`rust-axum`](../../examples/rust-axum/) | [rust.md](rust.md) |
| Go | [`packages/go`](../../packages/go/README.md) | [`go-nethttp`](../../examples/go-nethttp/) | [go.md](go.md) |
| PHP | [`packages/php`](../../packages/php/README.md) | [`php-plain`](../../examples/php-plain/) | [php.md](php.md) |
| Java (Spring Boot) | — | [`java-spring-boot`](../../examples/java-spring-boot/) | [java.md](java.md) |
| Ruby (Sinatra + OmniAuth) | — | [`ruby-sinatra`](../../examples/ruby-sinatra/) | [ruby.md](ruby.md) |
| .NET (ASP.NET Core) | — | [`dotnet-aspnetcore`](../../examples/dotnet-aspnetcore/) | [dotnet.md](dotnet.md) |
| WordPress | plugin | — | [integrations/wordpress.md](../integrations/wordpress.md) |

Whatever the language, the library must be configured for **ES256** ID
tokens, **PKCE S256**, and you must check the **`iss`** response parameter
yourself if the library does not. See [troubleshooting](../troubleshooting.md).
