# ASP.NET Core example (.NET 10)

A minimal server-rendered app: ASP.NET Core minimal APIs, cookie
authentication and `Microsoft.AspNetCore.Authentication.OpenIdConnect` 10.0.14.
Confidential client: the secret and the tokens stay on the server. The cookie
handler keeps each authentication ticket (claims and tokens) in an in-memory
`ITicketStore`; the browser only holds an encrypted, HttpOnly, SameSite=Lax
cookie that carries the ticket's key. Sign-out deletes the ticket on the
server, so a copied cookie stops working too.

## Run against NobleID

1. Register a confidential app at https://www.nobleid.org/dashboard/oauth-apps
   with redirect URI `http://localhost:3000/signin-oidc` (loopback `http` is
   allowed for development; use `https` in production).
2. Install the .NET 10 SDK.
3. ```sh
   cd examples/dotnet-aspnetcore
   cp .env.example .env    # fill in CLIENT_ID and CLIENT_SECRET
   set -a; . ./.env; set +a
   dotnet run
   ```
4. Open http://localhost:3000.

## Run against the local mock

```sh
node test/run-example.mjs dotnet-aspnetcore
```

## What it shows

| Route | |
|---|---|
| `GET /` | Signed out, or the merged ID-token and userinfo claims |
| `GET /login` | state + nonce + PKCE S256, redirect to NobleID |
| `GET /signin-oidc` | state → iss → error → code exchange → ID token verified (ES256 via JWKS) → userinfo; new auth cookie |
| `GET /works` | `/oauth/works` |
| `POST /refresh` | refresh grant; stores the rotated refresh token in a new server-side ticket |
| `POST /logout` | revoke refresh + access token, delete the server-side ticket, clear the cookie |

POST routes check an antiforgery token and the `Origin` header.

## Settings NobleID needs

The handler's defaults do not all fit NobleID. In `Program.cs`:

| Setting | Why |
|---|---|
| `ResponseMode = Query` | The default is `form_post`; NobleID returns the code in the query only. |
| `TokenValidationParameters.ValidAlgorithms = ["ES256"]` | NobleID signs ID tokens with ES256 only. |
| `UsePkce = true` | S256, sent even though this is a confidential client. |
| `PushedAuthorizationBehavior = Disable` | .NET 9+ switches to PAR whenever discovery lists a PAR endpoint. Optional; this example uses the plain authorize redirect. |
| `OnMessageReceived` checks `iss` | The handler does not check the RFC 9207 `iss` parameter. The event checks that the sign-in was started by this browser, then that `iss` equals the issuer (missing = rejected), before the handler looks at `error` or `code`. |
| `OnUserInformationReceived` keeps the raw JSON | The default claim actions drop userinfo-only claims such as `affiliations` and `works_count`. |
| `MapInboundClaims = false` | Keeps `sub`, `email`, ... under their own names. Key accounts on `sub`; link by `email` only when `email_verified` is true. |
| No sign-out from the OIDC scheme | NobleID has no end-session endpoint. Logout revokes the tokens and signs out of the cookie scheme only. |
| Correlation and nonce cookies `SameSite=Lax` | They must come back on the top-level redirect from NobleID. |
| `redirect_uri` and `Secure` from `REDIRECT_URI` | The handler would build `redirect_uri` from the request's scheme and Host, which a client or proxy can change. The example sends `REDIRECT_URI` as is and marks every cookie `Secure` unless `REDIRECT_URI` is `http://localhost`. |

The handler redeems the code with `client_secret_post`; the refresh and
revocation calls in this example use `client_secret_basic`. Each request uses
one method, never both.

Refresh tokens rotate and a reused one ends the session, so concurrent
refreshes of the same token in one process share a single request. With
several instances, serialise refreshes per user. On `invalid_grant` the user
is signed out. Any other refresh failure (including a new ID token that fails
verification) also signs the user out locally, because NobleID may already
have rotated the refresh token the session holds.

The session lasts 8 hours. Over https, the session and antiforgery cookies use
the `__Host-` prefix.

In production:

- Replace `MemoryTicketStore` with a store shared by all instances (for
  example one backed by `IDistributedCache`). The in-memory one signs
  everyone out on restart.
- Set `DATA_PROTECTION_KEYS_DIR` (or another Data Protection key store shared
  by all instances), and encrypt the keys at rest with one of the
  `ProtectKeysWith*` methods (`ProtectKeysWithCertificate`,
  `ProtectKeysWithAzureKeyVault`, `ProtectKeysWithDpapi`, ...). Anyone who can
  read the keys can forge or read the cookies.

Environment: `ISSUER` (default `https://id.nobleid.org`), `CLIENT_ID`,
`CLIENT_SECRET`, `REDIRECT_URI`, `PORT`, `SCOPE`, `DATA_PROTECTION_KEYS_DIR`.
