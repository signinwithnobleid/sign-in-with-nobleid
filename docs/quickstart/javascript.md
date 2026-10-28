# JavaScript and TypeScript

## Node

Helper: [`packages/node`](../../packages/node/README.md) (openid-client 6.8.8,
TypeScript types included). Example:
[`examples/node-openid-client`](../../examples/node-openid-client/README.md).

Install it from this repository (`npm install ./packages/node`, or copy
`index.mjs` and `index.d.ts`). `nobleid-signin` is not yet published to the
npm registry: a package of that name there is not ours.

```js
import { createNobleIdClient } from "nobleid-signin";

const nobleid = await createNobleIdClient({
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
});
const { url, transaction } = await nobleid.startSignIn({ redirectUri: process.env.REDIRECT_URI });
// … store transaction in the server-side session, redirect to url …
const { tokens, claims, scope } = await nobleid.finishSignIn(callbackUrl, transaction);
const info = await nobleid.userinfo(tokens.access_token, claims.sub);
```

Using openid-client directly: pass `{ id_token_signed_response_alg: "ES256" }`
as client metadata, call `enableNonRepudiationChecks(config)` to verify ID
token signatures against the JWKS, and send `code_challenge_method: "S256"`,
`state` and `nonce`. openid-client v6 checks the `iss` response parameter.
openid-client v5 also needs `id_token_signed_response_alg: "ES256"`.

## Next.js with Auth.js

Example: [`examples/nextjs-authjs`](../../examples/nextjs-authjs/README.md)
(Next.js 16.4, `next-auth@5.0.0-beta.32` — Auth.js v5 is still in beta).

```ts
{
  id: "nobleid", name: "NobleID", type: "oidc",
  issuer: process.env.ISSUER ?? "https://id.nobleid.org",
  clientId: process.env.CLIENT_ID, clientSecret: process.env.CLIENT_SECRET,
  checks: ["pkce", "state", "nonce"],
  client: { id_token_signed_response_alg: "ES256", token_endpoint_auth_method: "client_secret_basic" },
  authorization: { params: { scope: "openid profile email offline_access" } },
}
```

Know before you ship (details in the example's README):

- Auth.js does not verify the ID token signature; the example verifies it
  with `jose` against the JWKS in the `jwt` callback.
- An `oidc` provider never calls userinfo; the example does.
- Do not refresh tokens inside the `jwt` callback on every read: parallel
  reads replay the rotated refresh token and NobleID revokes the session.
- Auth.js accepts `http` issuers for any host; the example refuses them
  except for `localhost`.
- next-auth v4: `idToken: true`, `checks: ["pkce","state","nonce"]`,
  `client: { id_token_signed_response_alg: "ES256" }`.

## Browser only

The [browser SDK](../../sdk/README.md) runs a public-client flow and draws the
button. Example: [`examples/html-sdk`](../../examples/html-sdk/README.md).
Prefer a server (backend-for-frontend) when you have one.
