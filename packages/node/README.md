# nobleid-signin (Node.js)

Server-side helper for Sign in with NobleID, a thin layer over
[openid-client](https://github.com/panva/openid-client) v6 with NobleID's
settings chosen for you. TypeScript types included (`index.d.ts`).

Install it from a checkout of this repository, by path:
`npm install ./packages/node` (or `"nobleid-signin": "file:../path/to/packages/node"`
in `package.json`), or copy `index.mjs` and `index.d.ts`. The package is
**not yet published** to npm: do not `npm install nobleid-signin` from the
registry, as anything there under that name is not ours.

```js
import { createNobleIdClient, NobleIdError } from "nobleid-signin";

const nobleid = await createNobleIdClient({
  clientId: process.env.CLIENT_ID,          // nbcl_…
  clientSecret: process.env.CLIENT_SECRET,  // nbcs_… (confidential clients)
});

// GET /login
const { url, transaction } = await nobleid.startSignIn({
  redirectUri: process.env.REDIRECT_URI,
  scope: "openid profile email works offline_access",
});
req.session.nobleid = transaction;          // server-side session only
res.redirect(url);

// GET /callback
const tx = req.session.nobleid;
delete req.session.nobleid;                 // single use
const { tokens, claims, scope } = await nobleid.finishSignIn(fullCallbackUrl, tx);
const info = await nobleid.userinfo(tokens.access_token, claims.sub);
// key the account on claims.sub; read `scope` for what was granted
// then regenerate the session id (e.g. req.session.regenerate()) before
// storing the signed-in user, so a session id fixed before sign-in is useless

// later
const page = await nobleid.works(tokens.access_token, { limit: 50 });
const fresh = await nobleid.refresh(tokens.refresh_token, { expectedSub: claims.sub }); // store fresh.refresh_token
await nobleid.revoke(tokens.refresh_token, "refresh_token"); // on logout
```

What it does for you:

- Discovery, with the authorization endpoint on its own host.
- ID tokens: ES256 only, signature verified against the JWKS (re-fetched on
  an unknown `kid`), plus `iss`, `aud`, `exp`, `nonce`.
- PKCE S256, `state` and `nonce` on every sign-in, also for confidential clients.
- Callback order: transaction present → `state` (constant time) → `iss`
  (RFC 9207, missing is an error) → `error` → code → flow age (10 minutes;
  a transaction without a numeric `createdAt` is refused).
- `client_secret_basic` with form-urlencoded credentials (default when a
  secret is given), or `client_secret_post`, or `none`.
- `refresh()` shares one in-flight request per refresh token, so concurrent
  callers in one process never replay a rotated token (nothing is cached once
  it finishes). Across processes, lock per session yourself. On
  `invalid_grant`, sign the person out. Pass `expectedSub` (the `sub` stored
  at sign-in): a refresh-issued ID token is checked against it per caller.
- Errors are `NobleIdError` with `code`, `description`, `status` and
  `retryAfter` (on `429 slow_down`). They never contain token values.
- `http://` issuers are refused unless `allowInsecureLocalhost` is set and
  the host is `localhost`/`127.0.0.1`/`[::1]` (the local mock).

Fill your app's profile: `profileFromClaims(claims, userinfo)` returns a
plain `NobleIdProfile` (`name`, `givenName`, `picture`, `orcid`,
`affiliation`, `affiliations`, …), every field present and `null`, `[]` or
`false` when not shared. `orcid` is set only when proven through ORCID. It
throws `invalid_token` if userinfo is for another `sub`. Fill only empty
fields with it: [docs/profile-data.md](../../docs/profile-data.md).

```js
import { profileFromClaims } from "nobleid-signin";
const p = profileFromClaims(claims, await nobleid.userinfo(tokens.access_token, claims.sub));
```

Example app: [examples/node-openid-client](../../examples/node-openid-client/).
