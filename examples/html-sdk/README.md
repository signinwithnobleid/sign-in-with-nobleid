# Browser-only example (the SDK as a public client)

Two static pages and the [browser SDK](../../sdk/). No server-side code and no
secret: register a **public** app with redirect URI
`http://localhost:5173/callback.html` (development) or your `https` URL.

```sh
cd examples/html-sdk
# edit public/config.js: clientId
node serve.mjs            # http://localhost:5173
```

- `index.html` renders the official button (`NobleID.renderButton`).
- `callback.html` runs `NobleID.handleCallback`, shows the claims and the
  researcher badge, and signs out with `NobleID.revoke`.
- Tokens live in memory only; reloading the page signs you out of the demo.
  It asks for no `offline_access`.
- `serve.mjs` sends a strict Content-Security-Policy (`script-src 'self'`,
  no inline scripts) and serves the SDK from `../../sdk`. In production you
  can load `https://www.nobleid.org/sdk/nobleid-auth.js` instead.

If your app has a server, sign in there instead (a backend-for-frontend):
see the other examples.

Tests (against the local mock): `node --test test/html-sdk.test.mjs`.
