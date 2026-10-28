# Node.js example (openid-client v6)

A minimal server-rendered app using Node's `http` module and
[`nobleid-signin`](../../packages/node/) (openid-client 6.8.8).
Confidential client: the secret and the tokens stay on the server.

## Run against NobleID

1. Register a confidential app at https://www.nobleid.org/dashboard/oauth-apps
   with redirect URI `http://localhost:3000/callback` (loopback `http` is
   allowed for development; use `https` in production).
2. From the repository root: `npm ci`.
3. ```sh
   cd examples/node-openid-client
   cp .env.example .env    # fill in CLIENT_ID and CLIENT_SECRET
   node --env-file=.env server.mjs
   ```
4. Open http://localhost:3000.

## Run against the local mock

```sh
node test/run-example.mjs node-openid-client
```

## What it shows

| Route | |
|---|---|
| `GET /` | Signed out, or the merged ID-token and userinfo claims |
| `GET /login` | state + nonce + PKCE S256, redirect to NobleID |
| `GET /callback` | state → iss → error → code exchange → ID token verified (ES256 via JWKS) → userinfo; new session id |
| `GET /works` | `/oauth/works` |
| `POST /refresh` | refresh grant; stores the rotated refresh token |
| `POST /logout` | revoke refresh + access token, clear the session |

The session store is in memory: use a real one in production. A session is
created only when sign-in starts at `/login`; sessions idle for 8 hours are
dropped by a sweep every 10 minutes. Over https the cookie uses the `__Host-`
prefix. POST routes check a CSRF token (compared in constant time) and the
`Origin` header. A refresh that fails for any reason signs the user out
locally, because NobleID may already have rotated the refresh token.

Environment: `ISSUER` (default `https://id.nobleid.org`), `CLIENT_ID`,
`CLIENT_SECRET`, `REDIRECT_URI`, `PORT`, `SCOPE`.
