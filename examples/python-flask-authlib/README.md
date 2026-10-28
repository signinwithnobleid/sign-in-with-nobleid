# Python example (Flask + Authlib)

A minimal Flask app using [`nobleid_signin`](../../packages/python/), which
wraps Authlib 1.9. Confidential client; tokens are kept server-side and the
Flask session cookie only carries a random key.

## Run against NobleID

1. Register a confidential app with redirect URI `http://localhost:5000/callback`.
2. ```sh
   cd examples/python-flask-authlib
   python3 -m venv .venv && . .venv/bin/activate
   pip install --require-hashes -r requirements.txt
   pip install --no-deps ../../packages/python   # its dependencies are pinned above
   cp .env.example .env    # fill in the values, then export them
   set -a; . ./.env; set +a
   python app.py
   ```
3. Open http://localhost:5000.

## Run against the local mock

```sh
PYTHON=/path/to/venv/bin/python node test/run-example.mjs python-flask-authlib
```

## Authlib settings NobleID needs

- `client_kwargs={"code_challenge_method": "S256"}`. Without it Authlib
  silently sends no PKCE.
- ES256 comes from discovery (`id_token_signing_alg_values_supported`).
- Authlib does not check the `iss` response parameter, and reports `error`
  before checking `state`. The helper checks state, then iss, then error.
- `token_endpoint_auth_method="client_secret_post"`: Authlib's basic auth
  does not form-urlencode the credentials.

Routes are the same as in the [Node example](../node-openid-client/README.md).
Environment: `ISSUER`, `CLIENT_ID`, `CLIENT_SECRET`, `REDIRECT_URI`, `PORT`,
`SCOPE`, `FLASK_SECRET_KEY`.
