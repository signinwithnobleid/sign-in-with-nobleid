# Python

Helper: [`packages/python`](../../packages/python/README.md) over Authlib 1.9.
Install it with `pip install "nobleid-signin[flask]"`. Until 0.1.0 appears on
PyPI, install it from this repository (`pip install "./packages/python[flask]"`).
Example: [`examples/python-flask-authlib`](../../examples/python-flask-authlib/README.md).

```python
nobleid = NobleID(app, client_id=os.environ["CLIENT_ID"], client_secret=os.environ["CLIENT_SECRET"])

@app.get("/login")
def login():
    return nobleid.start_sign_in(os.environ["REDIRECT_URI"])

@app.get("/callback")
def callback():
    r = nobleid.finish_sign_in()   # state → iss → error → code → ID token (ES256 via JWKS)
    info = nobleid.userinfo(r["tokens"]["access_token"], r["claims"]["sub"])
```

Using Authlib directly:

- `client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"}`.
  Without `code_challenge_method` Authlib silently sends no PKCE.
- ES256 is taken from discovery; register with `server_metadata_url`.
- Check `request.args["iss"] == metadata["issuer"]` yourself, and check the
  state before looking at `error` (Authlib reports `error` first).
- Authlib's `client_secret_basic` does not form-urlencode the credentials;
  `token_endpoint_auth_method="client_secret_post"` avoids the question.
