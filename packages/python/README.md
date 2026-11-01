# nobleid-signin (Python)

Helper for Sign in with NobleID on top of [Authlib](https://authlib.org/)'s
Flask client. Python 3.11+.

## Install

Releases go to PyPI as `nobleid-signin`, published by this repository's
release workflow through PyPI trusted publishing:

```sh
pip install "nobleid-signin[flask]"
```

Only a project whose PyPI page links back to
[github.com/signinwithnobleid/sign-in-with-nobleid](https://github.com/signinwithnobleid/sign-in-with-nobleid) is ours. Until 0.1.0 appears on PyPI, install it
from a checkout of this repository, by path: `pip install "./packages/python[flask]"`.

## Use

```python
from flask import Flask, session
from nobleid_signin import NobleID, NobleIdError

app = Flask(__name__)
app.secret_key = ...  # from your environment
nobleid = NobleID(app, client_id=os.environ["CLIENT_ID"], client_secret=os.environ["CLIENT_SECRET"],
                  scope="openid profile email works offline_access")

@app.get("/login")
def login():
    return nobleid.start_sign_in(os.environ["REDIRECT_URI"])

@app.get("/callback")
def callback():
    try:
        r = nobleid.finish_sign_in()          # {"tokens", "claims", "scope"}
        info = nobleid.userinfo(r["tokens"]["access_token"], r["claims"]["sub"])
    except NobleIdError as e:
        return f"Sign-in failed: {e.code}", 400
    ...  # key the account on r["claims"]["sub"]; keep tokens server-side
```

Also: `nobleid.works(access_token, limit, offset)`,
`nobleid.refresh(refresh_token, expected_sub=sub)` (store the rotated token it
returns; a refresh-issued ID token is verified and its `sub` must equal
`expected_sub`, the `sub` you stored at sign-in),
`nobleid.revoke(token, hint)`.

What it adds to Authlib:

- `code_challenge_method="S256"` (without it Authlib silently sends no PKCE).
- ES256 ID tokens only (a header naming any other algorithm is refused;
  Authlib alone accepts whatever discovery lists). Authlib verifies the
  signature with the JWKS and re-fetches it on an unknown `kid`; `iss` and
  `aud` are both required and compared (Authlib's default checks `iss` only).
- Discovery: `issuer` must match and every endpoint must be https. HTTP
  redirects are never followed, and every request times out after 10 s.
- The RFC 9207 `iss` check, and `state` checked before any `error` is
  surfaced (Authlib reports `error` first and does not check `iss`).
- Single-use sign-in state and a 10-minute flow limit.
- `client_secret_post` for the token endpoint: Authlib's
  `client_secret_basic` does not form-urlencode the id and secret.
- Concurrent refreshes of the same token within the process share one
  request. Nothing is cached after it finishes, so a replayed (used) token
  goes to the provider and is refused there.
- `NobleIdError` with `code`, `description`, `status`, `retry_after`.

Fill your app's profile: `profile_from_claims(claims, userinfo)` returns a
plain dict (`name`, `given_name`, `picture`, `orcid`, `affiliation`,
`affiliations`, …), every key present and `None`, `[]` or `False` when not
shared. `orcid` is set only when proven through ORCID. It raises
`NobleIdError("invalid_token")` if userinfo is for another `sub`. Standard
library only. Fill only empty fields with it:
[docs/profile-data.md](../../docs/profile-data.md).

Example app: [examples/python-flask-authlib](../../examples/python-flask-authlib/).

Tests: `python -B -m unittest discover -s tests` from this directory, with the
dependencies installed.
