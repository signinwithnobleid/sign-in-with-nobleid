# JupyterHub

Written for JupyterHub 6.0.1 with `oauthenticator` 17.4.0
(`GenericOAuthenticator`). PKCE is in `oauthenticator` 17.1 and later.

**Tested?** Configuration checked against the local mock. The script
[`jupyterhub/test_against_mock.py`](jupyterhub/test_against_mock.py) loads
[`jupyterhub/jupyterhub_config.py`](jupyterhub/jupyterhub_config.py), points
its three endpoint URLs at the mock, and runs `GenericOAuthenticator`'s own
token exchange, userinfo fetch, `username_claim` and `allowed_users` check. It
covers PKCE, `client_secret_post` and `client_secret_basic`, refusal of a `sub`
that is not allowed, and a user who unticks `email`: 7 of 7 checks passed. The
browser leg (the authorization redirect) is played by the script. A full hub
with its proxy and spawner was not started.

## Configuration

[`jupyterhub/jupyterhub_config.py`](jupyterhub/jupyterhub_config.py):

```python
import os

c = get_config()  # noqa: F821

c.JupyterHub.authenticator_class = "generic-oauth"

c.GenericOAuthenticator.login_service = "NobleID"
c.GenericOAuthenticator.client_id = os.environ["NOBLEID_CLIENT_ID"]          # nbcl_...
c.GenericOAuthenticator.client_secret = os.environ["NOBLEID_CLIENT_SECRET"]  # nbcs_...
c.GenericOAuthenticator.oauth_callback_url = os.environ.get(
    "NOBLEID_CALLBACK_URL", "https://hub.example.org/hub/oauth_callback"
)

# The authorization endpoint is on www.nobleid.org; the rest are on id.nobleid.org.
c.GenericOAuthenticator.authorize_url = "https://www.nobleid.org/oauth/authorize"
c.GenericOAuthenticator.token_url = "https://id.nobleid.org/oauth/token"
c.GenericOAuthenticator.userdata_url = "https://id.nobleid.org/oauth/userinfo"

c.GenericOAuthenticator.scope = ["openid", "profile", "email"]
c.GenericOAuthenticator.enable_pkce = True

c.GenericOAuthenticator.username_claim = "sub"

c.GenericOAuthenticator.allowed_users = set(
    filter(None, os.environ.get("NOBLEID_ALLOWED_SUBS", "").split(","))
)
# c.GenericOAuthenticator.allow_all = True
c.GenericOAuthenticator.admin_users = set(
    filter(None, os.environ.get("NOBLEID_ADMIN_SUBS", "").split(","))
)
```

| Setting | Value | Why |
|---|---|---|
| `authorize_url` | `https://www.nobleid.org/oauth/authorize` | Different host from the others. `GenericOAuthenticator` does not read discovery, so all three URLs are set by hand. |
| `token_url` | `https://id.nobleid.org/oauth/token` | |
| `userdata_url` | `https://id.nobleid.org/oauth/userinfo` | Userinfo carries more claims than the ID token. Leave `userdata_from_id_token` off. |
| `scope` | `["openid", "profile", "email"]` | Add `"orcid"` to get `orcid` in `auth_state` (needs `enable_auth_state`). |
| `enable_pkce` | `True` | S256. Already the default in 17.1+; set it explicitly. |
| `basic_auth` | leave `False` | Sends `client_secret_post`, which NobleID accepts. `True` switches to `client_secret_basic`, which NobleID also accepts. |
| `username_claim` | `"sub"` | See below. |
| `oauth_callback_url` | your hub's `/hub/oauth_callback` | Register exactly this with NobleID. |
| `logout_redirect_url` | leave unset | NobleID has no end-session endpoint. JupyterHub logout is local. |

### Redirect URI

`https://hub.example.org/hub/oauth_callback`, or
`https://hub.example.org/<base_url>/hub/oauth_callback` if you set
`JupyterHub.base_url`. JupyterHub logs the URL it uses on each login
(`OAuth redirect: …`). Register exactly that.

### Username: `sub` or `preferred_username`

JupyterHub uses the username as the account key. It appears in server URLs
(`/user/<name>/`), in spawner resource names and, with a system-user spawner,
as the Unix account. Changing a user's username makes them a new user with an
empty home.

- **`sub`** (recommended). NobleID promises it never changes. It is opaque, so
  users see an ID rather than a name, and it may not be a valid Unix username.
  Use it with container or Kubernetes spawners.
- **`preferred_username`**. Readable, but NobleID does not promise it stays the
  same. If it changes, the person becomes a new hub user. Use it only if you
  can live with that, and never with `allow_all = True` on a hub where names
  carry permissions.

JupyterHub lowercases usernames.

### Who may sign in

Anyone can create a NobleID account, so pick one of these:

- `allowed_users`: a set of `sub` values. JupyterHub logs refused sign-ins as
  `User '<sub>' not allowed.`, which is a way to collect the value.
- `allow_existing_users = True`: manage access from `/hub/admin`.
- `allow_all = True`: any NobleID account. Only for a deliberately open hub.

With none of these set, nobody can sign in.

### Refresh tokens

Not needed for sign-in. If you add `offline_access` and
`enable_auth_state = True`, `oauthenticator` refreshes an expired access token
and stores the new refresh token. NobleID rotates refresh tokens on every use,
and a reused one revokes the chain. Avoid anything that refreshes the same
user's token from two places at once.

### Limits worth knowing

- `oauthenticator` checks `state` and PKCE but not the RFC 9207 `iss` callback
  parameter. That only matters if you put several identity providers behind
  one hub.
- It does not send or check an OIDC `nonce`. It trusts the server-to-server
  TLS call to the token and userinfo endpoints instead.

## Run the check yourself

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r docs/integrations/jupyterhub/requirements.txt
.venv/bin/python docs/integrations/jupyterhub/test_against_mock.py
```

Run it from the kit root. Node is needed for the mock. The script starts and
stops its own mock on a free port. It uses the mock's fake test client, never
real credentials.

## Profile fields

| NobleID claim | JupyterHub | Scope |
|---|---|---|
| `sub` | the hub username (`username_claim`) | `openid` |
| `name`, `email`, `orcid` | `auth_state["oauth_user"]`, with `enable_auth_state = True` | `profile`, `email`, `orcid` |

JupyterHub has no profile page. With `enable_auth_state = True` it keeps the userinfo response in `auth_state["oauth_user"]`, where a spawner can read it, for example to set `GIT_AUTHOR_NAME` from `name`.

For `orcid`, add `"orcid"` to `scope` and tick ORCID iD on your app.

Every claim, and how to fill a profile without overwriting what people
edit: [Fill your app's profile from NobleID](../profile-data.md).

## Sources

- Generic OAuthenticator setup:
  https://oauthenticator.readthedocs.io/en/latest/tutorials/provider-specific-setup/providers/generic.html
- `GenericOAuthenticator` reference:
  https://oauthenticator.readthedocs.io/en/latest/reference/api/gen/oauthenticator.generic.html
- Changelog (`enable_pkce`, 17.1.0):
  https://oauthenticator.readthedocs.io/en/latest/reference/changelog.html
