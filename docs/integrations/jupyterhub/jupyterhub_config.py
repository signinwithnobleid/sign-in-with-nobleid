# JupyterHub: Sign in with NobleID.
# Written for JupyterHub 6.0 + oauthenticator 17.4. See ../jupyterhub.md.
import os

c = get_config()  # noqa: F821 (provided by JupyterHub)

c.JupyterHub.authenticator_class = "generic-oauth"

c.GenericOAuthenticator.login_service = "NobleID"
c.GenericOAuthenticator.client_id = os.environ["NOBLEID_CLIENT_ID"]          # nbcl_...
c.GenericOAuthenticator.client_secret = os.environ["NOBLEID_CLIENT_SECRET"]  # nbcs_...
# Register exactly this URL with NobleID.
c.GenericOAuthenticator.oauth_callback_url = os.environ.get(
    "NOBLEID_CALLBACK_URL", "https://hub.example.org/hub/oauth_callback"
)

# The authorization endpoint is on www.nobleid.org; the rest are on id.nobleid.org.
c.GenericOAuthenticator.authorize_url = "https://www.nobleid.org/oauth/authorize"
c.GenericOAuthenticator.token_url = "https://id.nobleid.org/oauth/token"
c.GenericOAuthenticator.userdata_url = "https://id.nobleid.org/oauth/userinfo"

c.GenericOAuthenticator.scope = ["openid", "profile", "email"]
c.GenericOAuthenticator.enable_pkce = True  # S256; on by default since oauthenticator 17.1

# `sub` is the only identifier NobleID promises never changes.
c.GenericOAuthenticator.username_claim = "sub"

# Who may sign in. Pick one.
c.GenericOAuthenticator.allowed_users = set(
    filter(None, os.environ.get("NOBLEID_ALLOWED_SUBS", "").split(","))
)
# c.GenericOAuthenticator.allow_all = True  # any NobleID account
c.GenericOAuthenticator.admin_users = set(
    filter(None, os.environ.get("NOBLEID_ADMIN_SUBS", "").split(","))
)
