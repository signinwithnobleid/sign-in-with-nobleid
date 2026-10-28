"""Exercise oauthenticator's GenericOAuthenticator, configured by
jupyterhub_config.py, against the kit's local mock provider.

It runs the authenticator's own code for the token exchange (PKCE verifier,
client authentication), the userinfo fetch, username_claim and the
allowed_users check. The browser leg is played by this script: it builds the
authorization request the way OAuthLoginHandler does and follows the mock's
auto-approved redirect. A full JupyterHub (proxy, spawner) is not started.

    pip install --require-hashes -r docs/integrations/jupyterhub/requirements.txt
    python docs/integrations/jupyterhub/test_against_mock.py

Needs Node (for the mock). No real NobleID credentials are used.
"""

import asyncio
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

from oauthenticator.generic import GenericOAuthenticator
from oauthenticator.oauth2 import OAuthLoginHandler, _serialize_state
from traitlets.config import Config

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CALLBACK = "http://localhost:8000/callback"  # registered for the mock's confidential client


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http_get(url, follow=True):
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(url) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:  # a 302 surfaces here when not followed
        return e.code, dict(e.headers), e.read()


def http_post_json(url, data):
    req = urllib.request.Request(url, data=json.dumps(data).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def start_mock():
    proc = subprocess.Popen(
        ["node", str(ROOT / "mock-oidc/server.mjs"), "--port", "0", "--clients", str(ROOT / "test/clients.json")],
        stdout=subprocess.PIPE, text=True,
    )
    line = proc.stdout.readline()  # "mock-oidc listening: issuer http://localhost:<port> (port <port>)"
    if "issuer" not in line:
        proc.kill()
        raise RuntimeError("mock did not start: " + line)
    return proc, line.split("issuer ")[1].split(" ")[0]


def load_config():
    c = Config()
    code = (HERE / "jupyterhub_config.py").read_text()
    exec(compile(code, "jupyterhub_config.py", "exec"), {"get_config": lambda: c, "__name__": "config"})
    return c


class FakeCallbackHandler:
    """Just enough of OAuthCallbackHandler for GenericOAuthenticator.authenticate()."""

    def __init__(self, args, cookie_state):
        self._args, self._cookie = args, cookie_state

    def get_argument(self, name, default=None):
        return self._args.get(name, default)

    def get_state_cookie(self):
        return self._cookie


async def sign_in(auth, discovery):
    """Browser leg as OAuthLoginHandler.get() does it, then the hub's callback leg."""
    verifier, challenge = OAuthLoginHandler._generate_pkce_params(None)
    state_id = "test-state-0001"
    cookie_state = _serialize_state({"state_id": state_id, "next_url": None, "code_verifier": verifier})
    params = {
        "response_type": "code",
        "client_id": auth.client_id,
        "redirect_uri": auth.get_callback_url(),
        "scope": " ".join(auth.scope),
        "state": _serialize_state({"state_id": state_id}),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    status, headers, _ = http_get(auth.authorize_url + "?" + urllib.parse.urlencode(params), follow=False)
    assert status == 302, f"authorize returned {status}"
    cb = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(headers["Location"]).query))
    assert "error" not in cb, cb
    # oauthenticator does not check the RFC 9207 `iss` parameter; record that the provider sent it.
    assert cb.get("iss") == discovery["issuer"], cb
    return await auth.get_authenticated_user(FakeCallbackHandler(cb, cookie_state), None)


async def main():
    checks = []

    def ok(name, cond, detail=""):
        checks.append((name, bool(cond)))
        print(("PASS " if cond else "FAIL ") + name + (f"  ({detail})" if detail and not cond else ""))

    clients = json.loads((ROOT / "test/clients.json").read_text())["clients"]
    conf = next(x for x in clients if x["type"] == "confidential")
    os.environ.update({
        "NOBLEID_CLIENT_ID": conf["client_id"],
        "NOBLEID_CLIENT_SECRET": conf["client_secret"],
        "NOBLEID_CALLBACK_URL": CALLBACK,
        "NOBLEID_ALLOWED_SUBS": "mock-user-sub-0001",
    })

    c = load_config()
    g = c.GenericOAuthenticator
    ok("config: production endpoints",
       g.authorize_url == "https://www.nobleid.org/oauth/authorize"
       and g.token_url == "https://id.nobleid.org/oauth/token"
       and g.userdata_url == "https://id.nobleid.org/oauth/userinfo")

    proc, issuer = start_mock()
    try:
        _, _, body = http_get(issuer + "/.well-known/openid-configuration")
        disco = json.loads(body)
        # Same config, pointed at the mock's endpoints (taken from its discovery document).
        g.authorize_url = disco["authorization_endpoint"]
        g.token_url = disco["token_endpoint"]
        g.userdata_url = disco["userinfo_endpoint"]

        auth = GenericOAuthenticator(config=c)
        user = await sign_in(auth, disco)
        ok("sign-in: username is sub", user and user["name"] == "mock-user-sub-0001", user)
        last = json.loads(http_get(issuer + "/__mock/state")[2])["lastToken"]
        ok("token request: PKCE code_verifier sent", last and last["has_code_verifier"], last)
        ok("token request: client_secret_post (basic_auth=False)", last and last["auth_method"] == "client_secret_post", last)

        # Who may sign in: a sub not in allowed_users is refused.
        c2 = load_config()
        c2.GenericOAuthenticator.update(authorize_url=disco["authorization_endpoint"],
                                        token_url=disco["token_endpoint"],
                                        userdata_url=disco["userinfo_endpoint"],
                                        allowed_users={"someone-else"})
        refused = await sign_in(GenericOAuthenticator(config=c2), disco)
        ok("allowed_users: other sub refused", refused is None, refused)

        # basic_auth=True switches to client_secret_basic.
        c3 = load_config()
        c3.GenericOAuthenticator.update(authorize_url=disco["authorization_endpoint"],
                                        token_url=disco["token_endpoint"],
                                        userdata_url=disco["userinfo_endpoint"],
                                        basic_auth=True)
        user3 = await sign_in(GenericOAuthenticator(config=c3), disco)
        last = json.loads(http_get(issuer + "/__mock/state")[2])["lastToken"]
        ok("basic_auth=True: client_secret_basic", user3 and last["auth_method"] == "client_secret_basic", last)

        # A user who unticks `email` still signs in (username comes from sub).
        http_post_json(issuer + "/__mock/next-authorize", {"untick": ["email"]})
        user4 = await sign_in(GenericOAuthenticator(config=c), disco)
        ok("email unticked: still signs in", user4 and user4["name"] == "mock-user-sub-0001", user4)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    failed = [n for n, passed in checks if not passed]
    print(f"\n{len(checks) - len(failed)} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    asyncio.run(main())
