"""Minimal "Sign in with NobleID" web app: Flask + Authlib (via nobleid_signin).

Confidential client. Tokens stay on the server: the Flask session cookie holds
only a random session key; the tokens live in a server-side store (a dict
here; use your database or cache in production).

    ISSUER=https://id.nobleid.org CLIENT_ID=... CLIENT_SECRET=... \
    REDIRECT_URI=http://localhost:5000/callback FLASK_SECRET_KEY=... python app.py
"""

import json
import os
import secrets
import threading
import time
from urllib.parse import urlsplit

from flask import Flask, abort, redirect, render_template, request, session
from nobleid_signin import NobleID, NobleIdError

ISSUER = os.environ.get("ISSUER", "https://id.nobleid.org")
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:5000/callback")
PORT = int(os.environ.get("PORT", "5000"))
SCOPE = os.environ.get("SCOPE", "openid profile email orcid affiliations works offline_access")

APP_ORIGIN = "{0.scheme}://{0.netloc}".format(urlsplit(REDIRECT_URI))
CALLBACK_PATH = urlsplit(REDIRECT_URI).path

app = Flask(__name__)
_secret = os.environ.get("FLASK_SECRET_KEY", "")
# The key signs the session cookie: anyone who knows it can forge a session.
if _secret and (len(_secret) < 32 or _secret.lower().startswith(("generate", "replace", "change", "your"))):
    raise SystemExit("FLASK_SECRET_KEY is too short or a placeholder; generate one with secrets.token_urlsafe(48)")
app.secret_key = _secret or secrets.token_bytes(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=APP_ORIGIN.startswith("https:"),
    # Over https the __Host- prefix pins the cookie to this exact origin.
    SESSION_COOKIE_NAME="__Host-session" if APP_ORIGIN.startswith("https:") else "session",
)

nobleid = NobleID(app, issuer=ISSUER, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, scope=SCOPE)

STORE = {}  # session key -> {"user", "tokens", "scope", "seen"}; server-side only
STORE_LOCK = threading.Lock()
SESSION_IDLE = 8 * 3600  # seconds; idle sessions are dropped
SWEEP_EVERY = 600  # seconds between sweeps of the store
_last_sweep = time.monotonic()


def sweep():
    """Drop sessions idle for longer than SESSION_IDLE (at most every SWEEP_EVERY)."""
    global _last_sweep
    now = time.monotonic()
    with STORE_LOCK:
        if now - _last_sweep < SWEEP_EVERY:
            return
        _last_sweep = now
        for key in [k for k, v in STORE.items() if now - v["seen"] > SESSION_IDLE]:
            del STORE[key]


def current():
    key = session.get("key")
    with STORE_LOCK:
        s = STORE.get(key) if key else None
        if s:
            s["seen"] = time.monotonic()
    return s


def forget():
    """Sign out locally: drop the server-side entry and clear the cookie session."""
    with STORE_LOCK:
        STORE.pop(session.get("key"), None)
    session.clear()


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    origin = request.headers.get("Origin")
    if origin and origin != APP_ORIGIN:
        abort(403)
    expected = session.get("csrf", "")
    if not expected or not secrets.compare_digest(request.form.get("csrf", ""), expected):
        abort(403)


@app.before_request
def sweep_store():
    sweep()


@app.after_request
def headers(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; img-src https:; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.get("/")
def home():
    s = current()
    claims = json.dumps({**s["user"], "granted_scope": " ".join(s["scope"])}, indent=2) if s else None
    return render_template("index.html", s=s, claims=claims, csrf=csrf_token())


@app.get("/login")
def login():
    return nobleid.start_sign_in(REDIRECT_URI)


@app.get(CALLBACK_PATH)
def callback():
    try:
        result = nobleid.finish_sign_in()
        info = nobleid.userinfo(result["tokens"]["access_token"], result["claims"]["sub"])
    except NobleIdError as e:
        return render_template("error.html", code=e.code, description=e.description), 400
    # Key accounts on `sub`. Only trust `email` for linking when email_verified is true.
    session.clear()  # fresh session after sign-in
    key = secrets.token_urlsafe(32)
    with STORE_LOCK:
        STORE[key] = {"user": {**result["claims"], **info}, "tokens": result["tokens"], "scope": result["scope"], "seen": time.monotonic()}
    session["key"] = key
    return redirect("/", code=303)


@app.get("/works")
def works():
    s = current()
    if not s:
        return redirect("/")
    if "works" not in s["scope"]:
        return render_template("works.html", works=None)
    try:
        data = nobleid.works(s["tokens"]["access_token"], limit=50)
    except NobleIdError as e:
        return render_template("error.html", code=e.code, description=e.description), 400
    return render_template("works.html", works=json.dumps(data, indent=2))


@app.post("/refresh")
def refresh():
    check_csrf()
    s = current()
    if not s or not s["tokens"].get("refresh_token"):
        return redirect("/", code=303)
    try:
        fresh = nobleid.refresh(s["tokens"]["refresh_token"], expected_sub=s["user"]["sub"])
        fresh.pop("claims", None)
        s["tokens"] = {**s["tokens"], **fresh}
    except NobleIdError as e:
        # invalid_grant: the user removed the app, or the session ended. Any other
        # failure may come after the provider already rotated the refresh token,
        # so the one we hold could be spent. Either way, sign out locally.
        forget()
        if e.code == "invalid_grant":
            return redirect("/", code=303)
        return render_template("error.html", code=e.code, description=e.description), 400
    return redirect("/", code=303)


@app.post("/logout")
def logout():
    check_csrf()
    with STORE_LOCK:
        s = STORE.pop(session.get("key"), None)
    if s:
        # NobleID has no end-session endpoint: revoke, then forget the session.
        for name, hint in (("refresh_token", "refresh_token"), ("access_token", "access_token")):
            if s["tokens"].get(name):
                try:
                    nobleid.revoke(s["tokens"][name], hint)
                except NobleIdError:
                    pass
    session.clear()
    return redirect("/", code=303)


if __name__ == "__main__":
    app.run(host="localhost", port=PORT, debug=False)
