"""nobleid_signin: a thin helper for "Sign in with NobleID" on top of Authlib.

It registers NobleID with Authlib's Flask client with the settings NobleID
needs (discovery, PKCE S256, ES256 ID tokens verified against the JWKS) and
adds what Authlib leaves to you: the RFC 9207 ``iss`` check, checking
``state`` before surfacing an ``error``, single-use sign-in state, a refresh
that never replays a rotated refresh token, and revocation.

It does no cryptography of its own.

    from flask import Flask
    from nobleid_signin import NobleID

    app = Flask(__name__)
    nobleid = NobleID(app, client_id=..., client_secret=...)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import requests
from authlib.common.errors import AuthlibBaseError
from authlib.integrations.flask_client import OAuth
from authlib.integrations.flask_client.apps import FlaskOAuth2App
from authlib.integrations.requests_client import OAuth2Session

__all__ = ["NobleID", "NobleIdError", "NOBLEID_ISSUER", "DEFAULT_SCOPE", "granted", "profile_from_claims"]
__version__ = "1.0.0"

NOBLEID_ISSUER = "https://id.nobleid.org"
DEFAULT_SCOPE = "openid profile email"
MAX_FLOW_AGE_S = 10 * 60
_TX_KEY = "nobleid_tx"
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]", "::1")
_HTTP_TIMEOUT_S = 10
_ENDPOINTS = ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "revocation_endpoint", "jwks_uri")


class NobleIdError(Exception):
    """An OAuth/OIDC error with a machine-readable ``code``. Never contains tokens."""

    def __init__(self, code: str, description: str = "", status: Optional[int] = None, retry_after: Optional[str] = None):
        super().__init__(f"{code}: {description}" if description else code)
        self.code = code
        self.description = description
        self.status = status
        self.retry_after = retry_after


def _wrap(exc: Exception) -> NobleIdError:
    if isinstance(exc, NobleIdError):
        return exc
    if isinstance(exc, AuthlibBaseError):
        return NobleIdError(exc.error or "invalid_request", exc.description or "")
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        r = exc.response
        try:
            body = r.json()
        except ValueError:
            body = {}
        return NobleIdError(body.get("error") or f"http_{r.status_code}", body.get("error_description") or "", r.status_code, r.headers.get("Retry-After"))
    # joserfc / jwt validation errors and anything else: do not echo details that might include token material
    name = type(exc).__name__
    if "Claim" in name or "Signature" in name or "Key" in name or "Token" in name or "JWT" in name or "Jose" in name:
        return NobleIdError("invalid_token", name)
    return NobleIdError("server_error", name)


def _is_local_http(url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme == "http" and parts.hostname in _LOCAL_HOSTS


def _check_2xx(r: "requests.Response") -> None:
    """Raise for any non-2xx answer, redirects included (they are never followed)."""
    r.raise_for_status()
    if not 200 <= r.status_code < 300:
        raise NobleIdError("server_error", f"unexpected HTTP {r.status_code}", r.status_code)


def _require_es256(id_token: Any) -> None:
    """Reject an ID token whose header names any algorithm but ES256."""
    try:
        head = str(id_token).split(".", 1)[0]
        header = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
    except Exception:  # noqa: BLE001
        raise NobleIdError("invalid_token", "malformed ID token") from None
    if not isinstance(header, dict) or header.get("alg") != "ES256":
        raise NobleIdError("invalid_token", "ID token is not ES256")


class _Session(OAuth2Session):
    """Authlib's requests session, with redirects never followed.

    Used for discovery, the JWKS and the code exchange. A redirect is refused
    outright rather than handed back as if it were the answer.
    """

    def request(self, method, url, *args, **kwargs):
        kwargs["allow_redirects"] = False
        kwargs.setdefault("timeout", _HTTP_TIMEOUT_S)
        resp = super().request(method, url, *args, **kwargs)
        if 300 <= resp.status_code < 400:
            raise NobleIdError("server_error", f"refused an HTTP {resp.status_code} redirect", resp.status_code)
        return resp


class _App(FlaskOAuth2App):
    client_cls = _Session

    def parse_id_token(self, token, nonce, *args, **kwargs):
        # Authlib accepts whatever discovery lists; NobleID signs with ES256 only.
        if "id_token" in token:
            _require_es256(token["id_token"])
        return super().parse_id_token(token, nonce, *args, **kwargs)


class NobleID:
    """Sign in with NobleID for a Flask app (confidential client)."""

    def __init__(
        self,
        app=None,
        *,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        issuer: str = NOBLEID_ISSUER,
        scope: str = DEFAULT_SCOPE,
        name: str = "nobleid",
        oauth: Optional[OAuth] = None,
    ):
        self.issuer = issuer.rstrip("/")
        parts = urlsplit(self.issuer)
        if parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in _LOCAL_HOSTS):
            raise NobleIdError("invalid_request", "the issuer must be https (http only for a localhost mock)")
        if not client_id or not client_secret:
            raise NobleIdError("invalid_request", "client_id and client_secret are required")
        if "openid" not in scope.split():
            scope = "openid " + scope
        self.client_id = client_id
        self._client_secret = client_secret
        self.scope = scope
        self.name = name
        self.oauth = oauth or OAuth()
        self._inflight: Dict[str, "_Flight"] = {}
        self._inflight_guard = threading.Lock()
        if app is not None:
            self.init_app(app)

    def __repr__(self) -> str:  # never show the secret
        return f"NobleID(issuer={self.issuer!r}, client_id={self.client_id!r})"

    def init_app(self, app) -> None:
        self.oauth.init_app(app)
        self.client = self.oauth.register(
            name=self.name,
            client_id=self.client_id,
            client_secret=self._client_secret,
            server_metadata_url=self.issuer + "/.well-known/openid-configuration",
            client_cls=_App,
            client_kwargs={
                "default_timeout": _HTTP_TIMEOUT_S,
                "scope": self.scope,
                # Without this Authlib silently sends no PKCE.
                "code_challenge_method": "S256",
                # Authlib's client_secret_basic does not form-urlencode the id and
                # secret (RFC 6749 §2.3.1); posting them avoids the question.
                "token_endpoint_auth_method": "client_secret_post",
            },
        )

    # ── metadata ──

    @property
    def metadata(self) -> Dict[str, Any]:
        md = self.client.load_server_metadata()
        if md.get("issuer") != self.issuer:
            raise NobleIdError("invalid_issuer", "discovery issuer does not match the configured issuer")
        if "ES256" not in (md.get("id_token_signing_alg_values_supported") or []):
            raise NobleIdError("invalid_request", "provider does not advertise ES256")
        local = _is_local_http(self.issuer)
        for name in _ENDPOINTS:
            url = md.get(name)
            if not isinstance(url, str) or not (urlsplit(url).scheme == "https" or (local and _is_local_http(url))):
                raise NobleIdError("invalid_request", f"discovery {name} is missing or not https")
        return md

    def _claims_options(self) -> Dict[str, Any]:
        # iss and aud both required and compared; Authlib's default checks iss only.
        return {
            "iss": {"essential": True, "values": [self.issuer]},
            "aud": {"essential": True, "values": [self.client_id]},
        }

    # ── sign-in ──

    def start_sign_in(self, redirect_uri: str, **params):
        """Return a Flask redirect to NobleID. Extra params: prompt, max_age, login_hint."""
        from flask import session

        self.metadata  # validate discovery before sending anyone anywhere
        state = secrets.token_urlsafe(32)
        session[_TX_KEY] = {"state": state, "created_at": time.time()}
        allowed = {k: v for k, v in params.items() if k in ("prompt", "max_age", "login_hint")}
        # Authlib adds the nonce and the PKCE challenge and keeps them in the session.
        return self.client.authorize_redirect(redirect_uri, state=state, **allowed)

    def finish_sign_in(self) -> Dict[str, Any]:
        """Complete sign-in on the redirect URI.

        Checks, in order: a sign-in is in progress, ``state`` matches, ``iss``
        is the issuer, then surfaces any ``error``, then exchanges the code
        (PKCE) and verifies the ID token (ES256 signature via JWKS, iss, aud,
        exp, nonce). Returns ``{"tokens", "claims", "scope"}``.
        """
        from flask import request, session

        tx = session.pop(_TX_KEY, None)  # single use
        args = request.args
        if not tx or not isinstance(tx.get("state"), str):
            raise NobleIdError("invalid_state", "no sign-in in progress")
        if not hmac.compare_digest(args.get("state", ""), tx["state"]):
            raise NobleIdError("invalid_state", "state does not match")
        if args.get("iss") != self.issuer:
            raise NobleIdError("invalid_issuer", "the response did not come from the expected issuer")
        if args.get("error"):
            raise NobleIdError(args.get("error", ""), args.get("error_description", ""))
        if not args.get("code"):
            raise NobleIdError("invalid_request", "no authorization code")
        if time.time() - float(tx.get("created_at", 0)) > MAX_FLOW_AGE_S:
            raise NobleIdError("expired", "sign-in took too long; start again")
        try:
            token = self.client.authorize_access_token(claims_options=self._claims_options())
        except Exception as exc:  # noqa: BLE001
            raise _wrap(exc) from None
        claims = dict(token.get("userinfo") or {})
        if not claims.get("sub"):
            raise NobleIdError("invalid_token", "no verified ID token")
        return {"tokens": _tokens(token), "claims": claims, "scope": (token.get("scope") or "").split()}

    # ── resources ──

    def userinfo(self, access_token: str, expected_sub: str) -> Dict[str, Any]:
        try:
            r = requests.get(self.metadata["userinfo_endpoint"], headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}, timeout=_HTTP_TIMEOUT_S, allow_redirects=False)
            _check_2xx(r)
            data = r.json()
        except Exception as exc:  # noqa: BLE001
            raise _wrap(exc) from None
        if data.get("sub") != expected_sub:
            raise NobleIdError("invalid_token", "userinfo sub differs from the ID token sub")
        return data

    def works(self, access_token: str, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        try:
            r = requests.get(
                self.issuer + "/oauth/works",
                params={"limit": limit, "offset": offset},
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                timeout=_HTTP_TIMEOUT_S,
                allow_redirects=False,
            )
            _check_2xx(r)
            return r.json()
        except Exception as exc:  # noqa: BLE001
            raise _wrap(exc) from None

    # ── refresh / revoke ──

    def refresh(self, refresh_token: str, scope: Optional[str] = None, *, expected_sub: Optional[str] = None) -> Dict[str, Any]:
        """Use a refresh token; store the rotated one it returns.

        NobleID revokes the whole session if a used refresh token is presented
        again, so concurrent calls with the same token in this process share
        one request (the first caller's ``scope`` is used). Nothing is
        remembered once it finishes, so a later replay of the used token goes
        to the provider and is refused. Across processes, serialise per
        session yourself. On ``invalid_grant``, sign the user out.

        A refresh-issued ID token is verified (ES256, iss, aud, exp, no nonce)
        for each caller and its claims returned as ``"claims"``; pass the
        ``sub`` you stored at sign-in as ``expected_sub`` and a different one
        is rejected.
        """
        key = hashlib.sha256(refresh_token.encode()).hexdigest()
        with self._inflight_guard:
            flight = self._inflight.get(key)
            leader = flight is None
            if leader:
                flight = self._inflight[key] = _Flight()
        if leader:
            try:
                flight.result = self._refresh_request(refresh_token, scope)
            except Exception as exc:  # noqa: BLE001
                flight.error = _wrap(exc)
            finally:
                # Publish, then remove: a caller arriving in between shares
                # this result instead of sending the spent token again.
                flight.done.set()
                with self._inflight_guard:
                    self._inflight.pop(key, None)
        else:
            flight.done.wait()
        if flight.error is not None:
            e = flight.error
            raise NobleIdError(e.code, e.description, e.status, e.retry_after) from None
        raw = dict(flight.result or {})
        out = _tokens(raw)
        if raw.get("id_token"):
            claims = self._verify_refreshed_id_token(raw)
            if expected_sub is not None and not hmac.compare_digest(str(claims.get("sub", "")), expected_sub):
                raise NobleIdError("invalid_token", "the refreshed ID token is for another subject")
            out["claims"] = claims
        return out

    def _refresh_request(self, refresh_token: str, scope: Optional[str]) -> Dict[str, Any]:
        form = {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": self.client_id, "client_secret": self._client_secret}
        if scope:
            form["scope"] = scope
        r = requests.post(self.metadata["token_endpoint"], data=form, headers={"Accept": "application/json"}, timeout=_HTTP_TIMEOUT_S, allow_redirects=False)
        _check_2xx(r)
        return r.json()

    def _verify_refreshed_id_token(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        try:
            claims = self.client.parse_id_token(
                {"id_token": raw["id_token"], "access_token": raw.get("access_token")},
                nonce=None,
                claims_options=self._claims_options(),
            )
        except Exception as exc:  # noqa: BLE001
            raise _wrap(exc) from None
        claims = dict(claims or {})
        if not claims.get("sub"):
            raise NobleIdError("invalid_token", "no verified ID token")
        # Refresh-issued ID tokens carry no nonce; a stray one is refused.
        if "nonce" in claims:
            raise NobleIdError("invalid_token", "unexpected nonce in a refreshed ID token")
        return claims

    def revoke(self, token: str, token_type_hint: Optional[str] = None) -> None:
        """Revoke a token (RFC 7009). Revoking the refresh token also ends its access tokens."""
        form = {"token": token, "client_id": self.client_id, "client_secret": self._client_secret}
        if token_type_hint:
            form["token_type_hint"] = token_type_hint
        try:
            r = requests.post(self.metadata["revocation_endpoint"], data=form, timeout=_HTTP_TIMEOUT_S, allow_redirects=False)
            _check_2xx(r)
        except Exception as exc:  # noqa: BLE001
            raise _wrap(exc) from None


class _Flight:
    """One refresh request in flight, shared by the callers waiting on it."""

    __slots__ = ("done", "result", "error")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[NobleIdError] = None


def _tokens(t: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: t.get(k) for k in ("access_token", "refresh_token", "id_token", "token_type", "scope") if t.get(k) is not None}
    # Read expires_in from every response; do not hardcode a lifetime.
    out["expires_at"] = int(time.time()) + int(t.get("expires_in") or 0)
    return out


def granted(scope: List[str], name: str) -> bool:
    """True when the user actually granted ``name`` (they may untick scopes)."""
    return name in scope


from .profiles import profile_from_claims  # noqa: E402  (after NobleIdError, which it raises)
