"""Unit tests for nobleid_signin against a tiny in-process provider.

Run from packages/python with the package's dependencies installed:

    python -B -m unittest discover -s tests
"""

import base64
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from flask import Flask

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nobleid_signin import NobleID, NobleIdError  # noqa: E402

CLIENT_ID = "nbcl_test"
KEY = ec.generate_private_key(ec.SECP256R1())


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwk() -> dict:
    n = KEY.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig", "alg": "ES256",
            "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}


def sign(claims: dict, alg: str = "ES256") -> str:
    head = b64u(json.dumps({"alg": alg, "kid": "k1", "typ": "JWT"}).encode())
    body = b64u(json.dumps(claims).encode())
    r, s = decode_dss_signature(KEY.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
    return f"{head}.{body}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


class Provider:
    """Discovery, JWKS, token and revocation endpoints on 127.0.0.1."""

    def __init__(self):
        self.hits = {}
        self.token_delay = 0.0
        self.token_status = 200
        self.id_token_claims = None  # dict -> an ID token is included
        self.id_token_alg = "ES256"
        self.revoke_status = 200
        self.doc_overrides = {}
        self.discovery_status = 200
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body, headers=None):
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def _hit(self):
                path = self.path.split("?")[0]
                provider.hits[path] = provider.hits.get(path, 0) + 1
                return path

            def do_GET(self):
                path = self._hit()
                if path == "/.well-known/openid-configuration":
                    if provider.discovery_status != 200:
                        return self._send(provider.discovery_status, {}, {"Location": "https://evil.example/"})
                    return self._send(200, provider.doc())
                if path == "/jwks":
                    return self._send(200, {"keys": [jwk()]})
                self._send(404, {})

            def do_POST(self):
                path = self._hit()
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if path == "/token":
                    time.sleep(provider.token_delay)
                    if provider.token_status != 200:
                        return self._send(provider.token_status, {"error": "invalid_grant"})
                    n = provider.hits[path]
                    out = {"access_token": f"AT{n}", "token_type": "Bearer", "expires_in": 60, "refresh_token": f"RT{n}", "scope": "openid"}
                    if provider.id_token_claims is not None:
                        out["id_token"] = sign(provider.id_token_claims, provider.id_token_alg)
                    return self._send(200, out)
                if path == "/revoke":
                    return self._send(provider.revoke_status, {}, {"Location": "https://evil.example/"})
                self._send(404, {})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def doc(self):
        b = self.base
        d = {"issuer": b, "authorization_endpoint": f"{b}/authorize", "token_endpoint": f"{b}/token",
             "userinfo_endpoint": f"{b}/userinfo", "revocation_endpoint": f"{b}/revoke", "jwks_uri": f"{b}/jwks",
             "id_token_signing_alg_values_supported": ["ES256", "RS256"]}
        d.update(self.doc_overrides)
        return d

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def claims(**over):
    now = int(time.time())
    c = {"iss": None, "sub": "user-1", "aud": CLIENT_ID, "exp": now + 300, "iat": now}
    c.update(over)
    return c


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.p = Provider()
        self.n = NobleID(Flask(__name__), client_id=CLIENT_ID, client_secret="secret", issuer=self.p.base)

    def tearDown(self):
        self.p.close()

    def id_claims(self, **over):
        return claims(iss=self.p.base, **over)

    # discovery

    def test_non_https_endpoint_is_refused(self):
        self.p.doc_overrides = {"token_endpoint": "http://evil.example/token"}
        with self.assertRaises(NobleIdError) as cm:
            self.n.metadata
        self.assertIn("token_endpoint", cm.exception.description)

    def test_discovery_redirect_is_not_followed(self):
        self.p.discovery_status = 302
        with self.assertRaises(NobleIdError):
            self.n.metadata

    # ID token checks used at sign-in

    def parse(self, c, alg="ES256"):
        tok = {"id_token": sign(c, alg), "access_token": "AT"}
        return self.n.client.parse_id_token(tok, nonce="n1", claims_options=self.n._claims_options())

    def test_valid_id_token(self):
        self.assertEqual(self.parse(self.id_claims(nonce="n1"))["sub"], "user-1")

    def test_wrong_audience_is_rejected(self):
        with self.assertRaises(Exception):
            self.parse(self.id_claims(nonce="n1", aud="someone-else"))

    def test_missing_audience_is_rejected(self):
        c = self.id_claims(nonce="n1")
        del c["aud"]
        with self.assertRaises(Exception):
            self.parse(c)

    def test_alg_other_than_es256_is_rejected(self):
        with self.assertRaises(NobleIdError):
            self.parse(self.id_claims(nonce="n1"), alg="RS256")

    # refresh

    def test_refresh_verifies_the_id_token_and_sub(self):
        self.p.id_token_claims = self.id_claims()
        r = self.n.refresh("RT0", expected_sub="user-1")
        self.assertEqual(r["claims"]["sub"], "user-1")
        with self.assertRaises(NobleIdError) as cm:
            self.n.refresh("RT-other", expected_sub="user-2")
        self.assertEqual(cm.exception.code, "invalid_token")

    def test_refresh_rejects_a_bad_id_token(self):
        self.p.id_token_claims = self.id_claims(aud="someone-else")
        with self.assertRaises(NobleIdError):
            self.n.refresh("RT0")
        self.p.id_token_claims = self.id_claims(nonce="stray")
        with self.assertRaises(NobleIdError):
            self.n.refresh("RT1")
        self.p.id_token_claims = self.id_claims()
        self.p.id_token_alg = "RS256"
        with self.assertRaises(NobleIdError):
            self.n.refresh("RT2")

    def test_concurrent_refreshes_share_one_request(self):
        self.p.token_delay = 0.3
        results = []
        threads = [threading.Thread(target=lambda: results.append(self.n.refresh("RT0"))) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(self.p.hits.get("/token"), 1)
        self.assertEqual({r["refresh_token"] for r in results}, {"RT1"})
        self.assertEqual(self.n._inflight, {})

    def test_a_replay_after_the_request_finished_is_sent_not_answered_from_memory(self):
        self.n.refresh("RT0")
        self.n.refresh("RT0")
        self.assertEqual(self.p.hits.get("/token"), 2)

    def test_errors_are_not_kept(self):
        self.p.token_status = 400
        with self.assertRaises(NobleIdError) as cm:
            self.n.refresh("RT0")
        self.assertEqual(cm.exception.code, "invalid_grant")
        self.assertEqual(self.n._inflight, {})

    # revoke

    def test_revoke_requires_2xx(self):
        self.n.revoke("RT0", "refresh_token")
        self.p.revoke_status = 302
        with self.assertRaises(NobleIdError):
            self.n.revoke("RT0", "refresh_token")


if __name__ == "__main__":
    unittest.main()
