/**
 * Simulates the exact requests made by the WordPress plugin
 * "OpenID Connect Generic Client" (daggerhart-openid-connect-generic, 3.11.x)
 * against the mock, with the settings from examples/wordpress/README.md:
 * redirect URI admin-ajax.php?action=openid-connect-authorize, client_secret_post,
 * no PKCE, no nonce, a `scope` parameter on the token request, ID token checked
 * against the JWKS with the configured issuer, userinfo with a Bearer header.
 */
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createMock } from "../mock-oidc/server.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CLIENTS = JSON.parse(fs.readFileSync(path.join(ROOT, "test/clients.json"), "utf8")).clients;
const CONF = CLIENTS.find((c) => c.type === "confidential");

let mock, meta;
test.before(async () => {
  mock = createMock({ clients: CLIENTS });
  await mock.listen(0);
  meta = await (await fetch(mock.issuer + "/.well-known/openid-configuration")).json();
});
test.after(() => mock.close());

// PHP rawurlencode() == encodeURIComponent plus encoding of !'()*
const rawurlencode = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());

test("WordPress plugin request shape signs in against the mock", async () => {
  const site = "http://localhost:8089";
  const redirectUri = site + "/wp-admin/admin-ajax.php?action=openid-connect-authorize";
  const scope = "openid email profile";
  const state = crypto.randomBytes(16).toString("hex"); // bin2hex(random_bytes(16))

  // 1. Authorization request: the plugin's own URL format (no nonce, no PKCE).
  const authUrl =
    meta.authorization_endpoint +
    "?" +
    `response_type=code&scope=${rawurlencode(scope)}&client_id=${rawurlencode(CONF.client_id)}&state=${rawurlencode(state)}&redirect_uri=${rawurlencode(redirectUri)}`;
  const a = await fetch(authUrl, { redirect: "manual" });
  assert.equal(a.status, 302);
  const cb = new URL(a.headers.get("location"));
  assert.equal(cb.origin + cb.pathname, site + "/wp-admin/admin-ajax.php");
  assert.equal(cb.searchParams.get("action"), "openid-connect-authorize", "the registered query survives");
  assert.equal(cb.searchParams.get("state"), state);
  assert.equal(cb.searchParams.get("iss"), meta.issuer);
  const code = cb.searchParams.get("code");
  assert.ok(code);

  // 2. Token request: client_secret_post, redirect_uri, grant_type and the plugin's extra `scope`.
  const t = await fetch(meta.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Host: new URL(meta.token_endpoint).host },
    body: new URLSearchParams({ code, client_id: CONF.client_id, client_secret: CONF.client_secret, redirect_uri: redirectUri, grant_type: "authorization_code", scope }),
  });
  const tokens = await t.json();
  assert.equal(t.status, 200, JSON.stringify(tokens));
  assert.equal(tokens.refresh_token, undefined, "no offline_access requested, no refresh token");

  // 3. ID token validation as the plugin's JWT validator does it (JWKS URI + Issuer configured).
  const [h, p, s] = tokens.id_token.split(".");
  const header = JSON.parse(Buffer.from(h, "base64url"));
  const claims = JSON.parse(Buffer.from(p, "base64url"));
  const jwks = await (await fetch(meta.jwks_uri)).json();
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  assert.equal(jwk.alg, "ES256", "JWKS keys carry alg, which the plugin's JWT library requires");
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  assert.ok(crypto.verify("sha256", Buffer.from(h + "." + p), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url")));
  assert.equal(claims.aud, CONF.client_id);
  assert.equal(claims.iss, meta.issuer, "set the plugin's Issuer field: it would otherwise derive it from the login endpoint host");
  assert.notEqual(new URL(meta.authorization_endpoint).origin, claims.iss, "deriving the issuer from the login endpoint would fail");
  assert.ok(claims.sub && claims.exp && claims.iat);
  assert.equal(claims.nonce, undefined);

  // 4. Userinfo with a Bearer header; identity key `sub`, nickname key `preferred_username`, email `{email}`.
  const u = await fetch(meta.userinfo_endpoint, { headers: { Authorization: "Bearer " + tokens.access_token } });
  const info = await u.json();
  assert.equal(u.status, 200);
  assert.equal(info.sub, claims.sub);
  assert.ok(info.preferred_username);
  assert.ok(info.email);
  assert.equal(info.email_verified, true);
  assert.ok(!("end_session_endpoint" in meta), "leave the plugin's End Session Endpoint URL empty");
});
