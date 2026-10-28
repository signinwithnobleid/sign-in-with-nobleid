/**
 * Protocol conformance of the local mock: it must behave like the provider in
 * every way the examples and docs rely on. If one of these fails, the
 * examples' tests prove nothing.
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
const PUB = CLIENTS.find((c) => c.type === "public");
const RU = "http://localhost:8080/callback";

let mock, base, meta;
test.before(async () => {
  mock = createMock({ clients: CLIENTS });
  await mock.listen(0);
  base = mock.issuer;
  meta = await (await fetch(base + "/.well-known/openid-configuration")).json();
});
test.after(() => mock.close());
test.beforeEach(() => fetch(base + "/__mock/reset", { method: "POST", body: "{}" }));

const b64u = (b) => Buffer.from(b).toString("base64url");
const basic = (id, secret) => "Basic " + Buffer.from(encodeURIComponent(id) + ":" + encodeURIComponent(secret)).toString("base64");
const ctl = (p, body) => fetch(base + p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });

async function authorize(params, override) {
  if (override) await ctl("/__mock/next-authorize", override);
  const u = new URL(meta.authorization_endpoint);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) u.searchParams.set(k, v);
  const r = await fetch(u, { redirect: "manual" });
  return { status: r.status, location: r.headers.get("location") ? new URL(r.headers.get("location")) : null, text: await r.text() };
}

function pkce() {
  const verifier = b64u(crypto.randomBytes(32));
  return { verifier, challenge: b64u(crypto.createHash("sha256").update(verifier).digest()) };
}

async function token(form, { auth, contentType = "application/x-www-form-urlencoded", raw } = {}) {
  const headers = { "Content-Type": contentType };
  if (auth) headers.Authorization = auth;
  const r = await fetch(meta.token_endpoint, { method: "POST", headers, body: raw ?? new URLSearchParams(form).toString() });
  const text = await r.text();
  return { status: r.status, body: text ? JSON.parse(text) : null, headers: r.headers };
}

async function codeFor({ client = CONF, scope = "openid profile email offline_access", withPkce = true, override, nonce = "n-123" } = {}) {
  const p = pkce();
  const a = await authorize(
    {
      response_type: "code",
      client_id: client.client_id,
      redirect_uri: RU,
      scope,
      state: "s-1",
      nonce,
      code_challenge: withPkce ? p.challenge : undefined,
      code_challenge_method: withPkce ? "S256" : undefined,
    },
    override
  );
  assert.equal(a.status, 302, a.text);
  return { code: a.location.searchParams.get("code"), verifier: p.verifier, location: a.location };
}

async function exchange(c, { client = CONF, verifier, method = "basic" } = {}) {
  const form = { grant_type: "authorization_code", code: c.code, redirect_uri: RU };
  if (verifier !== null) form.code_verifier = verifier ?? c.verifier;
  if (client.type === "public") return token({ ...form, client_id: client.client_id });
  if (method === "post") return token({ ...form, client_id: client.client_id, client_secret: client.client_secret });
  return token(form, { auth: basic(client.client_id, client.client_secret) });
}

function decode(jwt) {
  const [h, p] = jwt.split(".");
  return { header: JSON.parse(Buffer.from(h, "base64url")), payload: JSON.parse(Buffer.from(p, "base64url")) };
}

/* ── discovery & keys ── */

test("discovery: issuer, authorize on another host, ES256 only, S256 only, query only, no end_session", () => {
  assert.equal(meta.issuer, base);
  assert.notEqual(new URL(meta.authorization_endpoint).host, new URL(base).host);
  assert.deepEqual(meta.id_token_signing_alg_values_supported, ["ES256"]);
  assert.deepEqual(meta.code_challenge_methods_supported, ["S256"]);
  assert.deepEqual(meta.response_types_supported, ["code"]);
  assert.deepEqual(meta.response_modes_supported, ["query"]);
  assert.equal(meta.authorization_response_iss_parameter_supported, true);
  for (const k of ["end_session_endpoint", "registration_endpoint", "acr_values_supported", "dpop_signing_alg_values_supported"]) assert.ok(!(k in meta), k);
  for (const k of ["profile_complete", "verification_level", "affiliation"]) assert.ok(meta.claims_supported.includes(k), k);
  assert.ok(!meta.claims_supported.includes("verified"), "the proposed `verified` array was dropped");
});

test("oauth-authorization-server metadata mirrors discovery", async () => {
  const m = await (await fetch(base + "/.well-known/oauth-authorization-server")).json();
  assert.equal(m.issuer, meta.issuer);
});

test("JWKS: P-256 ES256 keys with RFC 7638 kid; retired keys stay published", async () => {
  const jwks = await (await fetch(meta.jwks_uri)).json();
  const k = jwks.keys[0];
  assert.equal(k.kty, "EC");
  assert.equal(k.crv, "P-256");
  assert.equal(k.alg, "ES256");
  assert.equal(k.d, undefined, "no private material");
  const tp = b64u(crypto.createHash("sha256").update(JSON.stringify({ crv: k.crv, kty: k.kty, x: k.x, y: k.y })).digest());
  assert.equal(k.kid, tp);
  await ctl("/__mock/rotate-key");
  const after = await (await fetch(meta.jwks_uri)).json();
  assert.equal(after.keys.length, 2);
  assert.ok(after.keys.some((x) => x.kid === k.kid));
});

/* ── authorize ── */

test("authorize: unknown client or unregistered redirect_uri is shown, never redirected", async () => {
  const a = await authorize({ response_type: "code", client_id: "nbcl_unknown000000000000000000", redirect_uri: RU, scope: "openid" });
  assert.equal(a.status, 400);
  assert.equal(a.location, null);
  const b = await authorize({ response_type: "code", client_id: CONF.client_id, redirect_uri: "https://evil.example/cb", scope: "openid" });
  assert.equal(b.status, 400);
  assert.equal(b.location, null);
});

test("authorize: success redirect carries code, state and iss; loopback port may vary", async () => {
  const c = await codeFor();
  assert.match(c.code, /^nbac_/);
  assert.equal(c.location.searchParams.get("state"), "s-1");
  assert.equal(c.location.searchParams.get("iss"), base);
  assert.equal(c.location.port, "8080");
});

test("authorize: errors redirect with error, error_description, state and iss", async () => {
  const cases = [
    [{ response_type: "token" }, "unsupported_response_type"],
    [{ response_mode: "fragment" }, "invalid_request"],
    [{ scope: "profile" }, "invalid_scope"],
    [{ scope: "openid admin" }, "invalid_scope"],
    [{ code_challenge: "x".repeat(43), code_challenge_method: "plain" }, "invalid_request"],
    [{ prompt: "none login" }, "invalid_request"],
  ];
  for (const [extra, err] of cases) {
    const a = await authorize({ response_type: "code", client_id: CONF.client_id, redirect_uri: RU, scope: "openid", state: "st", ...extra });
    assert.equal(a.status, 302);
    assert.equal(a.location.searchParams.get("error"), err, JSON.stringify(extra));
    assert.ok(a.location.searchParams.get("error_description"));
    assert.equal(a.location.searchParams.get("state"), "st");
    assert.equal(a.location.searchParams.get("iss"), base);
  }
});

test("authorize: public clients must send PKCE", async () => {
  const a = await authorize({ response_type: "code", client_id: PUB.client_id, redirect_uri: RU, scope: "openid", state: "x" });
  assert.equal(a.location.searchParams.get("error"), "invalid_request");
});

test("prompt=none: consent_required without a grant, login_required when signed out, silent with a grant", async () => {
  const params = { response_type: "code", client_id: CONF.client_id, redirect_uri: RU, scope: "openid profile", state: "x", prompt: "none" };
  assert.equal((await authorize(params)).location.searchParams.get("error"), "consent_required");
  await codeFor({ scope: "openid profile" });
  assert.ok((await authorize(params)).location.searchParams.get("code"));
  assert.equal((await authorize(params, { loginRequired: true })).location.searchParams.get("error"), "login_required");
});

test("a redirect URI with a query keeps it (WordPress shape)", async () => {
  const ru = "http://localhost:8081/wp-admin/admin-ajax.php?action=openid-connect-authorize";
  const a = await authorize({ response_type: "code", client_id: CONF.client_id, redirect_uri: ru, scope: "openid", state: "w" });
  assert.equal(a.location.searchParams.get("action"), "openid-connect-authorize");
  assert.ok(a.location.searchParams.get("code"));
});

/* ── token ── */

test("token: client_secret_basic and client_secret_post both work; ID token is ES256 with claims", async () => {
  for (const method of ["basic", "post"]) {
    const r = await exchange(await codeFor(), { method });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.token_type, "Bearer");
    assert.equal(r.body.expires_in, 900);
    assert.match(r.body.access_token, /^nbat_/);
    assert.match(r.body.refresh_token, /^nbrt_/);
    assert.equal(r.headers.get("cache-control"), "no-store");
    assert.equal(r.headers.get("access-control-allow-origin"), "*");
    const { header, payload } = decode(r.body.id_token);
    assert.equal(header.alg, "ES256");
    assert.equal(payload.iss, base);
    assert.equal(payload.aud, CONF.client_id);
    assert.equal(payload.nonce, "n-123");
    assert.deepEqual(payload.amr, ["pwd", "otp", "mfa"]);
    assert.equal(payload.exp - payload.iat, 600);
    assert.ok(payload.auth_time);
    assert.equal(payload.research_interests, undefined, "userinfo-only");
    assert.equal(payload.verified_authorship_count, undefined, "userinfo-only");
  }
});

test("profile-gate claims: profile and affiliations scopes, ID token and userinfo", async () => {
  const both = decode((await exchange(await codeFor({ scope: "openid profile affiliations" }))).body.id_token).payload;
  assert.equal(both.profile_complete, true);
  assert.equal(both.verification_level, "authorship");
  assert.deepEqual(both.affiliation, { name: "Example University" });
  assert.equal(both.affiliations, undefined, "the full list stays userinfo-only");
  const bare = decode((await exchange(await codeFor({ scope: "openid" }))).body.id_token).payload;
  for (const k of ["profile_complete", "verification_level", "affiliation"]) assert.equal(bare[k], undefined, k);
});

test("ID token signature verifies against the JWKS", async () => {
  const r = await exchange(await codeFor());
  const jwks = await (await fetch(meta.jwks_uri)).json();
  const [h, p, s] = r.body.id_token.split(".");
  const key = crypto.createPublicKey({ key: jwks.keys.find((k) => k.kid === decode(r.body.id_token).header.kid), format: "jwk" });
  assert.ok(crypto.verify("sha256", Buffer.from(h + "." + p), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url")));
});

test("token: client-auth failures are 401 invalid_client with the exact body; mixing methods is 400", async () => {
  const c = await codeFor();
  const expect = { error: "invalid_client", error_description: "Client authentication failed" };
  const wrong = await token({ grant_type: "authorization_code", code: c.code, redirect_uri: RU, code_verifier: c.verifier }, { auth: basic(CONF.client_id, "nbcs_wrong") });
  assert.equal(wrong.status, 401);
  assert.deepEqual(wrong.body, expect);
  const both = await token(
    { grant_type: "authorization_code", code: c.code, redirect_uri: RU, code_verifier: c.verifier, client_secret: CONF.client_secret },
    { auth: basic(CONF.client_id, CONF.client_secret) }
  );
  assert.equal(both.status, 400, "basic + post in one request is a malformed request");
  assert.equal(both.body.error, "invalid_request");
  const mismatch = await token({ grant_type: "authorization_code", code: c.code, redirect_uri: RU, code_verifier: c.verifier, client_id: PUB.client_id }, { auth: basic(CONF.client_id, CONF.client_secret) });
  assert.equal(mismatch.status, 400, "body client_id differing from Basic");
  const noSecret = await token({ grant_type: "authorization_code", code: c.code, redirect_uri: RU, client_id: CONF.client_id });
  assert.equal(noSecret.status, 401);
  const publicWithSecret = await token({ grant_type: "authorization_code", code: c.code, client_id: PUB.client_id, client_secret: "x" });
  assert.equal(publicWithSecret.status, 401);
});

test("token: JSON bodies and repeated parameters are refused with 400 invalid_request", async () => {
  const json = await token(null, { contentType: "application/json", raw: JSON.stringify({ grant_type: "authorization_code" }) });
  assert.equal(json.status, 400);
  assert.equal(json.body.error, "invalid_request");
  const rep = await token(null, { raw: "grant_type=authorization_code&code=a&code=b", auth: basic(CONF.client_id, CONF.client_secret) });
  assert.equal(rep.status, 400);
  assert.equal(rep.body.error, "invalid_request");
});

test("PKCE: wrong verifier refused; verifier for a code issued without a challenge refused (downgrade)", async () => {
  const c = await codeFor();
  const bad = await exchange(c, { verifier: b64u(crypto.randomBytes(32)) });
  assert.equal(bad.body.error, "invalid_grant");
  const noPkce = await codeFor({ withPkce: false });
  const down = await exchange(noPkce, { verifier: b64u(crypto.randomBytes(32)) });
  assert.equal(down.body.error, "invalid_grant");
  const ok = await exchange(await codeFor({ withPkce: false }), { verifier: null });
  assert.equal(ok.status, 200, "confidential client without PKCE is allowed");
  const missing = await exchange(await codeFor(), { verifier: null });
  assert.equal(missing.body.error, "invalid_grant", "a challenge that was sent is always enforced");
});

test("a replayed code is refused and revokes the tokens it minted", async () => {
  const c = await codeFor();
  const first = await exchange(c);
  const replay = await exchange(c);
  assert.equal(replay.body.error, "invalid_grant");
  const ui = await fetch(meta.userinfo_endpoint, { headers: { Authorization: "Bearer " + first.body.access_token } });
  assert.equal(ui.status, 401);
  const rt = await token({ grant_type: "refresh_token", refresh_token: first.body.refresh_token }, { auth: basic(CONF.client_id, CONF.client_secret) });
  assert.equal(rt.body.error, "invalid_grant");
});

test("expired codes are refused", async () => {
  const c = await codeFor();
  await ctl("/__mock/expire-codes");
  assert.equal((await exchange(c)).body.error, "invalid_grant");
});

test("refresh: rotates; reuse of a rotated token revokes the family; narrowing ok, widening refused", async () => {
  const auth = basic(CONF.client_id, CONF.client_secret);
  const first = await exchange(await codeFor());
  const r1 = await token({ grant_type: "refresh_token", refresh_token: first.body.refresh_token }, { auth });
  assert.equal(r1.status, 200);
  assert.notEqual(r1.body.refresh_token, first.body.refresh_token);
  const idp = decode(r1.body.id_token).payload;
  for (const k of ["auth_time", "nonce", "amr"]) assert.equal(idp[k], undefined, k + " omitted on refresh");
  const narrowed = await token({ grant_type: "refresh_token", refresh_token: r1.body.refresh_token, scope: "openid profile" }, { auth });
  assert.equal(narrowed.body.scope, "openid profile");
  const widened = await token({ grant_type: "refresh_token", refresh_token: narrowed.body.refresh_token, scope: "openid works" }, { auth });
  assert.equal(widened.body.error, "invalid_scope");
  const reuse = await token({ grant_type: "refresh_token", refresh_token: first.body.refresh_token }, { auth });
  assert.equal(reuse.body.error, "invalid_grant");
  const latest = await token({ grant_type: "refresh_token", refresh_token: narrowed.body.refresh_token }, { auth });
  assert.equal(latest.body.error, "invalid_grant", "family revoked after reuse");
  assert.equal((await fetch(meta.userinfo_endpoint, { headers: { Authorization: "Bearer " + narrowed.body.access_token } })).status, 401);
});

test("no refresh token without offline_access, or when the user unticked it", async () => {
  assert.equal((await exchange(await codeFor({ scope: "openid profile" }))).body.refresh_token, undefined);
  const r = await exchange(await codeFor({ override: { untick: ["offline_access", "email", "openid"] } }));
  assert.equal(r.body.refresh_token, undefined);
  assert.equal(r.body.scope, "openid profile", "openid cannot be unticked; granted scope is narrower");
});

/* ── userinfo & works ── */

test("userinfo: header, form body; never query; never twice; error shapes", async () => {
  const at = (await exchange(await codeFor({ scope: "openid profile email orcid affiliations works" }))).body.access_token;
  const g = await fetch(meta.userinfo_endpoint, { headers: { Authorization: "Bearer " + at } });
  assert.equal(g.status, 200);
  assert.equal(g.headers.get("cache-control"), "no-store");
  const ui = await g.json();
  assert.equal(ui.sub, "mock-user-sub-0001");
  assert.ok(Array.isArray(ui.research_interests));
  assert.ok(Array.isArray(ui.affiliations));
  assert.equal(ui.orcid_verified, true);
  assert.equal(ui.works_count, 2);
  assert.equal(ui.verified_authorship_count, 1);
  assert.equal(ui.works_endpoint, base + "/oauth/works");
  assert.equal(ui.profile_complete, true);
  assert.equal(ui.verification_level, "authorship");
  assert.deepEqual(ui.affiliation, { name: "Example University" });
  assert.equal(ui.verified, undefined);

  const f = await fetch(meta.userinfo_endpoint, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "access_token=" + at });
  assert.equal(f.status, 200);
  const q = await fetch(meta.userinfo_endpoint + "?access_token=" + at);
  assert.equal(q.status, 401, "a query-string token is ignored, never read");
  assert.equal(await q.text(), "");
  const twice = await fetch(meta.userinfo_endpoint, { method: "POST", headers: { Authorization: "Bearer " + at, "Content-Type": "application/x-www-form-urlencoded" }, body: "access_token=" + at });
  assert.equal(twice.status, 400);
  assert.equal((await twice.json()).error, "invalid_request");

  const none = await fetch(meta.userinfo_endpoint);
  assert.equal(none.status, 401);
  assert.equal(none.headers.get("www-authenticate"), 'Bearer realm="nobleid"');
  assert.equal(await none.text(), "");
  const bad = await fetch(meta.userinfo_endpoint, { headers: { Authorization: "Bearer nbat_nope" } });
  assert.equal(bad.status, 401);
  assert.deepEqual(await bad.json(), { error: "invalid_token" });
  assert.match(bad.headers.get("www-authenticate"), /error="invalid_token"/);
});

test("userinfo without openid / works without works scope: 403 insufficient_scope", async () => {
  const auth = basic(CONF.client_id, CONF.client_secret);
  const first = await exchange(await codeFor({ scope: "openid profile offline_access" }));
  const noOpenid = await token({ grant_type: "refresh_token", refresh_token: first.body.refresh_token, scope: "profile" }, { auth });
  const u = await fetch(meta.userinfo_endpoint, { headers: { Authorization: "Bearer " + noOpenid.body.access_token } });
  assert.equal(u.status, 403);
  assert.equal((await u.json()).error, "insufficient_scope");
  const w = await fetch(base + "/oauth/works", { headers: { Authorization: "Bearer " + first.body.access_token } });
  assert.equal(w.status, 403);
});

test("works: paging and shape", async () => {
  const at = (await exchange(await codeFor({ scope: "openid works" }))).body.access_token;
  const r = await (await fetch(base + "/oauth/works?limit=1&offset=1", { headers: { Authorization: "Bearer " + at } })).json();
  assert.equal(r.total, 2);
  assert.equal(r.limit, 1);
  assert.equal(r.offset, 1);
  assert.equal(r.works.length, 1);
  for (const k of ["nobleid", "ark", "url", "title", "type", "doi", "publication_date", "publication_year", "version", "registered_at"]) assert.ok(k in r.works[0], k);
  assert.match(r.works[0].ark, /^ark:\/48914\//);
  assert.equal((await fetch(base + "/oauth/works?limit=101", { headers: { Authorization: "Bearer " + at } })).status, 400);
});

/* ── revoke & introspect ── */

test("revoke: 200 {} always; refresh revocation ends the family and its access tokens", async () => {
  const auth = basic(CONF.client_id, CONF.client_secret);
  const t = (await exchange(await codeFor())).body;
  const unknown = await fetch(meta.revocation_endpoint, { method: "POST", headers: { Authorization: auth, "Content-Type": "application/x-www-form-urlencoded" }, body: "token=nbrt_unknown" });
  assert.equal(unknown.status, 200);
  assert.deepEqual(await unknown.json(), {});
  const r = await fetch(meta.revocation_endpoint, { method: "POST", headers: { Authorization: auth, "Content-Type": "application/x-www-form-urlencoded" }, body: "token=" + t.refresh_token + "&token_type_hint=refresh_token" });
  assert.equal(r.status, 200);
  assert.equal((await fetch(meta.userinfo_endpoint, { headers: { Authorization: "Bearer " + t.access_token } })).status, 401);
});

test("revoke by another client is a no-op; public clients revoke with client_id only", async () => {
  const t = (await exchange(await codeFor())).body;
  await fetch(meta.revocation_endpoint, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token: t.access_token, client_id: PUB.client_id }) });
  assert.equal((await fetch(meta.userinfo_endpoint, { headers: { Authorization: "Bearer " + t.access_token } })).status, 200);
});

test("introspect: confidential only; inactive for anything not the caller's own live token", async () => {
  const auth = basic(CONF.client_id, CONF.client_secret);
  const t = (await exchange(await codeFor())).body;
  const call = (body, headers = { Authorization: auth }) =>
    fetch(meta.introspection_endpoint, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers }, body });
  const live = await (await call("token=" + t.access_token)).json();
  assert.equal(live.active, true);
  assert.equal(live.client_id, CONF.client_id);
  assert.deepEqual(await (await call("token=nbat_nope")).json(), { active: false });
  const pub = await call(new URLSearchParams({ token: t.access_token, client_id: PUB.client_id }), {});
  assert.equal(pub.status, 401);
  assert.equal((await pub.json()).error, "invalid_client");
});

/* ── PAR, rate limits, CORS ── */

test("PAR: pushed request then authorize with request_uri", async () => {
  const p = pkce();
  const r = await fetch(meta.pushed_authorization_request_endpoint, {
    method: "POST",
    headers: { Authorization: basic(CONF.client_id, CONF.client_secret), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ response_type: "code", redirect_uri: RU, scope: "openid", state: "par", code_challenge: p.challenge, code_challenge_method: "S256" }),
  });
  assert.equal(r.status, 201);
  const { request_uri } = await r.json();
  const a = await authorize({ client_id: CONF.client_id, request_uri });
  assert.equal(a.location.searchParams.get("state"), "par");
  assert.ok(a.location.searchParams.get("code"));
});

test("429 slow_down with Retry-After; CORS preflight on protocol endpoints", async () => {
  await ctl("/__mock/rate-limit", { count: 1, retryAfter: 3 });
  const r = await fetch(meta.userinfo_endpoint);
  assert.equal(r.status, 429);
  assert.equal(r.headers.get("retry-after"), "3");
  assert.deepEqual(await r.json(), { error: "slow_down" });
  const pre = await fetch(meta.token_endpoint, { method: "OPTIONS" });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get("access-control-allow-origin"), "*");
  assert.equal(pre.headers.get("access-control-allow-credentials"), null);
});

test("the mock answers loopback clients only", () => {
  const H = { host: "localhost:9400" };
  const cases = [
    ["192.0.2.10", H, 403], ["::ffff:192.0.2.10", H, 403], ["10.127.0.1", H, 403], ["fe80::1", H, 403], [undefined, H, 403],
    ["127.0.0.1", H, null], ["::1", H, null], ["::ffff:127.0.0.1", H, null],
    ["127.0.0.1", { host: "127.0.0.1:9400" }, null], ["::1", { host: "[::1]:9400" }, null], ["127.0.0.1", { host: "LOCALHOST" }, null],
    // DNS rebinding, tunnels and reverse proxies connect from loopback too
    ["127.0.0.1", {}, 403], ["127.0.0.1", { host: "rebind.evil.example:9400" }, 403], ["127.0.0.1", { host: "localhost.evil.example" }, 403],
    ["127.0.0.1", { host: "abc.tunnel.example" }, 403],
    ["127.0.0.1", { ...H, "x-forwarded-for": "203.0.113.9" }, 403], ["127.0.0.1", { ...H, forwarded: "for=203.0.113.9" }, 403],
    ["127.0.0.1", { ...H, "x-real-ip": "203.0.113.9" }, 403], ["127.0.0.1", { ...H, "cf-connecting-ip": "203.0.113.9" }, 403],
  ];
  for (const [addr, headers, want] of cases) {
    let status = null;
    const res = { writeHead: (s) => (status = s), setHeader() {}, end() {}, headersSent: false };
    mock.server.emit("request", { socket: { remoteAddress: addr }, method: "GET", url: "/__mock/state", headers, on() {} }, res);
    const label = String(addr) + " " + JSON.stringify(headers);
    if (want) assert.equal(status, want, label);
    else assert.notEqual(status, 403, label);
  }
});

test("test controls refuse requests from web pages (cross-site POST)", async () => {
  for (const [origin, want] of [["https://evil.example", 403], ["null", 403], ["http://localhost.evil.example", 403], ["http://localhost:5173", 200], ["http://127.0.0.1:3000", 200]]) {
    const r = await fetch(base + "/__mock/rate-limit", { method: "POST", headers: { Origin: origin, "Content-Type": "text/plain" }, body: JSON.stringify({ count: 5 }) });
    assert.equal(r.status, want, origin);
  }
  await ctl("/__mock/reset");
});

test("authorize: a repeated parameter uses the first value, as on the provider", async () => {
  const p = pkce();
  const u = new URL(meta.authorization_endpoint);
  for (const [k, v] of [["response_type", "code"], ["client_id", CONF.client_id], ["redirect_uri", RU], ["redirect_uri", "https://evil.example/cb"],
    ["scope", "openid"], ["state", "first"], ["state", "second"], ["nonce", "n"], ["code_challenge", p.challenge], ["code_challenge_method", "S256"]]) u.searchParams.append(k, v);
  const r = await fetch(u, { redirect: "manual" });
  assert.equal(r.status, 302);
  const loc = new URL(r.headers.get("location"));
  assert.equal(loc.origin + loc.pathname, RU);
  assert.deepEqual(loc.searchParams.getAll("state"), ["first"]);
  assert.ok(loc.searchParams.get("code"));
});
