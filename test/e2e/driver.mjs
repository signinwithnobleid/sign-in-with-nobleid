/**
 * Language-agnostic end-to-end scenarios for a server-side example app.
 *
 * Every server example follows the same small contract (see test/README.md):
 *   GET  /            signed out: contains id="signed-out"; signed in: <pre id="claims">{json}</pre>
 *   GET  /login       starts sign-in (redirects to the provider)   [profile.login]
 *   GET  <callback>   completes sign-in, then redirects to /; failures render id="error"
 *   GET  /works       <pre id="works">{json}</pre>                  [profile.works]
 *   POST /refresh     refresh-token grant (rotation)                 [profile.refresh]
 *   POST /logout      revoke + clear session                         [profile.logout]
 *
 * The driver acts as the browser and the user, and asks the mock what happened.
 */
import assert from "node:assert/strict";
import { CookieJar, request, follow, preJson, formFields } from "./http.mjs";

const EVIL = "https://evil.example";

export async function runScenarios({ appUrl, mockUrl, clientId, profile = {}, log = console.log }) {
  const p = {
    login: "/login",
    loginMethod: "GET",
    works: true,
    refresh: true,
    logout: true,
    pkce: true,
    nonce: true,
    negative: ["wrong_state", "iss_mismatch", "iss_missing", "denied", "nonce_mismatch", "aud_mismatch", "narrowed_consent"],
    ...profile,
  };
  const app = new URL(appUrl);
  const onApp = (u) => new URL(u).host === app.host;
  const results = [];

  const mock = async (path, body) => {
    const r = await fetch(mockUrl + path, body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    return r.json();
  };
  const clientState = async () => (await mock("/__mock/state")).clients[clientId];

  async function startLogin(jar) {
    let res;
    if (p.loginMethod === "authjs") {
      const csrf = await request(jar, new URL("/api/auth/csrf", app).toString());
      const { csrfToken } = JSON.parse(csrf.text);
      res = await request(jar, new URL("/api/auth/signin/nobleid", app).toString(), {
        method: "POST",
        body: { csrfToken, callbackUrl: appUrl + "/" },
        origin: app.origin,
      });
    } else {
      res = await request(jar, new URL(p.login, app).toString());
    }
    res = await follow(jar, res, onApp);
    assert.ok(res.location, `login did not redirect (status ${res.status})`);
    assert.ok(!onApp(res.location), "login did not leave the app");
    return res.location;
  }

  async function authorize(authUrl) {
    const r = await request(null, authUrl);
    assert.equal(r.status, 302, `authorize returned ${r.status}: ${r.text.slice(0, 200)}`);
    return r.location;
  }

  async function finish(jar, callbackUrl) {
    assert.ok(onApp(callbackUrl), "provider redirected somewhere other than the app: " + callbackUrl);
    const r = await request(jar, callbackUrl);
    return follow(jar, r, onApp);
  }

  async function home(jar) {
    return request(jar, appUrl + "/");
  }

  async function postForm(jar, path) {
    const page = await home(jar);
    const fields = formFields(page.text, path);
    assert.ok(fields, `no <form action="${path}"> on the signed-in page`);
    const r = await request(jar, new URL(path, app).toString(), { method: "POST", body: fields, origin: app.origin });
    assert.ok(r.status < 400, `POST ${path} -> ${r.status}: ${r.text.slice(0, 300)}`);
    return follow(jar, r, onApp);
  }

  async function signIn(jar, override) {
    const authUrl = await startLogin(jar);
    if (override) await mock("/__mock/next-authorize", override);
    const cb = await authorize(authUrl);
    return { authUrl, cb, final: await finish(jar, cb) };
  }

  async function expectSignedOut(jar, why) {
    const page = await home(jar);
    assert.ok(!preJson(page.text, "claims"), `${why}: app shows claims, i.e. the user was signed in`);
    assert.match(page.text, /id=["']signed-out["']/, `${why}: home page lacks id="signed-out"`);
  }

  function expectErrorPage(res, why, code) {
    assert.match(res.text, /id=["']error["']/, `${why}: expected an error page (id="error"), got status ${res.status}: ${res.text.slice(0, 300)}`);
    if (code) assert.ok(res.text.includes(code), `${why}: error page does not mention ${code}`);
  }

  async function scenario(name, fn) {
    try {
      await mock("/__mock/reset", {});
      await fn(new CookieJar());
      results.push({ name, ok: true });
      log(`ok - ${name}`);
    } catch (e) {
      results.push({ name, ok: false, error: e.message });
      log(`not ok - ${name}\n  # ${String(e.message).split("\n").join("\n  # ")}`);
    }
  }

  /* ── happy path, then works, refresh, logout on the same session ── */
  await scenario("sign-in: login -> authorize -> callback -> claims", async (jar) => {
    const { authUrl, final } = await signIn(jar);
    const q = new URL(authUrl).searchParams;
    assert.equal(q.get("response_type"), "code");
    assert.equal(q.get("client_id"), clientId);
    assert.ok(q.get("state"), "no state on the authorize request");
    if (p.pkce) assert.equal(q.get("code_challenge_method"), "S256", "PKCE S256 not used");
    if (p.nonce) assert.ok(q.get("nonce"), "no nonce on the authorize request");
    assert.ok(final.status < 400, `callback ended in ${final.status}: ${final.text.slice(0, 300)}`);
    const page = await home(jar);
    const claims = preJson(page.text, "claims");
    assert.ok(claims, "signed-in page has no <pre id=\"claims\">: " + page.text.slice(0, 300));
    assert.equal(claims.sub, "mock-user-sub-0001");
    assert.equal(claims.nobleid, "NI0MOCKUSER0001");
    assert.equal(claims.email_verified, true);
    assert.equal(claims.verified_authorship_count, 1, "userinfo-only claim missing: was userinfo called?");
    if ("name" in claims) {
      assert.equal(claims.profile_complete, true, "profile scope without profile_complete");
      assert.equal(claims.verification_level, "authorship", "profile scope without verification_level");
    }
    assert.ok(!("verified" in claims), "the proposed `verified` array was dropped");

    if (p.works) {
      const w = await request(jar, appUrl + "/works");
      const works = preJson(w.text, "works");
      assert.ok(works, "works page has no <pre id=\"works\">");
      assert.equal(works.total, 2);
      assert.ok(works.works[0].ark.startsWith("ark:/48914/"));
      log("  # works list ok");
    }

    if (p.refresh) {
      const before = (await clientState()).families;
      assert.equal(before.length, 1, "expected one refresh-token family (offline_access)");
      await postForm(jar, "/refresh");
      const after = (await clientState()).families;
      assert.equal(after[0].generation, before[0].generation + 1, "refresh did not rotate the refresh token");
      assert.equal(after[0].revoked, false, "refresh family revoked: was a rotated token reused?");
      const again = preJson((await home(jar)).text, "claims");
      assert.ok(again && again.sub === claims.sub, "not signed in after refresh");
      log("  # refresh rotated ok");
    }

    if (p.logout) {
      await postForm(jar, "/logout");
      await expectSignedOut(jar, "after logout");
      const s = await clientState();
      if (p.revokeOnLogout !== false) {
        assert.equal(s.liveRefreshTokens, 0, "refresh token still live after logout (not revoked)");
        assert.equal(s.liveAccessTokens, 0, "access token still live after logout (not revoked)");
      }
      log("  # logout + revoke ok");
    }
  });

  const neg = new Set(p.negative);

  if (neg.has("wrong_state"))
    await scenario("rejects a callback with the wrong state", async (jar) => {
      const authUrl = await startLogin(jar);
      const cb = new URL(await authorize(authUrl));
      cb.searchParams.set("state", "forged-" + (cb.searchParams.get("state") || ""));
      const res = await finish(jar, cb.toString());
      expectErrorPage(res, "wrong state");
      await expectSignedOut(jar, "wrong state");
    });

  if (neg.has("iss_mismatch"))
    await scenario("rejects a callback whose iss is not the issuer (RFC 9207)", async (jar) => {
      const { final } = await signIn(jar, { badIss: EVIL });
      expectErrorPage(final, "iss mismatch");
      await expectSignedOut(jar, "iss mismatch");
    });

  if (neg.has("iss_missing"))
    await scenario("rejects a callback without iss", async (jar) => {
      const { final } = await signIn(jar, { omitIss: true });
      expectErrorPage(final, "iss missing");
      await expectSignedOut(jar, "iss missing");
    });

  if (neg.has("denied"))
    await scenario("shows an error when the user denies consent", async (jar) => {
      const { final } = await signIn(jar, { deny: true });
      expectErrorPage(final, "denied", "access_denied");
      await expectSignedOut(jar, "denied");
    });

  if (neg.has("nonce_mismatch") && p.nonce)
    await scenario("rejects an ID token with the wrong nonce", async (jar) => {
      const { final } = await signIn(jar, { badNonce: true });
      expectErrorPage(final, "nonce mismatch");
      await expectSignedOut(jar, "nonce mismatch");
    });

  if (neg.has("aud_mismatch"))
    await scenario("rejects an ID token for another audience", async (jar) => {
      const { final } = await signIn(jar, { badAud: true });
      expectErrorPage(final, "aud mismatch");
      await expectSignedOut(jar, "aud mismatch");
    });

  if (neg.has("narrowed_consent"))
    await scenario("handles a user who unticked email and offline_access", async (jar) => {
      const { final } = await signIn(jar, { untick: ["email", "offline_access"] });
      assert.ok(final.status < 400, `callback ended in ${final.status}: ${final.text.slice(0, 300)}`);
      const claims = preJson((await home(jar)).text, "claims");
      assert.ok(claims, "not signed in after narrowed consent");
      assert.ok(!("email" in claims), "email shown although the user unticked it");
      assert.equal((await clientState()).families.length, 0, "a refresh token was issued without offline_access");
    });

  return results;
}
