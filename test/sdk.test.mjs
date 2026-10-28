/**
 * Tests for sdk/nobleid-auth.js, run in Node against the local mock.
 * The SDK is loaded into a fresh VM context per test with small shims for
 * window, sessionStorage, location, history and document.
 */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createMock } from "../mock-oidc/server.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SDK = fs.readFileSync(path.join(ROOT, "sdk/nobleid-auth.js"), "utf8");
const CLIENTS = JSON.parse(fs.readFileSync(path.join(ROOT, "test/clients.json"), "utf8")).clients;
const PUBLIC = CLIENTS.find((c) => c.type === "public").client_id;
const REDIRECT = "http://localhost:5173/callback.html";

/* ── a deliberately small DOM: enough for the SDK, and loud if it misbehaves ── */
class FakeNode {
  constructor(doc, tag) {
    this.ownerDocument = doc;
    this.tagName = tag;
    this.attributes = {};
    this.children = [];
    this.listeners = {};
    this.style = { cssText: "" };
    this._text = "";
  }
  setAttribute(k, v) {
    this.attributes[k] = String(v);
  }
  getAttribute(k) {
    return Object.prototype.hasOwnProperty.call(this.attributes, k) ? this.attributes[k] : null;
  }
  appendChild(c) {
    this.children.push(c);
    return c;
  }
  removeChild(c) {
    this.children = this.children.filter((x) => x !== c);
    return c;
  }
  get firstChild() {
    return this.children[0] || null;
  }
  addEventListener(t, fn) {
    (this.listeners[t] = this.listeners[t] || []).push(fn);
  }
  set textContent(v) {
    this.children = [];
    this._text = String(v);
  }
  get textContent() {
    return this._text + this.children.map((c) => c.textContent).join("");
  }
  set innerHTML(_) {
    throw new Error("innerHTML must never be used");
  }
  set outerHTML(_) {
    throw new Error("outerHTML must never be used");
  }
  insertAdjacentHTML() {
    throw new Error("insertAdjacentHTML must never be used");
  }
  all() {
    return [this, ...this.children.flatMap((c) => (c.all ? c.all() : [c]))];
  }
}

function makeBrowser({ search = "", fetchSpy, auto = [] } = {}) {
  const store = new Map();
  const created = [];
  const doc = {
    readyState: "complete",
    createElement(tag) {
      created.push(tag);
      return new FakeNode(doc, tag.toLowerCase());
    },
    createTextNode(t) {
      return { nodeType: 3, textContent: String(t) };
    },
    getElementById(id) {
      return doc.byId[id] || null;
    },
    querySelectorAll() {
      return doc.autoNodes;
    },
    addEventListener() {},
    write() {
      throw new Error("document.write must never be used");
    },
    byId: {},
    autoNodes: [],
  };
  for (const attrs of auto) {
    const n = new FakeNode(doc, "div");
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    doc.autoNodes.push(n);
  }
  const window = {
    crypto: globalThis.crypto,
    TextEncoder,
    URLSearchParams,
    URL,
    btoa,
    atob,
    Promise,
    Date,
    Math,
    JSON,
    Object,
    Array,
    String,
    Number,
    Error,
    isNaN,
    Uint8Array,
    encodeURIComponent,
    decodeURIComponent,
    console: { error() {}, log() {} },
    fetch: (url, init) => {
      if (fetchSpy) fetchSpy(String(url), init);
      return fetch(url, init);
    },
    sessionStorage: {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k),
    },
    location: {
      search,
      pathname: "/callback.html",
      href: "http://localhost:5173/callback.html" + search,
      origin: "http://localhost:5173",
      assigned: null,
      assign(u) {
        this.assigned = u;
      },
    },
    history: {
      calls: [],
      replaceState(...a) {
        this.calls.push(a);
      },
    },
    document: doc,
    eval() {
      throw new Error("eval must never be used");
    },
  };
  window.window = window;
  const ctx = vm.createContext(window);
  vm.runInContext(SDK, ctx, { filename: "nobleid-auth.js" });
  return { window, NobleID: window.NobleID, store, created, doc };
}

/* ── mock provider shared by the tests ── */
let mock;
let mockUrl;
let authEndpoint;
test.before(async () => {
  mock = createMock({ clients: CLIENTS });
  await mock.listen(0);
  mockUrl = mock.issuer;
  authEndpoint = (await (await fetch(mockUrl + "/.well-known/openid-configuration")).json()).authorization_endpoint;
});
test.after(() => mock.close());
test.beforeEach(() => fetch(mockUrl + "/__mock/reset", { method: "POST", body: "{}" }));

const control = (p, body) => fetch(mockUrl + p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });

async function startFlow(b, { scope = "openid profile email works", override } = {}) {
  b.NobleID.configure({ issuer: mockUrl, authorizationEndpoint: authEndpoint });
  const url = await b.NobleID.createAuthorizeUrl({ clientId: PUBLIC, redirectUri: REDIRECT, scope });
  if (override) await control("/__mock/next-authorize", override);
  const r = await fetch(url, { redirect: "manual" });
  assert.equal(r.status, 302);
  const cb = new URL(r.headers.get("location"));
  return { url: new URL(url), cb };
}

async function rejects(p, code) {
  await assert.rejects(p, (e) => {
    assert.equal(e.code, code, `expected ${code}, got ${e.code}: ${e.message}`);
    return true;
  });
}

/* ── tests ── */

test("version and public API are backwards compatible", () => {
  const { NobleID } = makeBrowser();
  assert.equal(NobleID.version, "2.1.1");
  for (const k of ["renderButton", "createButton", "createAuthorizeUrl", "signIn", "handleCallback", "revoke", "configure", "renderResearcherBadge"]) {
    assert.equal(typeof NobleID[k], "function", k);
  }
  assert.equal(NobleID.issuer, "https://id.nobleid.org");
  assert.equal(NobleID.endpoints.authorization, "https://www.nobleid.org/oauth/authorize");
  assert.equal(NobleID.endpoints.token, "https://id.nobleid.org/oauth/token");
  assert.equal(NobleID.endpoints.jwks, "https://id.nobleid.org/.well-known/jwks.json");
});

test("configure refuses non-https issuers except localhost", () => {
  const { NobleID } = makeBrowser();
  assert.throws(() => NobleID.configure({ issuer: "http://evil.example" }));
  assert.throws(() => NobleID.configure({ issuer: "javascript:alert(1)" }));
  assert.throws(() => NobleID.configure({ issuer: "https://ok.example", authorizationEndpoint: "http://evil.example/a" }));
  NobleID.configure({ issuer: "http://localhost:1234" });
  assert.equal(NobleID.endpoints.token, "http://localhost:1234/oauth/token");
  NobleID.configure({});
  assert.equal(NobleID.endpoints.authorization, "https://www.nobleid.org/oauth/authorize");
});

test("authorize URL: code + PKCE S256 + state + nonce, flow kept in sessionStorage", async () => {
  const b = makeBrowser();
  const { url } = await startFlow(b);
  const q = url.searchParams;
  assert.equal(q.get("response_type"), "code");
  assert.equal(q.get("code_challenge_method"), "S256");
  assert.match(q.get("code_challenge"), /^[A-Za-z0-9_-]{43}$/);
  assert.match(q.get("state"), /^[A-Za-z0-9_-]{43}$/);
  assert.match(q.get("nonce"), /^[A-Za-z0-9_-]{43}$/);
  assert.ok(q.get("scope").split(" ").includes("openid"));
  const flow = JSON.parse(b.store.get("nobleid_oauth"));
  assert.equal(flow.state, q.get("state"));
  assert.ok(!url.href.includes(flow.codeVerifier), "verifier must not appear in the URL");
});

test("handleCallback: full public-client sign-in, single use, URL cleaned", async () => {
  const b = makeBrowser();
  const { cb } = await startFlow(b);
  b.window.location.search = cb.search;
  const r = await b.NobleID.handleCallback({ clientId: PUBLIC, redirectUri: REDIRECT });
  assert.equal(r.claims.sub, "mock-user-sub-0001");
  assert.equal(r.claims.nobleid, "NI0MOCKUSER0001");
  assert.equal(r.claims.verified_authorship_count, 1);
  assert.equal(r.idTokenClaims.amr.join(","), "pwd,otp,mfa");
  assert.equal([...r.scope].sort().join(" "), "email openid profile works");
  assert.ok(r.tokens.access_token.startsWith("nbat_"));
  assert.equal(b.window.history.calls.length, 1, "code removed from the address bar");
  assert.equal(b.store.has("nobleid_oauth"), false, "flow removed");
  await rejects(b.NobleID.handleCallback({ clientId: PUBLIC, redirectUri: REDIRECT }), "invalid_state"); // replay
});

test("wrong state is rejected before any token request", async () => {
  const calls = [];
  const b = makeBrowser({ fetchSpy: (u) => calls.push(u) });
  const { cb } = await startFlow(b);
  cb.searchParams.set("state", "x".repeat(43));
  b.window.location.search = cb.search;
  await rejects(b.NobleID.handleCallback(), "invalid_state");
  assert.equal(calls.length, 0);
});

test("a forged error with the wrong state is invalid_state, not the error", async () => {
  const b = makeBrowser();
  await startFlow(b);
  b.window.location.search = "?error=access_denied&error_description=forged&state=wrong&iss=" + encodeURIComponent(mockUrl);
  await rejects(b.NobleID.handleCallback(), "invalid_state");
});

test("an error with the right state but wrong or missing iss is invalid_issuer", async () => {
  for (const iss of ["https://evil.example", null]) {
    const b = makeBrowser();
    const { cb } = await startFlow(b);
    const q = new URLSearchParams({ error: "access_denied", state: cb.searchParams.get("state") });
    if (iss) q.set("iss", iss);
    b.window.location.search = "?" + q;
    await rejects(b.NobleID.handleCallback(), "invalid_issuer");
  }
});

test("denied consent surfaces access_denied (right state and iss)", async () => {
  const b = makeBrowser();
  const { cb } = await startFlow(b, { override: { deny: true } });
  assert.equal(cb.searchParams.get("error"), "access_denied");
  assert.equal(cb.searchParams.get("iss"), mockUrl, "mock adds iss to error redirects");
  b.window.location.search = cb.search;
  await rejects(b.NobleID.handleCallback(), "access_denied");
});

test("iss mismatch and missing iss on a success response are rejected", async () => {
  for (const override of [{ badIss: "https://evil.example" }, { omitIss: true }]) {
    const b = makeBrowser();
    const { cb } = await startFlow(b, { override });
    b.window.location.search = cb.search;
    await rejects(b.NobleID.handleCallback(), "invalid_issuer");
  }
});

test("ID token nonce mismatch is rejected", async () => {
  const b = makeBrowser();
  const { cb } = await startFlow(b, { override: { badNonce: true } });
  b.window.location.search = cb.search;
  await rejects(b.NobleID.handleCallback(), "invalid_token");
});

test("ID token aud mismatch is rejected", async () => {
  const b = makeBrowser();
  const { cb } = await startFlow(b, { override: { badAud: true } });
  b.window.location.search = cb.search;
  await rejects(b.NobleID.handleCallback(), "invalid_token");
});

test("an expired flow is rejected", async () => {
  const b = makeBrowser();
  const { cb } = await startFlow(b);
  const flow = JSON.parse(b.store.get("nobleid_oauth"));
  flow.createdAt -= 11 * 60 * 1000;
  b.store.set("nobleid_oauth", JSON.stringify(flow));
  b.window.location.search = cb.search;
  await rejects(b.NobleID.handleCallback(), "expired");
});

test("clientId or redirectUri differing from the start is rejected", async () => {
  const b = makeBrowser();
  const { cb } = await startFlow(b);
  b.window.location.search = cb.search;
  await rejects(b.NobleID.handleCallback({ clientId: "nbcl_someoneelse000000000000" }), "invalid_request");
});

test("a replayed authorization code fails at the token endpoint", async () => {
  const b = makeBrowser();
  const { cb } = await startFlow(b);
  const saved = b.store.get("nobleid_oauth");
  b.window.location.search = cb.search;
  await b.NobleID.handleCallback();
  b.store.set("nobleid_oauth", saved); // an attacker restoring the flow still cannot reuse the code
  await rejects(b.NobleID.handleCallback(), "invalid_grant");
});

test("slow_down from the token endpoint carries retryAfter", async () => {
  const b = makeBrowser();
  const { cb } = await startFlow(b);
  await control("/__mock/rate-limit", { count: 1, retryAfter: 7 });
  b.window.location.search = cb.search;
  await assert.rejects(b.NobleID.handleCallback(), (e) => e.code === "slow_down" && e.retryAfter === 7);
});

test("revoke ends the access token (public client, client_id only)", async () => {
  const b = makeBrowser();
  const { cb } = await startFlow(b);
  b.window.location.search = cb.search;
  const r = await b.NobleID.handleCallback();
  assert.equal(await b.NobleID.revoke({ clientId: PUBLIC, token: r.tokens.access_token, tokenTypeHint: "access_token" }), true);
  const ui = await fetch(mockUrl + "/oauth/userinfo", { headers: { Authorization: "Bearer " + r.tokens.access_token } });
  assert.equal(ui.status, 401);
});

/* ── button ── */

test("button: safe hrefs only, official labels, min height 40px, no innerHTML", () => {
  const { NobleID } = makeBrowser();
  for (const bad of ["javascript:alert(1)", "//evil.example", "/\t/evil.example", "/\\evil.example", "http://evil.example/x", " https://x.example", "data:text/html,x"]) {
    assert.throws(() => NobleID.createButton({ loginUrl: bad }), /loginUrl/, bad);
  }
  const a = NobleID.createButton({ loginUrl: "/auth/nobleid/start", theme: "dark", size: "sm", label: "Continue with NobleID" });
  assert.equal(a.tagName, "a");
  assert.equal(a.getAttribute("href"), "/auth/nobleid/start");
  assert.match(a.style.cssText, /min-height:40px/);
  assert.equal(a.textContent, "Continue with NobleID");
  const b = NobleID.createButton({ clientId: PUBLIC, redirectUri: REDIRECT, label: "Click here to win" });
  assert.equal(b.tagName, "button");
  assert.equal(b.textContent, "Sign in with NobleID");
  assert.equal(b.children[0].getAttribute("src"), "https://www.nobleid.org/brand/nobleid-mark.svg");
});

/* ── researcher badge ── */

const GOOD = {
  sub: "mock-user-sub-0001",
  name: "Ada Example",
  nobleid: "NI0MOCKUSER0001",
  nobleid_uri: "https://www.nobleid.org/NI0MOCKUSER0001",
  identity_verified: true,
  nobleid_verified_researcher: true,
  orcid: "https://orcid.org/0000-0002-1825-0097",
  orcid_verified: true,
  verified_authorship_count: 3,
};

function links(el) {
  return el.all().filter((n) => n.tagName === "a");
}

test("badge: shows only true markers, links only to nobleid.org and orcid.org", () => {
  const b = makeBrowser();
  const box = new FakeNode(b.doc, "div");
  const badge = b.NobleID.renderResearcherBadge(box, GOOD);
  const text = badge.textContent;
  for (const s of ["Ada Example", "NI0MOCKUSER0001", "ID verified", "Verified researcher", "ORCID 0000-0002-1825-0097", "3 verified authorships"]) assert.ok(text.includes(s), s);
  const ls = links(badge);
  assert.deepEqual(ls.map((a) => a.getAttribute("href")).sort(), [GOOD.nobleid_uri, GOOD.orcid].sort());
  for (const a of ls) {
    assert.equal(a.getAttribute("rel"), "noopener noreferrer");
    assert.equal(a.getAttribute("target"), "_blank");
  }
  const none = b.NobleID.renderResearcherBadge(box, { name: "X", nobleid: "NI0MOCKUSER0001", identity_verified: false, verified_authorship_count: 0 });
  assert.ok(!none.textContent.includes("verified"), "no false markers");
});

test("badge: hostile claim values are inert", () => {
  const b = makeBrowser();
  const box = new FakeNode(b.doc, "div");
  const hostile = {
    name: '<script>alert("x")</script><img src=x onerror=alert(1)>',
    nobleid: "NI0MOCKUSER0001",
    nobleid_uri: "javascript:alert(1)",
    identity_verified: "true",
    nobleid_verified_researcher: 1,
    orcid: "javascript:alert(2)",
    orcid_verified: true,
    verified_authorship_count: "5",
  };
  const badge = b.NobleID.renderResearcherBadge(box, hostile);
  assert.ok(badge.textContent.includes('<script>alert("x")</script>'), "name rendered as text");
  assert.equal(links(badge).length, 0, "no links for unsafe URLs");
  assert.ok(!b.created.some((t) => /^(script|iframe|object|embed|style)$/i.test(t)), "no active elements created");
  for (const s of ["ID verified", "Verified researcher", "ORCID", "authorship"]) assert.ok(!badge.textContent.includes(s), s);

  for (const uri of [
    "https://evil.example/NI0MOCKUSER0001",
    "https://www.nobleid.org.evil.example/NI0MOCKUSER0001",
    "https://www.nobleid.org@evil.example/NI0MOCKUSER0001",
    "http://www.nobleid.org/NI0MOCKUSER0001",
    "https://www.nobleid.org/NI0MOCKUSER0001/../../x",
    "https://www.nobleid.org/NI0MOCKUSER0001?next=https://evil.example",
    "//www.nobleid.org/NI0MOCKUSER0001",
  ]) {
    const el = b.NobleID.renderResearcherBadge(box, { ...GOOD, nobleid_uri: uri, orcid: "https://orcid.org.evil.example/0000-0002-1825-0097" });
    const hrefs = links(el).map((a) => a.getAttribute("href"));
    assert.deepEqual(hrefs, [], `${uri} must not be linked`);
  }
  const unverifiedOrcid = b.NobleID.renderResearcherBadge(box, { ...GOOD, orcid_verified: false });
  assert.ok(!unverifiedOrcid.textContent.includes("ORCID"));
});

test("button: hostile loginUrl values are refused; accepted ones stay same-site or https", () => {
  const { NobleID } = makeBrowser();
  const hostile = [
    "//evil.example", "///evil.example", "/\\evil.example", "\\\\evil.example", "/\t/evil.example", "/\n/evil.example",
    "/\r\nSet-Cookie:x=1", "\t//evil.example", " //evil.example", "javascript:alert(1)", "JaVaScRiPt:alert(1)",
    "java\tscript:alert(1)", "data:text/html,<script>alert(1)</script>", "vbscript:x", "blob:https://evil.example/x",
    "https:evil.example", "https:/evil.example", "http://evil.example", "http://localhost.evil.example/",
    "http://127.0.0.1@evil.example/", "http://localhost:3000@evil.example/", "\uff0f\uff0fevil.example",
    "\u2215\u2215evil.example", "/\u0085/evil.example", "/\u007f/evil.example", "x".repeat(3000),
  ];
  for (const bad of hostile) assert.throws(() => NobleID.createButton({ loginUrl: bad }), /loginUrl/, JSON.stringify(bad));
  const accepted = ["/login", "/%2F%2Fevil.example", "/%5Cevil.example", "/auth?next=//evil.example", "https://app.example/login", "http://localhost:3000/login", "http://[::1]:3000/x"];
  for (const ok of accepted) {
    const href = NobleID.createButton({ loginUrl: ok }).getAttribute("href");
    const u = new URL(href, "https://app.example/page");
    assert.ok(u.origin === "https://app.example" || u.protocol === "https:" || /^http:\/\/(localhost|\[::1\])(:\d+)?$/.test(u.origin), ok);
    if (ok.startsWith("/")) assert.equal(u.origin, "https://app.example", ok);
  }
});

test("badge: the NobleID links only to its own profile; names cannot imitate markers", () => {
  const b = makeBrowser();
  const box = new FakeNode(b.doc, "div");
  const other = b.NobleID.renderResearcherBadge(box, { ...GOOD, nobleid_uri: "https://www.nobleid.org/NI0SOMEONEELSE1" });
  assert.deepEqual(links(other).map((a) => a.getAttribute("href")), [GOOD.orcid], "mismatched nobleid_uri is not linked");
  assert.ok(other.textContent.includes(GOOD.nobleid));
  const spoof = b.NobleID.renderResearcherBadge(box, {
    name: "Mallory \u2713 ID verified \u2714 \u2705 \u2611 \u221a \ud83d\uddf8 \ud83d\uddf9 \u237b \ud800\udd02 \ud83e\udfb1 \u202eecnetsixe\u202c \u2066x\u2069\u200f",
    nobleid: "NI0MOCKUSER0001",
  });
  const strong = spoof.all().find((n) => n.tagName === "strong");
  assert.doesNotMatch(strong.textContent, /[\u2713\u2714\u2705\u2611\u221a\u237b\u202a-\u202e\u2066-\u2069\u200e\u200f]|\ud83d[\uddf8\uddf9]|\ud800\udd02|\ud83e\udfb1/);
  assert.equal(strong.getAttribute("dir"), "auto");
  assert.ok(!spoof.all().some((n) => n.tagName === "ul"), "no marker list without true markers");
  const blank = b.NobleID.renderResearcherBadge(box, { name: " \u202e\u2713 ", nobleid: "NI0MOCKUSER0001" });
  assert.ok(blank.textContent.includes("NobleID member"));
});

test("badge: no money, support or payment wording in the SDK", () => {
  assert.doesNotMatch(SDK, /\b(tip|tips|tipping|donat\w*|pay|payment\w*|wallet|support this)\b/i);
});

test("data attributes: only this page's origin (sanitised markup can carry data-*)", () => {
  const cases = [
    [{ "data-nobleid-login-url": "/auth/start" }, "/auth/start"],
    [{ "data-nobleid-login-url": "http://localhost:5173/auth/start" }, "http://localhost:5173/auth/start"],
    [{ "data-nobleid-login-url": "https://evil.example/phish" }, null],
    [{ "data-nobleid-login-url": "http://localhost:5174/auth/start" }, null],
    [{ "data-nobleid-login-url": "//evil.example/x" }, null],
    [{ "data-nobleid-client-id": "nbcl_x", "data-nobleid-redirect-uri": "http://localhost:5173/callback.html" }, "button"],
    [{ "data-nobleid-client-id": "nbcl_attacker", "data-nobleid-redirect-uri": "https://evil.example/cb" }, null],
  ];
  for (const [attrs, want] of cases) {
    const { doc } = makeBrowser({ auto: [attrs] });
    const node = doc.autoNodes[0];
    const btn = node.children[0];
    if (want === null) assert.equal(btn, undefined, JSON.stringify(attrs));
    else if (want === "button") assert.equal(btn.tagName, "button", JSON.stringify(attrs));
    else assert.equal(btn.getAttribute("href"), want, JSON.stringify(attrs));
  }
  // The JS API is unchanged: an https login URL on another origin is the integrator's own choice.
  const { NobleID } = makeBrowser();
  assert.equal(NobleID.createButton({ loginUrl: "https://app.example/auth/start" }).getAttribute("href"), "https://app.example/auth/start");
});
