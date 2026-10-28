/**
 * examples/html-sdk end to end: its static server (CSP, no traversal), and
 * its real page script (public/app.js) driving the served SDK through a full
 * public-client sign-in and sign-out against the mock, in a VM with a tiny DOM.
 */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import vm from "node:vm";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createMock } from "../mock-oidc/server.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CLIENTS = JSON.parse(fs.readFileSync(path.join(ROOT, "test/clients.json"), "utf8")).clients;
const PUBLIC = CLIENTS.find((c) => c.type === "public").client_id;

const freePort = () =>
  new Promise((r) => {
    const s = net.createServer().listen(0, () => {
      const p = s.address().port;
      s.close(() => r(p));
    });
  });

let mock, meta, server, site;
test.before(async () => {
  mock = createMock({ clients: CLIENTS });
  await mock.listen(0);
  meta = await (await fetch(mock.issuer + "/.well-known/openid-configuration")).json();
  const port = await freePort();
  site = `http://localhost:${port}`;
  server = spawn(process.execPath, ["serve.mjs"], {
    cwd: path.join(ROOT, "examples/html-sdk"),
    env: { ...process.env, PORT: String(port), ISSUER: mock.issuer, AUTHORIZATION_ENDPOINT: meta.authorization_endpoint, CLIENT_ID: PUBLIC },
    stdio: "ignore",
  });
  for (let i = 0; i < 100; i++) {
    try {
      await fetch(site + "/");
      break;
    } catch {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
});
test.after(async () => {
  server.kill("SIGTERM");
  await mock.close();
});

const get = async (p) => {
  const r = await fetch(site + p);
  return { status: r.status, headers: r.headers, text: await r.text() };
};

test("static server: strict CSP, the SDK copy, no path traversal, no inline scripts", async () => {
  const idx = await get("/");
  assert.equal(idx.status, 200);
  const csp = idx.headers.get("content-security-policy");
  assert.match(csp, /script-src 'self'/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
  for (const page of ["/", "/callback.html"]) {
    const html = (await get(page)).text;
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i, page + " has an inline script");
    assert.doesNotMatch(html, /\bon[a-z]+=/i, page + " has an inline event handler");
  }
  assert.equal((await get("/sdk/nobleid-auth.js")).text, fs.readFileSync(path.join(ROOT, "sdk/nobleid-auth.js"), "utf8"));
  assert.equal((await get("/../package.json")).status, 404);
  assert.equal((await get("/%2e%2e/serve.mjs")).status, 404);
  assert.doesNotMatch(fs.readFileSync(path.join(ROOT, "examples/html-sdk/public/app.js"), "utf8"), /innerHTML|eval\(|document\.write/);
});

/* ── a tiny DOM, enough for app.js ── */
function el(tag, id) {
  return {
    tagName: tag,
    id,
    hidden: true,
    attributes: {},
    children: [],
    style: {},
    listeners: {},
    _t: "",
    setAttribute(k, v) {
      this.attributes[k] = String(v);
    },
    getAttribute(k) {
      return this.attributes[k] ?? null;
    },
    appendChild(c) {
      this.children.push(c);
      return c;
    },
    removeChild(c) {
      this.children = this.children.filter((x) => x !== c);
    },
    get firstChild() {
      return this.children[0] || null;
    },
    addEventListener(t, f) {
      (this.listeners[t] = this.listeners[t] || []).push(f);
    },
    set textContent(v) {
      this.children = [];
      this._t = String(v);
    },
    get textContent() {
      return this._t + this.children.map((c) => c.textContent).join("");
    },
    set innerHTML(_) {
      throw new Error("innerHTML used");
    },
  };
}

async function loadPage(pathname, search = "", store = new Map()) {
  const ids = Object.fromEntries(["signin", "status", "badge", "claims", "signout"].map((i) => [i, el("div", i)]));
  if (pathname === "/") delete ids.badge, delete ids.claims, delete ids.signout;
  else delete ids.signin;
  const assigned = [];
  const document = {
    readyState: "complete",
    getElementById: (i) => ids[i] || null,
    createElement: (t) => el(t.toLowerCase()),
    createTextNode: (t) => ({ textContent: String(t) }),
    querySelectorAll: () => [],
    addEventListener() {},
  };
  const window = {
    document,
    crypto: globalThis.crypto,
    TextEncoder,
    URLSearchParams,
    btoa,
    atob,
    fetch,
    console: { error() {}, log() {} },
    matchMedia: () => ({ matches: false }),
    sessionStorage: { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) },
    location: { origin: site, pathname, search, assign: (u) => assigned.push(u) },
    history: { replaceState() {} },
  };
  window.window = window;
  const ctx = vm.createContext(window);
  for (const src of ["/sdk/nobleid-auth.js", "/config.js", "/app.js"]) vm.runInContext((await get(src)).text, ctx, { filename: src });
  return { ids, store, assigned, window };
}

const until = async (fn) => {
  for (let i = 0; i < 200 && !fn(); i++) await new Promise((r) => setTimeout(r, 10));
};

test("index.html renders the button; click starts a PKCE flow to the mock", async () => {
  const page = await loadPage("/");
  const btn = page.ids.signin.children[0];
  assert.equal(btn.tagName, "button");
  assert.equal(btn.textContent, "Sign in with NobleID");
  btn.listeners.click[0]();
  await until(() => page.assigned.length);
  const u = new URL(page.assigned[0]);
  assert.equal(u.origin + u.pathname, meta.authorization_endpoint);
  assert.equal(u.searchParams.get("redirect_uri"), site + "/callback.html");
  assert.equal(u.searchParams.get("code_challenge_method"), "S256");

  // The provider redirects back; callback.html in the same tab (same sessionStorage).
  const r = await fetch(u, { redirect: "manual" });
  const cb = new URL(r.headers.get("location"));
  assert.equal(cb.origin + cb.pathname, site + "/callback.html");
  const again = await loadPage("/callback.html", cb.search, page.store); // same tab, same sessionStorage
  await until(() => !again.ids.claims.hidden || /failed/.test(again.ids.status.textContent));
  assert.match(again.ids.status.textContent, /^Signed in as Ada Example/);
  const claims = JSON.parse(again.ids.claims.textContent);
  assert.equal(claims.sub, "mock-user-sub-0001");
  assert.ok(again.ids.badge.textContent.includes("NI0MOCKUSER0001"));

  // Sign out revokes the access token.
  again.ids.signout.listeners.click[0]();
  await until(() => again.assigned.length);
  assert.deepEqual(again.assigned, ["/"]);
  const st = await (await fetch(mock.issuer + "/__mock/state")).json();
  assert.equal(st.clients[PUBLIC].liveAccessTokens, 0);
});

test("callback.html shows the error when consent is denied", async () => {
  const page = await loadPage("/");
  page.ids.signin.children[0].listeners.click[0]();
  await until(() => page.assigned.length);
  await fetch(mock.issuer + "/__mock/next-authorize", { method: "POST", body: JSON.stringify({ deny: true }) });
  const r = await fetch(page.assigned[0], { redirect: "manual" });
  const cb = new URL(r.headers.get("location"));
  const cbPage = await loadPage("/callback.html", cb.search, page.store);
  await until(() => /failed/.test(cbPage.ids.status.textContent));
  assert.match(cbPage.ids.status.textContent, /access_denied/);
  assert.equal(cbPage.ids.claims.hidden, true);
});
