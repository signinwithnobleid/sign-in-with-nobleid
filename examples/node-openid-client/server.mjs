/**
 * Minimal "Sign in with NobleID" web app: Node's http module + nobleid-signin
 * (which wraps openid-client v6). Confidential client: the secret and tokens
 * stay on this server; the browser only gets an opaque session cookie.
 *
 *   ISSUER=https://id.nobleid.org CLIENT_ID=... CLIENT_SECRET=... \
 *   REDIRECT_URI=http://localhost:3000/callback node server.mjs
 */
import http from "node:http";
import crypto from "node:crypto";
import { createNobleIdClient, NobleIdError } from "nobleid-signin";

const ISSUER = process.env.ISSUER || "https://id.nobleid.org";
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || "http://localhost:3000/callback";
const PORT = Number(process.env.PORT || 3000);
const SCOPE = process.env.SCOPE || "openid profile email orcid affiliations works offline_access";

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error("Set CLIENT_ID and CLIENT_SECRET (see .env.example).");
  process.exit(1);
}

const nobleid = await createNobleIdClient({
  issuer: ISSUER,
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  clientAuth: "client_secret_basic",
  allowInsecureLocalhost: true, // only takes effect for an http://localhost issuer (the local mock)
});

const APP_ORIGIN = new URL(REDIRECT_URI).origin;
const CALLBACK_PATH = new URL(REDIRECT_URI).pathname;
const SECURE_COOKIE = APP_ORIGIN.startsWith("https:");

/* ── a tiny in-memory session store (use a real one in production) ── */
// A session exists only from /login on; anonymous visits create nothing.
// Sessions idle for 8 hours are dropped by a sweep every 10 minutes.
const SESSION_IDLE_MS = 8 * 60 * 60 * 1000;
// Over https the __Host- prefix pins the cookie to this exact origin.
const COOKIE = SECURE_COOKIE ? "__Host-sid" : "sid";
const COOKIE_ATTRS = `Path=/; HttpOnly; SameSite=Lax${SECURE_COOKIE ? "; Secure" : ""}`;
const sessions = new Map();
const randomId = () => crypto.randomBytes(32).toString("base64url");
const COOKIE_RE = new RegExp(`(?:^|;\\s*)${COOKIE}=([A-Za-z0-9_-]{43})(?:;|$)`);
/** The caller's session, or { sid: null, data: null }. */
function getSession(req) {
  const m = COOKIE_RE.exec(req.headers.cookie || "");
  const data = m ? sessions.get(m[1]) : undefined;
  if (!data) return { sid: null, data: null };
  data.lastSeen = Date.now();
  return { sid: m[1], data };
}
/** Start a new session under a fresh random id. */
function createSession(res, data = {}) {
  const sid = randomId();
  sessions.set(sid, { csrf: randomId(), ...data, lastSeen: Date.now() });
  res.setHeader("Set-Cookie", `${COOKIE}=${sid}; ${COOKIE_ATTRS}`);
  return sessions.get(sid);
}
function destroySession(sid, res) {
  if (sid) sessions.delete(sid);
  res.setHeader("Set-Cookie", `${COOKIE}=; ${COOKIE_ATTRS}; Max-Age=0`);
}
setInterval(() => {
  const cutoff = Date.now() - SESSION_IDLE_MS;
  for (const [sid, data] of sessions) if (data.lastSeen < cutoff) sessions.delete(sid);
}, 10 * 60 * 1000).unref();
/** Constant-time comparison of two strings (false when either is empty). */
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || !a || !b) return false;
  const x = crypto.createHash("sha256").update(a).digest();
  const y = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(x, y);
}

/* ── html ── */
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const page = (body) =>
  `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NobleID example</title></head><body style="font-family:system-ui;max-width:48rem;margin:2rem auto;padding:0 1rem">${body}</body></html>`;
function send(res, status, html) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; img-src https:; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
  });
  res.end(page(html));
}
const redirect = (res, location) => {
  res.writeHead(303, { Location: location, "Cache-Control": "no-store" });
  res.end();
};
const form = (action, label, csrf) => `<form method="post" action="${action}" style="display:inline"><input type="hidden" name="csrf" value="${esc(csrf)}"><button>${label}</button></form>`;
const errorPage = (res, e) =>
  send(res, 400, `<h1>Sign-in failed</h1><p id="error">${esc(e.code || "error")}${e.description ? ": " + esc(e.description) : ""}</p><p><a href="/">Back</a></p>`);

async function readForm(req) {
  let body = "";
  for await (const c of req) {
    body += c;
    if (body.length > 10_000) throw new Error("body too large");
  }
  return new URLSearchParams(body);
}

/* ── routes ── */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, APP_ORIGIN);
  const { sid, data: s } = getSession(req);
  try {
    if (req.method === "GET" && url.pathname === "/") {
      if (!s?.user) {
        return send(res, 200, `<h1>NobleID example (Node)</h1><p id="signed-out">You are signed out.</p><p><a href="/login">Sign in with NobleID</a></p>`);
      }
      return send(
        res,
        200,
        `<h1>Signed in</h1><p>Hello, ${esc(s.user.name || s.user.nobleid)}.</p>` +
          `<pre id="claims">${esc(JSON.stringify({ ...s.user, granted_scope: s.scope.join(" ") }, null, 2))}</pre>` +
          `<p><a href="/works">My works</a> ${s.tokens.refresh_token ? form("/refresh", "Refresh tokens", s.csrf) : ""} ${form("/logout", "Sign out", s.csrf)}</p>`
      );
    }

    if (req.method === "GET" && url.pathname === "/login") {
      const { url: authUrl, transaction } = await nobleid.startSignIn({ redirectUri: REDIRECT_URI, scope: SCOPE });
      (s || createSession(res)).transaction = transaction;
      return redirect(res, authUrl);
    }

    if (req.method === "GET" && url.pathname === CALLBACK_PATH) {
      const transaction = s?.transaction;
      if (s) delete s.transaction; // single use, whatever happens next
      const { tokens, claims, scope } = await nobleid.finishSignIn(url, transaction);
      const info = await nobleid.userinfo(tokens.access_token, claims.sub);
      // Key your account on `sub`. Only trust `email` for linking when email_verified is true.
      if (sid) sessions.delete(sid);
      createSession(res, { user: { ...claims, ...info }, tokens, scope }); // new session id after sign-in
      return redirect(res, "/");
    }

    if (req.method === "GET" && url.pathname === "/works") {
      if (!s?.user) return redirect(res, "/");
      if (!s.scope.includes("works")) return send(res, 200, `<p>The works scope was not granted.</p><p><a href="/">Back</a></p>`);
      const works = await nobleid.works(s.tokens.access_token, { limit: 50 });
      return send(res, 200, `<h1>Works</h1><pre id="works">${esc(JSON.stringify(works, null, 2))}</pre><p><a href="/">Back</a></p>`);
    }

    if (req.method === "POST" && (url.pathname === "/refresh" || url.pathname === "/logout")) {
      const f = await readForm(req);
      const origin = req.headers.origin;
      if (!s || (origin && origin !== APP_ORIGIN) || !safeEqual(f.get("csrf"), s.csrf)) return send(res, 403, `<p id="error">forbidden</p>`);

      if (url.pathname === "/refresh") {
        if (!s.tokens?.refresh_token) return redirect(res, "/");
        try {
          // Fails if the refreshed ID token is for a different user.
          const { claims: _claims, ...fresh } = await nobleid.refresh(s.tokens.refresh_token, { expectedSub: s.user.sub });
          s.tokens = { ...s.tokens, ...fresh };
        } catch (e) {
          // invalid_grant: the user removed the app, or the session ended. Any
          // other failure may come after the provider already rotated the
          // refresh token, so the one we hold could be spent. Either way, sign
          // out locally.
          destroySession(sid, res);
          if (e.code === "invalid_grant") return redirect(res, "/");
          throw e;
        }
        return redirect(res, "/");
      }

      // Logout: NobleID has no end-session endpoint. Revoke, then clear our session.
      if (s.tokens) {
        if (s.tokens.refresh_token) await nobleid.revoke(s.tokens.refresh_token, "refresh_token").catch(() => {});
        await nobleid.revoke(s.tokens.access_token, "access_token").catch(() => {});
      }
      destroySession(sid, res);
      return redirect(res, "/");
    }

    send(res, 404, `<p>Not found</p>`);
  } catch (e) {
    if (e instanceof NobleIdError) return errorPage(res, e);
    console.error("request failed:", e && e.name); // never log tokens or full errors that may hold them
    send(res, 500, `<p id="error">server_error</p>`);
  }
});

server.listen(PORT, "localhost", () => console.log(`example listening on ${APP_ORIGIN} (port ${PORT})`));
