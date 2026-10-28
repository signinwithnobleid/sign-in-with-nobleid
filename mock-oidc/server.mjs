#!/usr/bin/env node
/**
 * A local mock of the "Sign in with NobleID" OpenID Connect provider.
 *
 * For development and automated tests only. It mirrors the provider's public
 * protocol behaviour (endpoints, parameters, error shapes, token rules) so an
 * integration can be exercised end to end without real credentials. It is not
 * the provider's implementation and has no relationship to its internals.
 *
 * Zero dependencies: node:http and node:crypto only.
 *
 *   node mock-oidc/server.mjs --port 9400 --clients test/clients.json
 *
 * The issuer is http://localhost:<port>. As in production, the authorization
 * endpoint lives on a different host than the issuer: here it is
 * http://127.0.0.1:<port>/oauth/authorize.
 *
 * Endpoints under /__mock/ are test controls (see README.md). They exist only
 * in this mock.
 */
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

/* ───────────────────────── configuration ───────────────────────── */

const SCOPES = ["openid", "profile", "email", "orcid", "affiliations", "works", "offline_access"];
const PROMPTS = ["none", "login", "consent", "select_account"];

const DEFAULT_USER = Object.freeze({
  sub: "mock-user-sub-0001",
  nobleid: "NI0MOCKUSER0001",
  name: "Ada Example",
  given_name: "Ada",
  family_name: "Example",
  preferred_username: "ada.example",
  picture: "https://www.nobleid.org/brand/nobleid-mark.svg",
  website: "https://example.org/ada",
  research_interests: ["Bibliometrics", "Open science"],
  identity_verified: true,
  nobleid_verified_researcher: false,
  updated_at: 1767225600,
  email: "ada@example.com",
  email_verified: true,
  // ORCID's documented example iD (a fictional person). Present only because
  // the mock user "connected it through ORCID sign-in"; set to null to model a
  // user who has not.
  orcid: "https://orcid.org/0000-0002-1825-0097",
  affiliations: [{ organization: "Example University", role: "Researcher", start_year: 2021 }],
  // The profile-gate claims. NobleID signs an account in to apps only once its
  // profile is complete, so a sign-in always carries profile_complete: true;
  // "incomplete" can appear only in an ID token issued on refresh.
  profile_complete: true,
  verification_level: "authorship", // profile < orcid < authorship
  // Primary affiliation as entered; `ror` only when the person chose one.
  affiliation: { name: "Example University" },
  amr: ["pwd", "otp", "mfa"],
  // Only an authorship that NobleID verified counts.
  verified_authorship_count: 1,
  works: [
    {
      nobleid: "NI0MOCKWORK0001",
      ark: "ark:/48914/mock0work0001",
      title: "A mock paper about persistent identifiers",
      type: "article",
      doi: "10.5555/mock.0001",
      publication_date: "2025-03-14",
      publication_year: 2025,
      version: 1,
      registered_at: "2025-03-20T10:00:00Z",
    },
    {
      nobleid: "NI0MOCKWORK0002",
      ark: "ark:/48914/mock0work0002",
      title: "A second mock work (dataset)",
      type: "dataset",
      doi: null,
      publication_date: null,
      publication_year: 2026,
      version: 2,
      registered_at: "2026-01-05T08:30:00Z",
    },
  ],
});

const DEFAULTS = Object.freeze({
  codeTtl: 120,
  accessTokenTtl: 900,
  idTokenTtl: 600,
  refreshIdleTtl: 30 * 24 * 3600, // mock value only
  parTtl: 60,
});

/* ───────────────────────── small helpers ───────────────────────── */

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const rand = (n = 32) => b64url(crypto.randomBytes(n));
const now = () => Math.floor(Date.now() / 1000);
const sha256 = (s) => crypto.createHash("sha256").update(s).digest();

function safeEqual(a, b) {
  const ha = sha256(String(a));
  const hb = sha256(String(b));
  return crypto.timingSafeEqual(ha, hb) && String(a).length === String(b).length;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

/** Parse a query/form string; returns { params, repeated } without collapsing duplicates. */
function parseParams(str) {
  const sp = new URLSearchParams(str || "");
  const params = {};
  const repeated = [];
  for (const [k, v] of sp) {
    if (Object.prototype.hasOwnProperty.call(params, k)) repeated.push(k);
    else params[k] = v;
  }
  return { params, repeated };
}

function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error("body too large"));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function isLoopbackPeer(addr) {
  return /^(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1|::ffff:127\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.test(String(addr || ""));
}

// A browser page on another site can reach localhost (DNS rebinding, or a
// plain cross-site POST), and a tunnel or reverse proxy on this machine
// connects from 127.0.0.1. Neither is a client on this machine, so the Host
// header must name loopback and no forwarding header may be present.
const LOOPBACK_HOST = /^(localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[::1\])(:\d{1,5})?$/i;
const PROXY_HEADERS = ["forwarded", "x-forwarded-for", "x-forwarded-host", "x-real-ip", "cf-connecting-ip", "true-client-ip", "fly-client-ip", "x-client-ip"];
const LOOPBACK_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?$/i;

/** Why a request must be refused, or null. */
function refusal(req) {
  if (!isLoopbackPeer(req.socket.remoteAddress)) return "mock-oidc answers loopback clients only";
  if (!LOOPBACK_HOST.test(String(req.headers.host || ""))) return "mock-oidc answers requests addressed to localhost only";
  if (PROXY_HEADERS.some((h) => req.headers[h] !== undefined)) return "mock-oidc refuses requests that came through a proxy or tunnel";
  return null;
}

function isLoopbackHttp(u) {
  return u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
}

/** Exact redirect URI match; for http loopback URIs the port may vary (RFC 8252 §7.3). */
function redirectMatches(registered, presented) {
  if (registered === presented) return true;
  let r, p;
  try {
    r = new URL(registered);
    p = new URL(presented);
  } catch {
    return false;
  }
  if (!isLoopbackHttp(r) || !isLoopbackHttp(p)) return false;
  return r.hostname === p.hostname && r.pathname === p.pathname && r.search === p.search && !p.hash && !p.username && !p.password;
}

/* ───────────────────────── keys ───────────────────────── */

function newSigningKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  // RFC 7638 thumbprint: required members, lexicographic order, no whitespace.
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  const kid = b64url(sha256(canonical));
  return { privateKey, kid, publicJwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, kid, alg: "ES256", use: "sig" } };
}

function signJwt(key, payload) {
  const header = { alg: "ES256", typ: "JWT", kid: key.kid };
  const input = b64url(JSON.stringify(header)) + "." + b64url(JSON.stringify(payload));
  const sig = crypto.sign("sha256", Buffer.from(input), { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  return input + "." + b64url(sig);
}

/* ───────────────────────── the mock ───────────────────────── */

export function createMock(options = {}) {
  const clients = new Map();
  for (const c of options.clients || []) clients.set(c.client_id, c);

  const st = {
    keys: [newSigningKey()], // [0] signs; older keys stay published
    cfg: { ...DEFAULTS },
    user: { ...DEFAULT_USER },
    next: null, // one-shot override for the next authorize request
    rateLimit: { remaining: 0, retryAfter: 1 },
    codes: new Map(),
    access: new Map(),
    refresh: new Map(),
    families: new Map(),
    grants: new Map(), // `${client}|${sub}` -> Set(scopes)
    par: new Map(),
    lastAuthorize: null,
    lastToken: null,
  };

  let issuer = options.issuer || null;
  let authorizeOrigin = options.authorizeOrigin || null;

  const endpoints = () => ({
    authorization_endpoint: authorizeOrigin + "/oauth/authorize",
    token_endpoint: issuer + "/oauth/token",
    userinfo_endpoint: issuer + "/oauth/userinfo",
    revocation_endpoint: issuer + "/oauth/revoke",
    introspection_endpoint: issuer + "/oauth/introspect",
    pushed_authorization_request_endpoint: issuer + "/oauth/par",
    jwks_uri: issuer + "/.well-known/jwks.json",
  });

  function discovery() {
    return {
      issuer,
      ...endpoints(),
      scopes_supported: ["openid", "profile", "works", "orcid", "affiliations", "email", "offline_access"],
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["ES256"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
      revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
      introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
      prompt_values_supported: PROMPTS,
      claims_supported: [
        "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "amr", "nobleid", "nobleid_uri",
        "profile_complete", "verification_level", "affiliation", "name",
        "given_name", "family_name", "preferred_username", "profile", "picture", "website", "research_interests",
        "identity_verified", "nobleid_verified_researcher", "updated_at", "email", "email_verified", "orcid",
        "orcid_verified", "affiliations", "works_count", "works_endpoint", "verified_authorship_count",
      ],
      claims_parameter_supported: false,
      request_parameter_supported: false,
      request_uri_parameter_supported: false,
      require_pushed_authorization_requests: false,
      authorization_response_iss_parameter_supported: true,
    };
  }

  /* ── claims ── */

  function profileUrl(u) {
    return "https://www.nobleid.org/" + u.nobleid;
  }

  function baseClaims(u) {
    return { sub: u.sub, nobleid: u.nobleid, nobleid_uri: profileUrl(u) };
  }

  function scopedClaims(u, scopes, forUserinfo) {
    const c = baseClaims(u);
    if (scopes.has("profile")) {
      Object.assign(c, {
        name: u.name,
        given_name: u.given_name,
        family_name: u.family_name,
        preferred_username: u.preferred_username,
        profile: profileUrl(u),
        picture: u.picture,
        website: u.website,
        identity_verified: !!u.identity_verified,
        nobleid_verified_researcher: !!u.nobleid_verified_researcher,
        updated_at: u.updated_at,
      });
      if (forUserinfo) c.research_interests = u.research_interests || [];
      for (const k of Object.keys(c)) if (c[k] == null) delete c[k];
    }
    if (scopes.has("email") && u.email) {
      c.email = u.email;
      c.email_verified = !!u.email_verified;
    }
    if (scopes.has("orcid") && u.orcid) {
      c.orcid = u.orcid;
      c.orcid_verified = true;
    }
    // ID token and userinfo, as NobleID does.
    if (scopes.has("profile") && typeof u.profile_complete === "boolean") {
      c.profile_complete = u.profile_complete;
      if (u.verification_level) c.verification_level = u.verification_level;
    }
    if (scopes.has("affiliations") && u.affiliation && u.affiliation.name) {
      c.affiliation = { name: u.affiliation.name };
      if (u.affiliation.ror) c.affiliation.ror = u.affiliation.ror;
    }
    if (forUserinfo && scopes.has("affiliations")) c.affiliations = u.affiliations || [];
    if (forUserinfo && scopes.has("works")) {
      c.works_count = (u.works || []).length;
      c.works_endpoint = issuer + "/oauth/works";
      c.verified_authorship_count = u.verified_authorship_count || 0;
    }
    return c;
  }

  function mintIdToken(clientId, scopes, extra, overrides = {}) {
    const iat = now();
    const payload = {
      iss: issuer,
      aud: overrides.badAud ? "nbcl_someoneelse000000000000" : clientId,
      iat,
      exp: iat + st.cfg.idTokenTtl,
      ...scopedClaims(st.user, scopes, false),
      ...extra,
    };
    if (overrides.badNonce && payload.nonce) payload.nonce = "forged-" + payload.nonce;
    return signJwt(st.keys[0], payload);
  }

  /* ── responses ── */

  const CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Max-Age": "600",
  };

  function send(res, status, body, headers = {}) {
    const isJson = body !== null && typeof body === "object";
    const h = { "Cache-Control": "no-store", Pragma: "no-cache", ...headers };
    if (isJson) h["Content-Type"] = "application/json";
    res.writeHead(status, h);
    res.end(isJson ? JSON.stringify(body) : body || "");
  }

  const oauthError = (res, status, error, description, headers = {}) =>
    send(res, status, description ? { error, error_description: description } : { error }, { ...CORS, ...headers });

  const invalidClient = (res, usedBasic) =>
    oauthError(res, 401, "invalid_client", "Client authentication failed", usedBasic ? { "WWW-Authenticate": 'Basic realm="nobleid"' } : {});
  // Mixing Basic with body credentials is a malformed request (400), as on the provider.
  const authFailed = (res, auth) => (auth.twoMethods ? oauthError(res, 400, "invalid_request", auth.twoMethods) : invalidClient(res, auth.usedBasic));

  function errorPage(res, status, error, description) {
    send(
      res,
      status,
      `<!doctype html><meta charset="utf-8"><title>NobleID (mock) – error</title>` +
        `<h1>Sign-in request rejected</h1><p id="error" data-error="${escapeHtml(error)}">${escapeHtml(error)}: ${escapeHtml(description)}</p>`,
      { "Content-Type": "text/html; charset=utf-8" }
    );
  }

  /* ── client authentication (token, revoke, introspect, PAR) ── */

  function authenticateClient(req, params) {
    const auth = req.headers.authorization;
    const usedBasic = typeof auth === "string" && /^basic /i.test(auth);
    const bodySecret = Object.prototype.hasOwnProperty.call(params, "client_secret");
    if (usedBasic && bodySecret) return { error: true, usedBasic, twoMethods: "Use one client authentication method, not two" };
    if (usedBasic) {
      let decoded;
      try {
        decoded = Buffer.from(auth.slice(6).trim(), "base64").toString("utf8");
      } catch {
        return { error: true, usedBasic };
      }
      const i = decoded.indexOf(":");
      if (i < 0) return { error: true, usedBasic };
      let id, secret;
      try {
        // RFC 6749 §2.3.1: id and secret are form-urlencoded before base64.
        id = decodeURIComponent(decoded.slice(0, i).replace(/\+/g, " "));
        secret = decodeURIComponent(decoded.slice(i + 1).replace(/\+/g, " "));
      } catch {
        return { error: true, usedBasic };
      }
      if (params.client_id !== undefined && params.client_id !== id) return { error: true, usedBasic, twoMethods: "client_id in the body does not match Basic credentials" };
      const client = clients.get(id);
      if (!client || client.type !== "confidential" || !safeEqual(secret, client.client_secret)) return { error: true, usedBasic };
      return { client, method: "client_secret_basic" };
    }
    const client = clients.get(params.client_id);
    if (!client) return { error: true };
    if (client.type === "confidential") {
      if (!bodySecret || !safeEqual(params.client_secret, client.client_secret)) return { error: true };
      return { client, method: "client_secret_post" };
    }
    if (bodySecret) return { error: true };
    return { client, method: "none" };
  }

  async function readForm(req, res) {
    const ct = String(req.headers["content-type"] || "").toLowerCase();
    if (!ct.startsWith("application/x-www-form-urlencoded")) {
      oauthError(res, 400, "invalid_request", "Request body must be application/x-www-form-urlencoded");
      return null;
    }
    const raw = await readBody(req);
    const { params, repeated } = parseParams(raw);
    if (repeated.length) {
      oauthError(res, 400, "invalid_request", "Repeated parameter: " + repeated[0]);
      return null;
    }
    return params;
  }

  function rateLimited(res) {
    if (st.rateLimit.remaining > 0) {
      st.rateLimit.remaining--;
      oauthError(res, 429, "slow_down", null, { "Retry-After": String(st.rateLimit.retryAfter) });
      return true;
    }
    return false;
  }

  /* ── token bookkeeping ── */

  function issueAccessToken(clientId, sub, scopes, link) {
    const token = "nbat_" + rand(32);
    st.access.set(token, { clientId, sub, scopes, iat: now(), exp: now() + st.cfg.accessTokenTtl, revoked: false, ...link });
    return token;
  }

  function issueRefreshToken(familyId) {
    const fam = st.families.get(familyId);
    const token = "nbrt_" + rand(32);
    fam.generation++;
    st.refresh.set(token, { familyId, used: false, lastUsed: now(), iat: now() });
    fam.current = token;
    return token;
  }

  function revokeFamily(familyId) {
    const fam = st.families.get(familyId);
    if (!fam) return;
    fam.revoked = true;
    for (const at of st.access.values()) if (at.familyId === familyId) at.revoked = true;
  }

  function revokeCodeTokens(codeRec) {
    for (const t of codeRec.minted) {
      const at = st.access.get(t);
      if (at) at.revoked = true;
    }
    if (codeRec.familyId) revokeFamily(codeRec.familyId);
  }

  function liveAccess(token) {
    const at = st.access.get(token);
    if (!at || at.revoked || at.exp <= now()) return null;
    if (at.familyId && st.families.get(at.familyId)?.revoked) return null;
    return at;
  }

  function liveRefresh(token) {
    const rt = st.refresh.get(token);
    if (!rt) return null;
    const fam = st.families.get(rt.familyId);
    if (!fam || fam.revoked || rt.used || now() - rt.lastUsed > st.cfg.refreshIdleTtl) return null;
    return { rt, fam };
  }

  /* ── /oauth/authorize ── */

  function authorize(req, res, url) {
    // A repeated authorize parameter: the first value counts, as on the provider.
    const { params: q0 } = parseParams(url.search.slice(1));
    let q = q0;
    st.lastAuthorize = { ...q0 };

    // Pushed authorization request.
    if (q.request_uri) {
      const p = st.par.get(q.request_uri);
      st.par.delete(q.request_uri);
      if (!p || p.exp < now() || p.client_id !== q.client_id) {
        return errorPage(res, 400, "invalid_request", "Unknown or expired request_uri.");
      }
      q = { ...p.params, client_id: p.client_id };
      st.lastAuthorize = { ...q, request_uri: "(pushed)" };
    }

    // Errors before the client and exact redirect URI are matched are shown here, never redirected.
    const client = clients.get(q.client_id);
    if (!client) return errorPage(res, 400, "invalid_client", "Unknown client_id.");
    if (!q.redirect_uri || !(client.redirect_uris || []).some((r) => redirectMatches(r, q.redirect_uri))) {
      return errorPage(res, 400, "invalid_request", "redirect_uri is not registered for this application.");
    }

    const override = st.next || {};
    st.next = null;

    const redirect = (fields) => {
      const u = new URL(q.redirect_uri);
      for (const [k, v] of Object.entries(fields)) if (v !== undefined && v !== null) u.searchParams.append(k, v);
      if (q.state !== undefined) u.searchParams.append("state", q.state);
      if (!override.omitIss) u.searchParams.append("iss", override.badIss || issuer);
      send(res, 302, "", { Location: u.toString() });
    };
    const fail = (error, error_description) => redirect({ error, error_description });

    if (q.response_type !== "code") return fail("unsupported_response_type", "Only response_type=code is supported.");
    if (q.response_mode !== undefined && q.response_mode !== "query") return fail("invalid_request", "Only response_mode=query is supported.");
    if (q.request !== undefined) return fail("request_not_supported", "Request objects are not supported.");

    const requested = String(q.scope || "").split(" ").filter(Boolean);
    if (!requested.includes("openid")) return fail("invalid_scope", "The openid scope is required.");
    const unknown = requested.find((s) => !SCOPES.includes(s));
    if (unknown) return fail("invalid_scope", "Unknown scope: " + unknown);

    if (q.code_challenge_method !== undefined && q.code_challenge_method !== "S256") {
      return fail("invalid_request", "code_challenge_method must be S256.");
    }
    if (q.code_challenge !== undefined) {
      if (q.code_challenge_method !== "S256") return fail("invalid_request", "code_challenge_method must be S256.");
      if (!/^[A-Za-z0-9_-]{43}$/.test(q.code_challenge)) return fail("invalid_request", "Malformed code_challenge.");
    }
    if (client.type === "public" && !q.code_challenge) return fail("invalid_request", "PKCE (S256) is required for this client.");

    const prompts = String(q.prompt || "").split(" ").filter(Boolean);
    if (prompts.some((p) => !PROMPTS.includes(p))) return fail("invalid_request", "Unsupported prompt value.");
    if (prompts.includes("none") && prompts.length > 1) return fail("invalid_request", "prompt=none cannot be combined with other values.");
    if (q.max_age !== undefined && !/^\d+$/.test(q.max_age)) return fail("invalid_request", "max_age must be a non-negative integer.");

    if (override.error) return fail(override.error, override.error_description || "Mock error.");
    if (override.deny) return fail("access_denied", "The user declined the request.");

    const grantKey = client.client_id + "|" + st.user.sub;
    const existing = st.grants.get(grantKey);
    if (prompts.includes("none")) {
      if (override.loginRequired) return fail("login_required", "The user is not signed in to NobleID.");
      const covers = existing && requested.every((s) => existing.has(s));
      if (override.consentRequired || !covers) return fail("consent_required", "The user has not approved this application.");
    }

    // The user may untick any scope except openid.
    const untick = new Set((override.untick || []).filter((s) => s !== "openid"));
    const granted = new Set(requested.filter((s) => !untick.has(s)));
    st.grants.set(grantKey, new Set([...(existing || []), ...granted]));

    const code = "nbac_" + rand(32);
    st.codes.set(code, {
      clientId: client.client_id,
      redirectUri: q.redirect_uri,
      scopes: granted,
      nonce: q.nonce,
      challenge: q.code_challenge || null,
      authTime: now(),
      exp: now() + st.cfg.codeTtl,
      used: false,
      minted: [],
      familyId: null,
      overrides: { badNonce: !!override.badNonce, badAud: !!override.badAud },
    });
    redirect({ code });
  }

  /* ── /oauth/token ── */

  async function token(req, res) {
    if (rateLimited(res)) return;
    const params = await readForm(req, res);
    if (!params) return;
    const auth = authenticateClient(req, params);
    if (auth.error) return authFailed(res, auth);
    const client = auth.client;
    st.lastToken = { grant_type: params.grant_type, auth_method: auth.method, client_id: client.client_id, has_code_verifier: "code_verifier" in params };

    const tokenHeaders = CORS;

    if (params.grant_type === "authorization_code") {
      const rec = st.codes.get(params.code || "");
      if (!rec) return oauthError(res, 400, "invalid_grant", "Invalid authorization code.");
      if (rec.used) {
        revokeCodeTokens(rec);
        return oauthError(res, 400, "invalid_grant", "Authorization code already used.");
      }
      rec.used = true;
      if (rec.exp < now()) return oauthError(res, 400, "invalid_grant", "Authorization code expired.");
      if (rec.clientId !== client.client_id) return oauthError(res, 400, "invalid_grant", "Authorization code was issued to another client.");
      if (params.redirect_uri !== rec.redirectUri) return oauthError(res, 400, "invalid_grant", "redirect_uri does not match the authorization request.");
      if (rec.challenge) {
        const v = params.code_verifier;
        if (!v || !/^[A-Za-z0-9._~-]{43,128}$/.test(v) || !safeEqual(b64url(sha256(v)), rec.challenge)) {
          return oauthError(res, 400, "invalid_grant", "PKCE verification failed.");
        }
      } else if (params.code_verifier !== undefined) {
        return oauthError(res, 400, "invalid_grant", "code_verifier sent for a code issued without a code_challenge.");
      }

      const scopes = rec.scopes;
      let familyId = null;
      if (scopes.has("offline_access")) {
        familyId = rand(12);
        st.families.set(familyId, { clientId: client.client_id, sub: st.user.sub, scopes, generation: 0, revoked: false, current: null });
        rec.familyId = familyId;
      }
      const access_token = issueAccessToken(client.client_id, st.user.sub, scopes, { familyId, code: true });
      rec.minted.push(access_token);
      const extra = { auth_time: rec.authTime };
      if (rec.nonce !== undefined) extra.nonce = rec.nonce;
      if (st.user.amr && st.user.amr.length) extra.amr = st.user.amr;
      const body = {
        access_token,
        token_type: "Bearer",
        expires_in: st.cfg.accessTokenTtl,
        scope: [...scopes].join(" "),
        id_token: mintIdToken(client.client_id, scopes, extra, rec.overrides),
      };
      if (familyId) body.refresh_token = issueRefreshToken(familyId);
      return send(res, 200, body, tokenHeaders);
    }

    if (params.grant_type === "refresh_token") {
      const rt = st.refresh.get(params.refresh_token || "");
      if (!rt) return oauthError(res, 400, "invalid_grant", "Invalid refresh token.");
      const fam = st.families.get(rt.familyId);
      if (fam.clientId !== client.client_id) return oauthError(res, 400, "invalid_grant", "Refresh token was issued to another client.");
      if (rt.used) {
        // Reuse of a rotated token: assume theft, end the whole family.
        revokeFamily(rt.familyId);
        return oauthError(res, 400, "invalid_grant", "Refresh token already used.");
      }
      if (!liveRefresh(params.refresh_token)) return oauthError(res, 400, "invalid_grant", "Refresh token is no longer valid.");
      let scopes = fam.scopes;
      if (params.scope !== undefined) {
        const req2 = String(params.scope).split(" ").filter(Boolean);
        if (!req2.length || req2.some((s) => !fam.scopes.has(s))) return oauthError(res, 400, "invalid_scope", "Requested scope exceeds the original grant.");
        scopes = new Set(req2);
      }
      rt.used = true;
      const access_token = issueAccessToken(client.client_id, fam.sub, scopes, { familyId: rt.familyId });
      const body = {
        access_token,
        token_type: "Bearer",
        expires_in: st.cfg.accessTokenTtl,
        scope: [...scopes].join(" "),
        refresh_token: issueRefreshToken(rt.familyId),
      };
      // Refresh-issued ID tokens carry no auth_time, nonce or amr.
      if (scopes.has("openid")) body.id_token = mintIdToken(client.client_id, scopes, {});
      return send(res, 200, body, tokenHeaders);
    }

    return oauthError(res, 400, "unsupported_grant_type", "Supported: authorization_code, refresh_token.");
  }

  /* ── bearer-protected resources ── */

  async function bearer(req, res, url, { allowForm }) {
    const hdr = req.headers.authorization;
    const fromHeader = typeof hdr === "string" && /^bearer /i.test(hdr) ? hdr.slice(7).trim() : null;
    // As on the provider, a token in the query string is never read: it is
    // ignored, so a request that has no other token gets a bare 401.
    let fromForm = null;
    if (allowForm && req.method === "POST") {
      const ct = String(req.headers["content-type"] || "").toLowerCase();
      if (ct.startsWith("application/x-www-form-urlencoded")) {
        const { params, repeated } = parseParams(await readBody(req));
        if (repeated.length) {
          oauthError(res, 400, "invalid_request", "Repeated parameter.");
          return null;
        }
        fromForm = params.access_token ?? null;
      }
    }
    if (fromHeader && fromForm) {
      oauthError(res, 400, "invalid_request", "Send the access token once.");
      return null;
    }
    const tok = fromHeader || fromForm;
    if (!tok) {
      send(res, 401, "", { ...CORS, "WWW-Authenticate": 'Bearer realm="nobleid"' });
      return null;
    }
    const at = liveAccess(tok);
    if (!at) {
      send(res, 401, { error: "invalid_token" }, { ...CORS, "WWW-Authenticate": 'Bearer realm="nobleid", error="invalid_token"' });
      return null;
    }
    return at;
  }

  const insufficientScope = (res) =>
    send(res, 403, { error: "insufficient_scope" }, { ...CORS, "WWW-Authenticate": 'Bearer realm="nobleid", error="insufficient_scope"' });

  async function userinfo(req, res, url) {
    if (rateLimited(res)) return;
    const at = await bearer(req, res, url, { allowForm: true });
    if (!at) return;
    if (!at.scopes.has("openid")) return insufficientScope(res);
    send(res, 200, scopedClaims(st.user, at.scopes, true), CORS);
  }

  async function works(req, res, url) {
    if (rateLimited(res)) return;
    const at = await bearer(req, res, url, { allowForm: false });
    if (!at) return;
    if (!at.scopes.has("works")) return insufficientScope(res);
    const limitS = url.searchParams.get("limit");
    const offsetS = url.searchParams.get("offset");
    const limit = limitS === null ? 50 : /^\d+$/.test(limitS) ? Number(limitS) : NaN;
    const offset = offsetS === null ? 0 : /^\d+$/.test(offsetS) ? Number(offsetS) : NaN;
    if (!(limit >= 1 && limit <= 100) || !(offset >= 0)) return oauthError(res, 400, "invalid_request", "limit must be 1..100 and offset >= 0.");
    const all = (st.user.works || []).map((w) => ({
      nobleid: w.nobleid,
      ark: w.ark,
      url: "https://nobleid.org/" + w.ark,
      title: w.title,
      type: w.type,
      doi: w.doi,
      publication_date: w.publication_date,
      publication_year: w.publication_year,
      version: w.version,
      registered_at: w.registered_at,
    }));
    send(res, 200, { sub: st.user.sub, total: all.length, limit, offset, works: all.slice(offset, offset + limit) }, CORS);
  }

  /* ── revoke / introspect / PAR ── */

  async function revoke(req, res) {
    if (rateLimited(res)) return;
    const params = await readForm(req, res);
    if (!params) return;
    const auth = authenticateClient(req, params);
    if (auth.error) return authFailed(res, auth);
    if (!params.token) return oauthError(res, 400, "invalid_request", "token is required.");
    const cid = auth.client.client_id;
    const rt = st.refresh.get(params.token);
    if (rt && st.families.get(rt.familyId)?.clientId === cid) revokeFamily(rt.familyId);
    const at = st.access.get(params.token);
    if (at && at.clientId === cid) at.revoked = true;
    send(res, 200, {}, CORS);
  }

  async function introspect(req, res) {
    if (rateLimited(res)) return;
    const params = await readForm(req, res);
    if (!params) return;
    const auth = authenticateClient(req, params);
    if (auth.error) return authFailed(res, auth);
    if (auth.client.type !== "confidential") return invalidClient(res, auth.usedBasic);
    const cid = auth.client.client_id;
    const at = liveAccess(params.token || "");
    if (at && at.clientId === cid) {
      return send(res, 200, { active: true, token_type: "Bearer", scope: [...at.scopes].join(" "), client_id: cid, sub: at.sub, iat: at.iat, exp: at.exp, iss: issuer }, CORS);
    }
    const live = liveRefresh(params.token || "");
    if (live && live.fam.clientId === cid) {
      return send(res, 200, { active: true, token_type: "refresh_token", scope: [...live.fam.scopes].join(" "), client_id: cid, sub: live.fam.sub, iss: issuer }, CORS);
    }
    send(res, 200, { active: false }, CORS);
  }

  async function par(req, res) {
    if (rateLimited(res)) return;
    const params = await readForm(req, res);
    if (!params) return;
    const auth = authenticateClient(req, params);
    if (auth.error) return authFailed(res, auth);
    if (params.request_uri) return oauthError(res, 400, "invalid_request", "request_uri is not allowed here.");
    const client = auth.client;
    if (!params.redirect_uri || !(client.redirect_uris || []).some((r) => redirectMatches(r, params.redirect_uri))) {
      return oauthError(res, 400, "invalid_request", "redirect_uri is not registered for this application.");
    }
    const p = { ...params };
    delete p.client_secret;
    const request_uri = "urn:ietf:params:oauth:request_uri:" + rand(24);
    st.par.set(request_uri, { client_id: client.client_id, params: p, exp: now() + st.cfg.parTtl });
    send(res, 201, { request_uri, expires_in: st.cfg.parTtl }, CORS);
  }

  /* ── test controls ── */

  function stateSnapshot() {
    const out = {};
    for (const id of clients.keys()) out[id] = { liveAccessTokens: 0, liveRefreshTokens: 0, families: [] };
    for (const [t, at] of st.access) if (liveAccess(t)) out[at.clientId].liveAccessTokens++;
    for (const [fid, fam] of st.families) {
      const live = fam.current && liveRefresh(fam.current) ? 1 : 0;
      out[fam.clientId].liveRefreshTokens += live;
      out[fam.clientId].families.push({ id: fid, generation: fam.generation, revoked: fam.revoked, scope: [...fam.scopes].join(" ") });
    }
    return { clients: out, lastAuthorize: st.lastAuthorize, lastToken: st.lastToken, keys: st.keys.map((k) => k.kid) };
  }

  async function control(req, res, url) {
    // Test controls are for the test runner, never for a web page.
    const origin = req.headers.origin;
    if (origin !== undefined && !LOOPBACK_ORIGIN.test(origin)) return send(res, 403, { error: "forbidden" });
    const body = req.method === "POST" ? await readBody(req) : "";
    let data = {};
    if (body) {
      try {
        data = JSON.parse(body);
      } catch {
        return send(res, 400, { error: "bad json" });
      }
    }
    switch (url.pathname) {
      case "/__mock/state":
        return send(res, 200, stateSnapshot());
      case "/__mock/reset":
        st.codes.clear();
        st.access.clear();
        st.refresh.clear();
        st.families.clear();
        st.grants.clear();
        st.par.clear();
        st.next = null;
        st.cfg = { ...DEFAULTS };
        st.user = { ...DEFAULT_USER };
        st.rateLimit = { remaining: 0, retryAfter: 1 };
        st.lastAuthorize = null;
        st.lastToken = null;
        return send(res, 200, { ok: true });
      case "/__mock/next-authorize":
        st.next = data;
        return send(res, 200, { ok: true });
      case "/__mock/config":
        Object.assign(st.cfg, data.cfg || {});
        if (data.user) st.user = { ...st.user, ...data.user };
        return send(res, 200, { ok: true });
      case "/__mock/rate-limit":
        st.rateLimit = { remaining: data.count || 1, retryAfter: data.retryAfter || 1 };
        return send(res, 200, { ok: true });
      case "/__mock/rotate-key":
        st.keys.unshift(newSigningKey());
        return send(res, 200, { kid: st.keys[0].kid });
      case "/__mock/expire-codes":
        for (const c of st.codes.values()) c.exp = now() - 1;
        return send(res, 200, { ok: true });
      default:
        return send(res, 404, { error: "not_found" });
    }
  }

  /* ── router ── */

  async function handle(req, res) {
    const url = new URL(req.url, issuer);
    const path = url.pathname;
    try {
      if (req.method === "OPTIONS" && (path.startsWith("/oauth/") || path.startsWith("/.well-known/")) && path !== "/oauth/authorize") {
        return send(res, 204, "", CORS);
      }
      if (path === "/.well-known/openid-configuration" || path === "/.well-known/oauth-authorization-server") {
        return send(res, 200, discovery(), { ...CORS, "Cache-Control": "public, max-age=300" });
      }
      if (path === "/.well-known/jwks.json") {
        return send(res, 200, { keys: st.keys.map((k) => k.publicJwk) }, { ...CORS, "Cache-Control": "public, max-age=300" });
      }
      if (path === "/oauth/authorize" && req.method === "GET") return authorize(req, res, url);
      if (path === "/oauth/token" && req.method === "POST") return await token(req, res);
      if (path === "/oauth/userinfo" && (req.method === "GET" || req.method === "POST")) return await userinfo(req, res, url);
      if (path === "/oauth/works" && req.method === "GET") return await works(req, res, url);
      if (path === "/oauth/revoke" && req.method === "POST") return await revoke(req, res);
      if (path === "/oauth/introspect" && req.method === "POST") return await introspect(req, res);
      if (path === "/oauth/par" && req.method === "POST") return await par(req, res);
      if (path.startsWith("/__mock/")) return await control(req, res, url);
      if (path.startsWith("/oauth/")) return send(res, 405, { error: "invalid_request", error_description: "Method not allowed." }, CORS);
      return send(res, 404, { error: "not_found" });
    } catch (e) {
      if (!res.headersSent) send(res, 500, { error: "server_error" });
      if (options.verbose) console.error(e);
    }
  }

  const server = http.createServer((req, res) => {
    // A test double that signs anyone in: answer this machine only, whatever
    // address the server ended up bound to.
    const why = refusal(req);
    if (why) {
      res.writeHead(403, { "Content-Type": "text/plain", Connection: "close" });
      return res.end(why + "\n");
    }
    if (options.verbose) console.log(req.method, req.url.split("?")[0]);
    handle(req, res);
  });

  return {
    server,
    get issuer() {
      return issuer;
    },
    async listen(port = 0, host) {
      await new Promise((r) => server.listen(port, host, r));
      const p = server.address().port;
      issuer = issuer || `http://localhost:${p}`;
      authorizeOrigin = authorizeOrigin || `http://127.0.0.1:${p}`;
      return p;
    },
    close: () => new Promise((r) => server.close(r)),
  };
}

/* ───────────────────────── CLI ───────────────────────── */

function arg(name, fallback) {
  const i = process.argv.indexOf("--" + name);
  return i > 0 ? process.argv[i + 1] : fallback;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  const clientsPath = arg("clients", process.env.MOCK_CLIENTS);
  if (!clientsPath) {
    console.error("usage: node server.mjs --port <port> --clients <clients.json>");
    process.exit(2);
  }
  const clients = JSON.parse(fs.readFileSync(clientsPath, "utf8")).clients;
  const mock = createMock({ clients, verbose: process.argv.includes("--verbose") });
  const port = await mock.listen(Number(arg("port", process.env.MOCK_PORT || 9400)));
  console.log(`mock-oidc listening: issuer ${mock.issuer} (port ${port})`);
  console.warn("mock-oidc is a TEST DOUBLE: it signs anyone in as a fixed test user without a password.");
  console.warn("It answers this machine only. Never expose it through a proxy, tunnel or port forward.");
  for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => mock.close().then(() => process.exit(0)));
}
