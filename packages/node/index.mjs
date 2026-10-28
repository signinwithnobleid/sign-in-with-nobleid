/**
 * nobleid-signin: a thin server-side helper for "Sign in with NobleID".
 *
 * It wraps openid-client (v6) with NobleID's settings already chosen:
 * discovery, ES256 ID tokens verified against the JWKS, PKCE S256, state,
 * nonce and the RFC 9207 `iss` check on every callback, refresh-token
 * rotation that never runs two refreshes of the same token at once, and
 * revocation. It does no cryptography of its own.
 *
 * Keep tokens on your server. Store the object returned by startSignIn() in
 * your server-side session and pass it back to finishSignIn().
 */
import crypto from "node:crypto";
import * as oidc from "openid-client";

export const NOBLEID_ISSUER = "https://id.nobleid.org";
export const DEFAULT_SCOPE = "openid profile email";
const MAX_FLOW_AGE_MS = 10 * 60 * 1000;

/** An error with an OAuth error code (`code`), safe to show to developers. Never contains tokens. */
export class NobleIdError extends Error {
  constructor(code, description, extra = {}) {
    super(description ? `${code}: ${description}` : code);
    this.name = "NobleIdError";
    this.code = code;
    this.description = description || "";
    if (extra.status) this.status = extra.status;
    if (extra.retryAfter !== undefined) this.retryAfter = extra.retryAfter;
  }
}

/* ── profile filling ─────────────────────────────────────────────────── */

const ORCID_URI = /^https:\/\/orcid\.org\/\d{4}-\d{4}-\d{4}-\d{3}[\dX]$/;
const ROR_URI = /^https:\/\/ror\.org\/0[a-hj-km-np-tv-z0-9]{6}\d{2}$/;

function text(v) {
  return typeof v === "string" && v.trim() ? v.trim() : null;
}

function urlWith(v, schemes) {
  const t = text(v);
  if (!t) return null;
  try {
    const u = new URL(t);
    return schemes.includes(u.protocol) && u.hostname ? t : null;
  } catch {
    return null;
  }
}

function year(v) {
  if (Number.isInteger(v) && v >= 1000 && v <= 9999) return v;
  // Servers before 27 Oct 2026 sent start_year as a string.
  if (typeof v === "string" && /^\d{4}$/.test(v.trim())) return Number(v.trim());
  return null;
}

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * A plain profile from the verified ID token claims and, if you called it,
 * the userinfo response (same `sub`, or this throws `invalid_token`).
 * Userinfo wins where both carry a claim: it is fresher and has more.
 *
 * Every field is always present: `null` (or `[]`, or `false`) when the
 * person did not share it or NobleID does not know it. `orcid` is set only
 * when NobleID marked it proven; `picture` only when https; `website` and
 * `profileUrl` only when http(s). Affiliations are what the person entered,
 * not checked by NobleID. Fill only empty fields with it: see
 * docs/profile-data.md.
 */
export function profileFromClaims(idTokenClaims, userinfo) {
  const id = isObject(idTokenClaims) ? idTokenClaims : {};
  const sub = text(id.sub);
  if (!sub) throw new NobleIdError("invalid_token", "the ID token has no sub");
  const ui = isObject(userinfo) ? userinfo : {};
  if (ui.sub !== undefined && ui.sub !== sub) throw new NobleIdError("invalid_token", "userinfo is for another subject");
  const c = { ...id, ...ui, sub };

  const seen = new Set();
  const researchInterests = (Array.isArray(c.research_interests) ? c.research_interests : [])
    .map(text)
    .filter((x) => x && !seen.has(x.toLowerCase()) && seen.add(x.toLowerCase()));
  const main = isObject(c.affiliation) && text(c.affiliation.name)
    ? { name: text(c.affiliation.name), ror: ROR_URI.test(text(c.affiliation.ror) || "") ? text(c.affiliation.ror) : null }
    : null;
  const affiliations = (Array.isArray(c.affiliations) ? c.affiliations : [])
    .filter((a) => isObject(a) && text(a.organization))
    .map((a) => ({
      organization: text(a.organization),
      role: text(a.role),
      startYear: year(a.start_year),
      ror: ROR_URI.test(text(a.ror) || "") ? text(a.ror) : null,
    }));
  const email = text(c.email);
  const orcid = c.orcid_verified === true && ORCID_URI.test(text(c.orcid) || "") ? text(c.orcid) : null;

  return {
    sub,
    nobleid: text(c.nobleid),
    nobleidUri: urlWith(c.nobleid_uri, ["https:"]),
    name: text(c.name),
    givenName: text(c.given_name),
    familyName: text(c.family_name),
    username: text(c.preferred_username),
    picture: urlWith(c.picture, ["https:"]),
    website: urlWith(c.website, ["https:", "http:"]),
    profileUrl: urlWith(c.profile, ["https:"]),
    researchInterests,
    email,
    emailVerified: email !== null && c.email_verified === true,
    orcid,
    affiliation: main,
    affiliations,
    identityVerified: c.identity_verified === true,
    verifiedResearcher: c.nobleid_verified_researcher === true,
    updatedAt: Number.isInteger(c.updated_at) ? c.updated_at : null,
  };
}

function sameString(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ha = crypto.createHash("sha256").update(a).digest();
  const hb = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(ha, hb) && a.length === b.length;
}

function isLocalHttp(u) {
  return u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
}

function retryAfterOf(err) {
  const v = err?.response?.headers?.get?.("retry-after");
  if (!v) return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : v;
}

/** Turn openid-client / network errors into NobleIdError without leaking token values. */
function wrap(err) {
  if (err instanceof NobleIdError) return err;
  if (err && typeof err.error === "string") {
    return new NobleIdError(err.error, err.error_description, { status: err.status, retryAfter: retryAfterOf(err) });
  }
  if (err && err.cause && typeof err.cause.error === "string") {
    return new NobleIdError(err.cause.error, err.cause.error_description, { status: err.cause.status });
  }
  return new NobleIdError("server_error", err && err.code ? String(err.code) : "request failed");
}

/**
 * Discover the provider and create a client.
 *
 * @param {object} o
 * @param {string} o.clientId           Your client id (nbcl_...).
 * @param {string} [o.clientSecret]     Confidential clients only. Read it from the environment.
 * @param {string} [o.issuer]           Defaults to https://id.nobleid.org.
 * @param {"client_secret_basic"|"client_secret_post"|"none"} [o.clientAuth]
 * @param {boolean} [o.allowInsecureLocalhost] Allow an http://localhost issuer (local mock only).
 */
export async function createNobleIdClient(o) {
  if (!o || !o.clientId) throw new NobleIdError("invalid_request", "clientId is required");
  const issuer = new URL(o.issuer || NOBLEID_ISSUER);
  const insecure = issuer.protocol !== "https:";
  if (insecure && !(o.allowInsecureLocalhost && isLocalHttp(issuer))) {
    throw new NobleIdError("invalid_request", "the issuer must be https (http is allowed only for a localhost mock)");
  }
  const method = o.clientAuth || (o.clientSecret ? "client_secret_basic" : "none");
  if (method !== "none" && !o.clientSecret) throw new NobleIdError("invalid_request", "clientSecret is required for " + method);
  if (method === "none" && o.clientSecret) throw new NobleIdError("invalid_request", "public clients have no secret");
  const auth =
    method === "client_secret_basic"
      ? oidc.ClientSecretBasic(o.clientSecret)
      : method === "client_secret_post"
        ? oidc.ClientSecretPost(o.clientSecret)
        : oidc.None();

  let config;
  try {
    config = await oidc.discovery(
      issuer,
      o.clientId,
      { id_token_signed_response_alg: "ES256" }, // NobleID signs ID tokens with ES256 only
      auth,
      insecure ? { execute: [oidc.allowInsecureRequests] } : undefined
    );
  } catch (e) {
    throw wrap(e);
  }
  // Verify the ID token signature against the provider's JWKS (fetched again on an unknown kid).
  oidc.enableNonRepudiationChecks(config);
  return new NobleIdClient(config, method === "none");
}

export class NobleIdClient {
  constructor(config, isPublic) {
    this.config = config;
    this.isPublic = isPublic;
    this.issuer = config.serverMetadata().issuer;
    this._refreshing = new Map();
  }

  /**
   * Build the authorization URL. Returns { url, transaction }; keep `transaction`
   * in the server-side session (never in a URL) until the callback.
   */
  async startSignIn({ redirectUri, scope = DEFAULT_SCOPE, prompt, maxAge, loginHint } = {}) {
    if (!redirectUri) throw new NobleIdError("invalid_request", "redirectUri is required");
    if (!scope.split(" ").includes("openid")) scope = "openid " + scope;
    const codeVerifier = oidc.randomPKCECodeVerifier();
    const transaction = {
      state: oidc.randomState(),
      nonce: oidc.randomNonce(),
      codeVerifier,
      redirectUri,
      maxAge: maxAge ?? null,
      createdAt: Date.now(),
    };
    const params = {
      redirect_uri: redirectUri,
      scope,
      state: transaction.state,
      nonce: transaction.nonce,
      code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier),
      code_challenge_method: "S256",
    };
    if (prompt) params.prompt = prompt;
    if (maxAge != null) params.max_age = String(maxAge);
    if (loginHint) params.login_hint = loginHint;
    return { url: oidc.buildAuthorizationUrl(this.config, params).href, transaction };
  }

  /**
   * Complete sign-in on the redirect URI.
   *
   * Checks, in order: a sign-in is in progress, `state` matches, `iss` is the
   * issuer, then surfaces any `error`, then exchanges the code (PKCE) and
   * verifies the ID token (ES256 signature via JWKS, iss, aud, exp, nonce).
   *
   * @param {string|URL} callbackUrl  The full URL the browser was redirected to.
   * @param {object} transaction      What startSignIn() returned; use it once.
   * @returns {Promise<{tokens: object, claims: object, scope: string[]}>}
   */
  async finishSignIn(callbackUrl, transaction) {
    const current = new URL(callbackUrl);
    const q = current.searchParams;
    if (!transaction || !transaction.state) throw new NobleIdError("invalid_state", "no sign-in in progress");
    if (!sameString(q.get("state"), transaction.state)) throw new NobleIdError("invalid_state", "state does not match");
    if (q.get("iss") !== this.issuer) throw new NobleIdError("invalid_issuer", "the response did not come from the expected issuer");
    if (q.get("error")) throw new NobleIdError(q.get("error"), q.get("error_description") || "");
    if (!q.get("code")) throw new NobleIdError("invalid_request", "no authorization code");
    const age = Date.now() - transaction.createdAt;
    // A missing or non-numeric createdAt fails closed (NaN would otherwise pass).
    if (typeof transaction.createdAt !== "number" || !Number.isFinite(age) || age > MAX_FLOW_AGE_MS) throw new NobleIdError("expired", "sign-in took too long; start again");

    // openid-client derives redirect_uri from the URL it is given, so rebuild it on the registered URI.
    const url = new URL(transaction.redirectUri);
    for (const [k, v] of q) url.searchParams.append(k, v);
    let tokens;
    try {
      tokens = await oidc.authorizationCodeGrant(this.config, url, {
        pkceCodeVerifier: transaction.codeVerifier,
        expectedState: transaction.state,
        expectedNonce: transaction.nonce,
        idTokenExpected: true,
        maxAge: transaction.maxAge ?? undefined,
      });
    } catch (e) {
      throw wrap(e);
    }
    return { tokens: toTokenSet(tokens), claims: tokens.claims(), scope: String(tokens.scope || "").split(" ").filter(Boolean) };
  }

  /** Read claims from the userinfo endpoint. `expectedSub` must be the ID token's sub. */
  async userinfo(accessToken, expectedSub) {
    try {
      return await oidc.fetchUserInfo(this.config, accessToken, expectedSub);
    } catch (e) {
      throw wrap(e);
    }
  }

  /** List the user's registered works (needs the `works` scope). */
  async works(accessToken, { limit = 50, offset = 0 } = {}) {
    const url = new URL(this.issuer + "/oauth/works");
    url.searchParams.set("limit", String(limit));
    url.searchParams.set("offset", String(offset));
    let res;
    try {
      res = await oidc.fetchProtectedResource(this.config, accessToken, url, "GET");
    } catch (e) {
      throw wrap(e);
    }
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      const ra = res.headers.get("retry-after");
      throw new NobleIdError(body.error || "http_" + res.status, body.error_description, { status: res.status, retryAfter: ra ? Number(ra) : undefined });
    }
    return body;
  }

  /**
   * Use a refresh token. NobleID rotates refresh tokens: store the new one and
   * discard the old one. Presenting a used refresh token again ends the whole
   * session, so concurrent calls with the same token share one request here
   * (only while it is in flight; nothing is remembered afterwards).
   * Across processes, serialise refreshes yourself (e.g. a per-session lock).
   * On `invalid_grant`, sign the user out.
   *
   * A refresh-issued ID token is verified by openid-client (ES256 via JWKS,
   * iss, aud, exp). Pass the `sub` you stored at sign-in as `expectedSub`: it
   * is checked for each caller, and a different `sub` is rejected.
   */
  async refresh(refreshToken, { scope, expectedSub } = {}) {
    const key = crypto.createHash("sha256").update(String(refreshToken)).digest("hex");
    let shared = this._refreshing.get(key);
    if (!shared) {
      shared = (async () => {
        try {
          return await oidc.refreshTokenGrant(this.config, refreshToken, scope ? { scope } : undefined);
        } catch (e) {
          throw wrap(e);
        } finally {
          this._refreshing.delete(key);
        }
      })();
      this._refreshing.set(key, shared);
    }
    const t = await shared;
    const out = toTokenSet(t);
    const claims = t.id_token ? t.claims() : undefined;
    if (t.id_token && (!claims || typeof claims.sub !== "string" || !claims.sub)) {
      throw new NobleIdError("invalid_id_token", "the refreshed ID token has no sub");
    }
    if (claims && expectedSub !== undefined && !sameString(claims.sub, String(expectedSub))) {
      throw new NobleIdError("invalid_id_token", "the refreshed ID token is for another subject");
    }
    if (claims) out.claims = claims;
    return out;
  }

  /** Revoke a token (RFC 7009). Revoking a refresh token also ends the access tokens minted from it. */
  async revoke(token, tokenTypeHint) {
    try {
      await oidc.tokenRevocation(this.config, token, tokenTypeHint ? { token_type_hint: tokenTypeHint } : undefined);
    } catch (e) {
      throw wrap(e);
    }
  }

  /** Introspect a token (RFC 7662). Confidential clients only. */
  async introspect(token) {
    if (this.isPublic) throw new NobleIdError("invalid_client", "introspection is for confidential clients");
    try {
      return await oidc.tokenIntrospection(this.config, token);
    } catch (e) {
      throw wrap(e);
    }
  }
}

function toTokenSet(t) {
  const expiresIn = typeof t.expires_in === "number" ? t.expires_in : Number(t.expires_in || 0);
  return {
    access_token: t.access_token,
    refresh_token: t.refresh_token,
    id_token: t.id_token,
    token_type: t.token_type,
    scope: t.scope,
    // Read expires_in from every response; do not hardcode a lifetime.
    expires_at: Math.floor(Date.now() / 1000) + expiresIn,
  };
}
