/**
 * Server-only helpers for talking to NobleID directly: discovery, ID token
 * verification (ES256 via JWKS), userinfo, works, refresh and revocation.
 * Auth.js handles the sign-in redirect and the code exchange; these cover
 * what it does not.
 */
import crypto from "node:crypto";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

export const ISSUER = process.env.ISSUER ?? "https://id.nobleid.org";
export const CLIENT_ID = process.env.CLIENT_ID ?? "";
export const CLIENT_SECRET = process.env.CLIENT_SECRET ?? "";
export const SCOPE = process.env.SCOPE ?? "openid profile email orcid affiliations works offline_access";

// NobleID is https only. Plain http is accepted for a loopback issuer (the
// local mock) and nothing else. Auth.js itself does not enforce https.
{
  const u = new URL(ISSUER);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) {
    throw new Error("ISSUER must be an https URL");
  }
}

// AUTH_SECRET encrypts the session cookie: anyone who knows it can forge a
// session for any person. Refuse a short or placeholder value.
{
  const s = process.env.AUTH_SECRET;
  if (s !== undefined && s !== "" && (s.length < 32 || /^(replace|generate|change|your)[-_ ]/i.test(s))) {
    throw new Error("AUTH_SECRET is too short or a placeholder: generate one with `npx auth secret`");
  }
}

/** What this app keeps in the encrypted Auth.js session cookie. */
export type NobleToken = {
  sub: string;
  claims: Record<string, unknown>; // ID token claims merged with userinfo
  scope: string[]; // granted scope, from the token response
  access_token: string;
  expires_at: number; // seconds since epoch, from expires_in
  refresh_token?: string; // only when offline_access was granted
  csrf: string; // per-session token for this app's own POST forms
  refresh_error?: string;
};

export class NobleIdError extends Error {
  constructor(
    public code: string,
    public status?: number,
    public retryAfter?: number,
  ) {
    super(code);
  }
}

/* ── discovery and keys ── */

type Discovery = {
  issuer: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  revocation_endpoint: string;
  jwks_uri: string;
};

let discovery: { at: number; doc: Promise<Discovery> } | null = null;

export function getDiscovery(): Promise<Discovery> {
  if (!discovery || Date.now() - discovery.at > 3600_000) {
    const doc = (async () => {
      const res = await fetch(ISSUER + "/.well-known/openid-configuration", { cache: "no-store" });
      if (!res.ok) throw new NobleIdError("discovery_failed", res.status);
      const d = (await res.json()) as Discovery;
      if (d.issuer !== ISSUER) throw new NobleIdError("issuer_mismatch");
      return d;
    })();
    discovery = { at: Date.now(), doc };
    doc.catch(() => (discovery = null)); // retry next time
  }
  return discovery.doc;
}

let jwks: { uri: string; set: ReturnType<typeof createRemoteJWKSet> } | null = null;

/**
 * Verify an ID token's signature (ES256, key from the published JWKS; an
 * unknown kid triggers a re-fetch), iss, aud and exp. The nonce of a sign-in
 * ID token is checked by Auth.js; refresh-issued ID tokens carry no nonce.
 */
export async function verifyIdToken(idToken: string): Promise<JWTPayload & { sub: string }> {
  const { jwks_uri } = await getDiscovery();
  if (!jwks || jwks.uri !== jwks_uri) {
    // Keys are cached; an unknown kid (key rotation) re-fetches the set at once.
    // No cooldown is needed: ID tokens only arrive from the token endpoint.
    jwks = { uri: jwks_uri, set: createRemoteJWKSet(new URL(jwks_uri), { cooldownDuration: 0 }) };
  }
  const { payload } = await jwtVerify(idToken, jwks.set, {
    algorithms: ["ES256"],
    issuer: ISSUER,
    audience: CLIENT_ID,
    requiredClaims: ["sub", "exp", "iat"],
  });
  if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== CLIENT_ID) {
    throw new NobleIdError("invalid_azp");
  }
  return payload as JWTPayload & { sub: string };
}

/* ── client authentication: client_secret_basic (RFC 6749 §2.3.1) ── */

const form = (s: string) => encodeURIComponent(s).replace(/%20/g, "+");
const basicAuth = () => "Basic " + Buffer.from(form(CLIENT_ID) + ":" + form(CLIENT_SECRET)).toString("base64");

async function failure(res: Response): Promise<NobleIdError> {
  const body = (await res.json().catch(() => ({}))) as { error?: string };
  const ra = Number(res.headers.get("retry-after"));
  return new NobleIdError(typeof body.error === "string" ? body.error : "http_" + res.status, res.status, Number.isFinite(ra) && ra > 0 ? ra : undefined);
}

/* ── resources ── */

export async function fetchUserinfo(accessToken: string, expectedSub: string): Promise<Record<string, unknown>> {
  const { userinfo_endpoint } = await getDiscovery();
  const res = await fetch(userinfo_endpoint, { headers: { Authorization: "Bearer " + accessToken, Accept: "application/json" }, cache: "no-store" });
  if (!res.ok) throw await failure(res);
  const info = (await res.json()) as Record<string, unknown>;
  if (info.sub !== expectedSub) throw new NobleIdError("userinfo_sub_mismatch"); // OIDC Core 5.3.2
  return info;
}

export async function fetchWorks(accessToken: string, { limit = 50, offset = 0 } = {}): Promise<unknown> {
  const url = new URL(ISSUER + "/oauth/works");
  url.searchParams.set("limit", String(limit));
  url.searchParams.set("offset", String(offset));
  const res = await fetch(url, { headers: { Authorization: "Bearer " + accessToken, Accept: "application/json" }, cache: "no-store" });
  if (!res.ok) throw await failure(res);
  return res.json();
}

/* ── refresh (rotating) ── */

type TokenResponse = { access_token: string; expires_in?: number; refresh_token?: string; scope?: string; id_token?: string };

const inflight = new Map<string, Promise<TokenResponse>>();

/**
 * One refresh-token grant. NobleID rotates the refresh token on every use and
 * treats a second use of an old one as theft (the whole family is revoked),
 * so concurrent calls in this process with the same token share one request.
 * Throws NobleIdError("invalid_grant") when the session is over.
 */
export function refreshTokens(refreshToken: string): Promise<TokenResponse> {
  const key = crypto.createHash("sha256").update(refreshToken).digest("hex");
  const pending = inflight.get(key);
  if (pending) return pending;
  const p = (async () => {
    const { token_endpoint } = await getDiscovery();
    const res = await fetch(token_endpoint, {
      method: "POST",
      headers: { Authorization: basicAuth(), "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken }),
      cache: "no-store",
    });
    if (!res.ok) throw await failure(res);
    const t = (await res.json()) as TokenResponse;
    if (typeof t.access_token !== "string") throw new NobleIdError("invalid_token_response");
    return t;
  })();
  inflight.set(key, p);
  p.finally(() => setTimeout(() => inflight.delete(key), 0)).catch(() => {});
  return p;
}

/** RFC 7009. Revoking the refresh token also ends the access tokens minted from it. */
export async function revoke(token: string, hint: "refresh_token" | "access_token"): Promise<void> {
  const { revocation_endpoint } = await getDiscovery();
  const res = await fetch(revocation_endpoint, {
    method: "POST",
    headers: { Authorization: basicAuth(), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token, token_type_hint: hint }),
    cache: "no-store",
  });
  if (!res.ok) throw await failure(res);
}

/* ── small utilities ── */

export const randomToken = () => crypto.randomBytes(32).toString("base64url");

export function sameString(a: unknown, b: unknown): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ha = crypto.createHash("sha256").update(a).digest();
  const hb = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(ha, hb) && a.length === b.length;
}
