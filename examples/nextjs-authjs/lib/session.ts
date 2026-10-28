/**
 * Reading the full (encrypted) session token on the server, and guarding this
 * app's own POST routes.
 */
import { headers } from "next/headers";
import type { NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";
import { type NobleToken, sameString } from "@/lib/nobleid";

const AUTH_URL = process.env.AUTH_URL;
const SECURE = AUTH_URL ? AUTH_URL.startsWith("https:") : process.env.NODE_ENV === "production";

/**
 * The decrypted session token, including the access and refresh tokens.
 * Server-side only; never return it to the browser.
 */
export async function readToken(): Promise<NobleToken | null> {
  const h = await headers();
  // Only the cookie: getToken would also accept an Authorization header.
  const req = { headers: { cookie: h.get("cookie") ?? "" } };
  const t = await getToken({ req, secret: process.env.AUTH_SECRET, secureCookie: SECURE });
  return t && typeof (t as { access_token?: unknown }).access_token === "string" ? (t as unknown as NobleToken) : null;
}

export function appOrigin(req: NextRequest): string {
  return AUTH_URL ? new URL(AUTH_URL).origin : req.nextUrl.origin;
}

/**
 * CSRF defence for POST /refresh and /logout: the Origin header must be this
 * app's origin, and the hidden `csrf` input must match the session's token.
 */
export async function checkPost(req: NextRequest, token: NobleToken | null): Promise<boolean> {
  if (req.headers.get("origin") !== appOrigin(req)) return false;
  if (!token) return true; // nothing to protect; the caller just redirects
  const body = await req.formData().catch(() => null);
  return sameString(body?.get("csrf"), token.csrf);
}
