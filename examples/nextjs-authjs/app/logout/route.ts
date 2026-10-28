import { type NextRequest, NextResponse } from "next/server";
import { signOut } from "@/auth";
import { appOrigin, checkPost, readToken } from "@/lib/session";

/**
 * Sign out: events.signOut (auth.ts) revokes the refresh and access tokens at
 * NobleID, then Auth.js clears the session cookie. NobleID has no end-session
 * endpoint, so there is no redirect to the provider.
 */
export async function POST(req: NextRequest) {
  const token = await readToken();
  if (!(await checkPost(req, token))) return new NextResponse('<p id="error">forbidden</p>', { status: 403, headers: { "Content-Type": "text/html; charset=utf-8" } });
  if (token) await signOut({ redirect: false });
  return NextResponse.redirect(new URL("/", appOrigin(req)), 303);
}
