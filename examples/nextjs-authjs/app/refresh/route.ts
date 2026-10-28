import { type NextRequest, NextResponse } from "next/server";
import { unstable_update } from "@/auth";
import { appOrigin, checkPost, readToken } from "@/lib/session";

/**
 * One refresh-token grant, on an explicit POST. The jwt callback performs it
 * (trigger "update") and Auth.js writes the rotated refresh token back into
 * the session cookie. On invalid_grant the jwt callback ends the session.
 */
export async function POST(req: NextRequest) {
  const token = await readToken();
  if (!(await checkPost(req, token))) return new NextResponse('<p id="error">forbidden</p>', { status: 403, headers: { "Content-Type": "text/html; charset=utf-8" } });
  // The data is not a session: the jwt callback reads `refresh: true` and nothing else.
  if (token?.refresh_token) await unstable_update({ refresh: true } as unknown as Parameters<typeof unstable_update>[0]);
  return NextResponse.redirect(new URL("/", appOrigin(req)), 303);
}
