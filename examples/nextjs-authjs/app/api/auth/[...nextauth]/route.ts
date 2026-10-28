import type { NextRequest } from "next/server";
import { handlers } from "@/auth";
import { appOrigin } from "@/lib/session";

export const POST = handlers.POST;

// RFC 6749 error codes are short ASCII tokens; only show ones that look like that.
const ERROR_CODE = /^[A-Za-z0-9_.-]{1,64}$/;

/**
 * Auth.js reports a provider error (e.g. the user denied consent) as
 * `?error=OAuthCallbackError` and drops the provider's own code. It throws that
 * error only after it has checked state and iss, so at that point the `error`
 * on the callback is genuine: pass it on to the error page as `provider_error`.
 */
export async function GET(req: NextRequest): Promise<Response> {
  const res = await handlers.GET(req);
  const providerError = req.nextUrl.searchParams.get("error");
  const location = res.headers.get("location");
  if (req.nextUrl.pathname !== "/api/auth/callback/nobleid" || !providerError || !location) return res;
  const to = new URL(location, req.nextUrl);
  if (to.origin !== appOrigin(req) || to.searchParams.get("error") !== "OAuthCallbackError" || !ERROR_CODE.test(providerError)) return res;
  to.searchParams.set("provider_error", providerError);
  const h = new Headers(res.headers); // Response.redirect() headers are immutable
  h.set("location", to.toString());
  return new Response(null, { status: res.status, headers: h });
}
