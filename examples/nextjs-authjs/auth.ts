/**
 * Auth.js (next-auth v5) configured for "Sign in with NobleID".
 *
 * Session strategy: JWT. The ID-token claims, the userinfo claims and the
 * tokens live only in the encrypted (JWE) session cookie. The session object
 * that reaches the browser (`auth()`, `/api/auth/session`) carries claims and
 * flags, never an access or refresh token.
 */
import NextAuth from "next-auth";
import type { JWT } from "next-auth/jwt";
import {
  CLIENT_ID,
  CLIENT_SECRET,
  ISSUER,
  SCOPE,
  type NobleToken,
  NobleIdError,
  fetchUserinfo,
  randomToken,
  refreshTokens,
  revoke,
  verifyIdToken,
} from "@/lib/nobleid";

export const { handlers, auth, signIn, signOut, unstable_update } = NextAuth({
  providers: [
    {
      id: "nobleid",
      name: "NobleID",
      type: "oidc",
      // Discovery: the authorization endpoint lives on a different host than
      // the issuer; Auth.js reads it from the discovery document.
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      checks: ["pkce", "state", "nonce"], // PKCE S256 + state + nonce
      authorization: { params: { scope: SCOPE } },
      client: {
        token_endpoint_auth_method: "client_secret_basic",
        id_token_signed_response_alg: "ES256", // NobleID signs ID tokens with ES256 only
      },
    },
  ],
  // The session (and the tokens in it) ends 8 hours after the last cookie write.
  session: { strategy: "jwt", maxAge: 8 * 60 * 60 },
  // Both failure kinds land on one page that renders id="error".
  pages: { signIn: "/signin", error: "/signin" },
  callbacks: {
    async jwt({ token, account, trigger, session }) {
      // 1. Sign-in: Auth.js has exchanged the code and checked state, iss
      //    (RFC 9207), PKCE, nonce, aud and exp, but not the ID token's
      //    signature. Verify it here, then fetch userinfo once.
      if (account) {
        if (account.provider !== "nobleid" || !account.id_token || !account.access_token) {
          throw new NobleIdError("invalid_token_response");
        }
        const idClaims = await verifyIdToken(account.id_token);
        const info = await fetchUserinfo(account.access_token, idClaims.sub);
        const t: NobleToken = {
          sub: idClaims.sub, // key accounts on sub, never on email
          claims: { ...idClaims, ...info },
          // The user may untick scopes: read what was granted.
          scope: String(account.scope ?? SCOPE).split(" ").filter(Boolean),
          access_token: account.access_token,
          expires_at: account.expires_at ?? Math.floor(Date.now() / 1000),
          refresh_token: account.refresh_token,
          csrf: randomToken(),
        };
        return t as unknown as JWT;
      }

      // 2. An explicit refresh, requested by POST /refresh through
      //    unstable_update({ refresh: true }). Never refresh on a plain read:
      //    reads happen in parallel and a server component cannot write the
      //    cookie, so the rotated refresh token would be lost and the old one
      //    replayed, which makes NobleID revoke the whole session.
      if (trigger === "update" && session?.refresh === true) {
        const t = token as unknown as NobleToken;
        if (!t.refresh_token) return token;
        let spent = false; // once the grant succeeds, the old refresh token is dead
        try {
          const r = await refreshTokens(t.refresh_token);
          spent = true;
          if (r.id_token) {
            const c = await verifyIdToken(r.id_token); // no nonce on refresh-issued ID tokens
            if (c.sub !== t.sub) throw new NobleIdError("sub_mismatch");
          }
          const next: NobleToken = {
            ...t,
            access_token: r.access_token,
            expires_at: Math.floor(Date.now() / 1000) + Number(r.expires_in ?? 0),
            refresh_token: r.refresh_token ?? t.refresh_token, // store the rotated one
            scope: r.scope ? r.scope.split(" ").filter(Boolean) : t.scope,
            refresh_error: undefined,
          };
          return next as unknown as JWT;
        } catch (e) {
          // invalid_grant: the user revoked the app or the session ended. Sign out.
          if (e instanceof NobleIdError && e.code === "invalid_grant") return null;
          // The grant succeeded but its result was rejected: the stored refresh
          // token is spent and replaying it would revoke the session. Sign out.
          if (spent) return null;
          // Anything else (e.g. slow_down): keep the session, report it.
          return { ...t, refresh_error: e instanceof NobleIdError ? e.code : "refresh_failed" } as unknown as JWT;
        }
      }

      // Ignore any other client-supplied update data.
      return token;
    },

    // Only what the UI needs. No tokens.
    async session({ session, token }) {
      const t = token as unknown as NobleToken;
      return {
        ...session,
        sub: t.sub,
        claims: t.claims,
        scope: t.scope,
        csrf: t.csrf,
        canRefresh: Boolean(t.refresh_token),
        accessTokenExpiresAt: t.expires_at,
        refreshError: t.refresh_error ?? null,
      };
    },
  },
  events: {
    // NobleID has no end-session endpoint. Signing out = revoke the refresh
    // token (which ends its access tokens) and the access token, then Auth.js
    // clears the session cookie.
    async signOut(message) {
      if (!("token" in message) || !message.token) return;
      const t = message.token as unknown as NobleToken;
      if (t.refresh_token) await revoke(t.refresh_token, "refresh_token").catch(() => {});
      if (t.access_token) await revoke(t.access_token, "access_token").catch(() => {});
    },
  },
  // Never log tokens or codes: debug output off, errors reduced to type + message.
  debug: false,
  logger: {
    error(error) {
      const type = (error as { type?: string }).type ?? error.name;
      const cause = (error as { cause?: { err?: Error } }).cause?.err;
      console.error(`[auth][error] ${type}: ${error.message}${cause ? ` (${cause.message})` : ""}`);
    },
  },
});

/** The fields the session callback adds. */
export type NobleSession = {
  sub: string;
  claims: Record<string, unknown>;
  scope: string[];
  csrf: string;
  canRefresh: boolean;
  accessTokenExpiresAt: number;
  refreshError: string | null;
};
