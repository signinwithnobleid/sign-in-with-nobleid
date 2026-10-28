import type { Session } from "next-auth";
import { auth, type NobleSession } from "@/auth";
import { SignInButton } from "./sign-in-button";

export const dynamic = "force-dynamic";

export default async function Home() {
  const session = (await auth()) as (Session & Partial<NobleSession>) | null;
  if (!session?.sub || !session.claims || !session.csrf) {
    return (
      <main>
        <h1>NobleID example (Next.js + Auth.js)</h1>
        <p id="signed-out">You are signed out.</p>
        <SignInButton />
      </main>
    );
  }
  const c = session.claims;
  const shown = { ...c, granted_scope: (session.scope ?? []).join(" ") };
  return (
    <main>
      <h1>Signed in</h1>
      <p>Hello, {String(c.name ?? c.nobleid ?? session.sub)}.</p>
      {session.refreshError ? <p>Last refresh failed: {session.refreshError}</p> : null}
      {/* React escapes text content, so the JSON is HTML-escaped. */}
      <pre id="claims">{JSON.stringify(shown, null, 2)}</pre>
      <p>
        <a href="/works">My works</a>{" "}
        {session.canRefresh ? (
          <form method="post" action="/refresh" style={{ display: "inline" }}>
            <input type="hidden" name="csrf" value={session.csrf} />
            <button type="submit">Refresh tokens</button>
          </form>
        ) : null}{" "}
        <form method="post" action="/logout" style={{ display: "inline" }}>
          <input type="hidden" name="csrf" value={session.csrf} />
          <button type="submit">Sign out</button>
        </form>
      </p>
    </main>
  );
}
