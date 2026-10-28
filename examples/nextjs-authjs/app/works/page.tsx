import { redirect } from "next/navigation";
import { NobleIdError, fetchWorks } from "@/lib/nobleid";
import { readToken } from "@/lib/session";

export const dynamic = "force-dynamic";

export default async function Works() {
  const token = await readToken();
  if (!token) redirect("/");
  const back = (
    <p>
      <a href="/">Back</a>
    </p>
  );
  if (!token.scope.includes("works")) return <main><p>The works scope was not granted.</p>{back}</main>;
  // Reads never refresh (see README). An expired access token means: POST /refresh first.
  if (token.expires_at <= Math.floor(Date.now() / 1000) + 10) {
    return <main><p>The access token has expired. Use “Refresh tokens” on the home page.</p>{back}</main>;
  }
  let works: unknown;
  try {
    works = await fetchWorks(token.access_token, { limit: 50 });
  } catch (e) {
    const code = e instanceof NobleIdError ? e.code : "server_error";
    return <main><p id="error">{code}</p>{back}</main>;
  }
  return (
    <main>
      <h1>Works</h1>
      <pre id="works">{JSON.stringify(works, null, 2)}</pre>
      {back}
    </main>
  );
}
