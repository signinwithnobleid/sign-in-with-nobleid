import { SignInButton } from "../sign-in-button";

export const dynamic = "force-dynamic";

// What Auth.js puts in ?error=. Validation failures (state, iss, nonce, aud,
// signature) are not "client safe" in Auth.js and all arrive as Configuration.
const HELP: Record<string, string> = {
  OAuthCallbackError: "NobleID returned an error.",
  Configuration: "The sign-in response failed validation (state, iss, ID token) or the app is misconfigured. The server log has the reason.",
  AccessDenied: "This app's signIn callback refused the sign-in.",
  MissingCSRF: "The sign-in form expired. Try again.",
};

const CODE = /^[A-Za-z0-9_.-]{1,64}$/;

export default async function SignInPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const q = await searchParams;
  const one = (v: string | string[] | undefined) => (typeof v === "string" && CODE.test(v) ? v : undefined);
  const error = one(q.error);
  // Set by app/api/auth/[...nextauth]/route.ts only after Auth.js validated state and iss.
  const providerError = error === "OAuthCallbackError" ? one(q.provider_error) : undefined;
  return (
    <main>
      <h1>Sign in</h1>
      {error ? (
        <>
          <p id="error">{providerError ?? error}</p>
          <p>
            {Object.hasOwn(HELP, error) ? HELP[error] : "Sign-in failed."}
            {providerError ? ` (Auth.js: ${error})` : null}
          </p>
        </>
      ) : null}
      <SignInButton />
      <p>
        <a href="/">Home</a>
      </p>
    </main>
  );
}
