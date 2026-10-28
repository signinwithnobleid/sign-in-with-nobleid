import { signIn } from "@/auth";

/** A server action: Next.js checks the Origin of the POST, Auth.js does the rest. */
export function SignInButton() {
  return (
    <form
      action={async () => {
        "use server";
        await signIn("nobleid", { redirectTo: "/" });
      }}
    >
      <button type="submit">Sign in with NobleID</button>
    </form>
  );
}
