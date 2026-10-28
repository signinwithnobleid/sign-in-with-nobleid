import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = { title: "NobleID example (Next.js + Auth.js)", referrer: "no-referrer" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "system-ui", maxWidth: "48rem", margin: "2rem auto", padding: "0 1rem" }}>{children}</body>
    </html>
  );
}
