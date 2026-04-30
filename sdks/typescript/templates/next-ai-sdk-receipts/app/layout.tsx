import type { ReactNode } from "react";

export const metadata = {
  title: "Chio receipts",
  description: "Next.js + Vercel AI SDK + Chio receipts viewer (template skeleton).",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
