import type { Metadata } from "next";
import "./globals.css";
import { AuthProvider } from "@/lib/auth-context";

export const metadata: Metadata = {
  title: "SentinelOps AI — Site Reliability Engineering Platform",
  description: "AI-assisted SRE platform for incident detection, investigation, safe remediation, and recovery verification.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-slate-950 text-slate-100 antialiased min-h-screen selection:bg-emerald-500/20 selection:text-emerald-400">
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
