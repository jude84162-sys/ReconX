import { ClerkProvider } from "@clerk/nextjs";
import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { Navbar } from "@/components/navbar";
import { PublicNavbar } from "@/components/public-navbar";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "ReconX Web",
  description: "Authorized OSINT workflows for ReconX v2"
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const configuredKey = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
  const publishableKey =
    configuredKey && !configuredKey.includes("replace_me") ? configuredKey : undefined;
  const content = (
    <>
      {publishableKey ? <Navbar /> : <PublicNavbar />}
      <main className="mx-auto min-h-screen max-w-6xl px-6 py-10">{children}</main>
    </>
  );

  return (
    <html lang="en">
      <body className={inter.className}>
        {publishableKey ? <ClerkProvider publishableKey={publishableKey}>{content}</ClerkProvider> : content}
      </body>
    </html>
  );
}
