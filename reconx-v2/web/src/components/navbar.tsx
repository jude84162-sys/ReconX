"use client";

import { SignInButton, SignUpButton, UserButton, useUser } from "@clerk/nextjs";
import Link from "next/link";

export function Navbar() {
  const { isSignedIn } = useUser();

  return (
    <header className="border-b border-slate-800 bg-slate-950/90">
      <nav className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <Link href="/" className="font-mono text-lg font-bold text-cyan-300">
          reconx<span className="text-slate-500">/v2</span>
        </Link>
        <div className="flex items-center gap-4 text-sm text-slate-300">
          {isSignedIn && <Link href="/dashboard" className="hover:text-cyan-300">Dashboard</Link>}
          {!isSignedIn ? (
            <>
              <SignInButton mode="modal">
                <button className="hover:text-cyan-300">Sign in</button>
              </SignInButton>
              <SignUpButton mode="modal">
                <button className="button-primary">Get started</button>
              </SignUpButton>
            </>
          ) : (
            <UserButton afterSignOutUrl="/" />
          )}
        </div>
      </nav>
    </header>
  );
}
