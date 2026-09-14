import Link from "next/link";

export function PublicNavbar() {
  return (
    <header className="border-b border-slate-800 bg-slate-950/90">
      <nav className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <Link href="/" className="font-mono text-lg font-bold text-cyan-300">
          reconx<span className="text-slate-500">/v2</span>
        </Link>
        <span className="text-sm text-slate-500">Clerk setup required</span>
      </nav>
    </header>
  );
}
