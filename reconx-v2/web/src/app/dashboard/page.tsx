import Link from "next/link";
import { AccountButton } from "@/components/account-button";

const scans = [
  ["email", "Email breach intelligence"],
  ["username", "Username search"],
  ["domain", "Domain intelligence"],
  ["ip", "IP profiling"]
] as const;

export default function DashboardPage() {
  return (
    <section className="space-y-10">
      <div className="flex items-start justify-between">
        <div>
          <p className="font-mono text-sm text-cyan-300">workspace / dashboard</p>
          <h1 className="mt-2 text-4xl font-bold text-white">Choose a workflow</h1>
          <p className="mt-3 text-slate-400">Mock scan endpoints are ready for the Rust API integration.</p>
        </div>
        <AccountButton />
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        {scans.map(([type, title]) => (
          <Link key={type} href={`/scan/${type}`} className="panel transition hover:border-cyan-400">
            <p className="font-mono text-sm text-cyan-300">/scan/{type}</p>
            <h2 className="mt-3 text-xl font-semibold text-white">{title}</h2>
            <p className="mt-2 text-sm text-slate-400">Open the form and prepare an authorized request.</p>
          </Link>
        ))}
      </div>
    </section>
  );
}
