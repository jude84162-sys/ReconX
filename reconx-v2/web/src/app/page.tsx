import Link from "next/link";

const features = [
  ["Email breach intelligence", "Aggregate authorized checks from the Rust v2 engine."],
  ["Username and domain workflows", "Keep common reconnaissance tasks in one dashboard."],
  ["Audit-first design", "Use explicit authorization before connecting production data."]
];

export default function HomePage() {
  return (
    <section className="space-y-16 py-16">
      <div className="max-w-3xl space-y-6">
        <p className="font-mono text-sm uppercase tracking-[0.3em] text-cyan-300">ReconX v2 / web</p>
        <h1 className="text-5xl font-bold tracking-tight text-white md:text-7xl">Authorized OSINT, focused.</h1>
        <p className="text-lg leading-8 text-slate-400">
          A dark, fast workspace for running ReconX investigations with clear authorization boundaries.
        </p>
        <Link href="/dashboard" className="button-primary inline-block">Open dashboard</Link>
      </div>
      <div className="grid gap-4 md:grid-cols-3">
        {features.map(([title, description]) => (
          <article key={title} className="panel">
            <h2 className="font-semibold text-white">{title}</h2>
            <p className="mt-3 text-sm leading-6 text-slate-400">{description}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
