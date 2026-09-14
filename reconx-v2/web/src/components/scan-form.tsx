"use client";

import { FormEvent, useState } from "react";

type ScanFormProps = { type: "email" | "username" | "domain" | "ip" };

export function ScanForm({ type }: ScanFormProps) {
  const [target, setTarget] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setResult(null);
    const response = await fetch(`/api/scan/${type}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target })
    });
    const data = await response.json();
    setResult(JSON.stringify(data, null, 2));
    setLoading(false);
  }

  return (
    <form onSubmit={submit} className="panel max-w-2xl space-y-5">
      <label className="block text-sm text-slate-300" htmlFor="target">
        {type} target
      </label>
      <input
        id="target"
        required
        value={target}
        onChange={(event) => setTarget(event.target.value)}
        placeholder={`Enter a ${type}`}
        className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 font-mono text-slate-100 outline-none focus:border-cyan-400"
      />
      <button className="button-primary" disabled={loading}>
        {loading ? "Preparing scan..." : "Run authorized scan"}
      </button>
      {result && <pre className="overflow-x-auto rounded-lg bg-slate-950 p-4 text-xs text-cyan-200">{result}</pre>}
    </form>
  );
}
