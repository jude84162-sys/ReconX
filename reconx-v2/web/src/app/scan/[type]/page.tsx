import { notFound } from "next/navigation";
import { ScanForm } from "@/components/scan-form";

const scanTypes = ["email", "username", "domain", "ip"] as const;
type ScanType = (typeof scanTypes)[number];

export default function ScanPage({ params }: { params: { type: string } }) {
  if (!scanTypes.includes(params.type as ScanType)) notFound();
  const type = params.type as ScanType;
  return (
    <section className="space-y-8">
      <div>
        <p className="font-mono text-sm text-cyan-300">reconx / scan / {type}</p>
        <h1 className="mt-2 text-4xl font-bold capitalize text-white">{type} scan</h1>
        <p className="mt-3 text-slate-400">This Phase 7 endpoint returns mock data until the Rust API is wired in Phase 8.</p>
      </div>
      <ScanForm type={type} />
    </section>
  );
}
