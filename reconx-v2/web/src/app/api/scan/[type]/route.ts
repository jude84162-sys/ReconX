import { NextRequest, NextResponse } from "next/server";

const scanTypes = new Set(["email", "username", "domain", "ip"]);

export async function POST(request: NextRequest, { params }: { params: { type: string } }) {
  if (!scanTypes.has(params.type)) {
    return NextResponse.json({ error: "Unsupported scan type" }, { status: 404 });
  }
  const body = (await request.json()) as { target?: unknown };
  if (typeof body.target !== "string" || !body.target.trim()) {
    return NextResponse.json({ error: "A target is required" }, { status: 400 });
  }
  return NextResponse.json({
    status: "mock",
    scanType: params.type,
    target: body.target.trim(),
    message: "Placeholder response. Rust API integration is planned for Phase 8."
  });
}
