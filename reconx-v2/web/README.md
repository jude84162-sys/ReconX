# ReconX Web Dashboard

Phase 7 provides a Next.js 14 + Clerk UI shell for ReconX v2. It includes a
dark landing page, protected dashboard, scan forms, and mock API routes for
email, username, domain, and IP workflows.

## Development

```powershell
Copy-Item .env.local.example .env.local
# Add Clerk keys to .env.local
npm install
npm run dev
```

The Rust API is intentionally not connected yet; that work belongs to Phase 8.
Do not commit `.env.local` or deploy this development shell without configuring
your own Clerk application.
