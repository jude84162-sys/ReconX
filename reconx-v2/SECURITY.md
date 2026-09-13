# Security Policy

## Scope

ReconX v2 is an **OSINT (Open-Source Intelligence) tool**. It gathers information from **publicly available sources only**. It does **not**:

- Breach any system or service
- Bypass authentication or authorization
- Access private data
- Perform any illegal activity

## Legal Boundaries

**You MUST only use ReconX against targets you:**

1. **Own** — use `--self-owned` flag, OR
2. **Have written authorization to test** — use `--authorized-for <reason> --consent-file <path>`

Unauthorized use may violate:

- **CFAA** (US Computer Fraud and Abuse Act)
- **GDPR** (EU General Data Protection Regulation)
- **Computer Misuse Act** (UK)
- Similar laws in your jurisdiction

**The authors of ReconX assume no liability for misuse.**

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Reporting a Vulnerability

If you discover a security issue in **ReconX itself** (not in a target you scan), please:

1. **Do NOT** open a public GitHub issue
2. **DO** email the maintainer at the address listed in `Cargo.toml`
3. Include:
   - Description of the issue
   - Steps to reproduce
   - Affected version(s)
   - Any suggested fixes

We will respond within **7 days** and aim to publish a fix within **30 days** for critical issues.

## Audit Logging

ReconX logs every scan to `~/.reconx/audit.log` in JSON format. This includes:

- Timestamp (UTC)
- User ID (from `$USER` / `$USERNAME`)
- Action (`email_scan`)
- Target (email)
- Authorization type (`self` or `authorized:<reason>`)
- Result summary

If you are concerned about privacy, you can delete this file at any time.

## Rate Limiting

ReconX respects API rate limits:

- **HIBP**: honors `Retry-After` header
- **EmailRep**: throttles to your plan limit
- **Gravatar**: no official limit, but uses connection pooling
- **BreachDirectory**: documented rate limits

## Dependencies

We audit dependencies via:

- `cargo audit` (run in CI)
- `cargo deny` (planned)

To check locally:

    cargo install cargo-audit
    cd reconx-v2
    cargo audit

## Best Practices for Users

1. **Never** commit `.env` files (already in `.gitignore`)
2. **Never** share API keys in issues or PRs
3. **Rotate** API keys regularly
4. **Review** `~/.reconx/audit.log` for unexpected entries
5. **Run** in an isolated environment if scanning sensitive targets

## Contact

For security concerns, open a **private security advisory** on GitHub:

https://github.com/jude84162-sys/ReconX/security/advisories/new
