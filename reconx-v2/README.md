# ReconX v2

> ⚡ Blazing-fast OSINT email breach intelligence, written in Rust

[![CI](https://github.com/jude84162-sys/ReconX/actions/workflows/ci.yml/badge.svg)](https://github.com/jude84162-sys/ReconX/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-blue.svg)](https://www.rust-lang.org)
[![Version](https://img.shields.io/badge/version-0.2.0-green.svg)](https://github.com/jude84162-sys/ReconX/releases)

> ⚠️ **Legal Disclaimer** — ReconX is intended for educational purposes and **authorized** security testing only. Scanning email addresses you do not own or have written permission to test may violate laws (CFAA, GDPR, etc.). The authors assume no liability for misuse. Always use `--self` for your own addresses, or `--authorized-for <reason> --consent-file <path>` for authorized pentests.

---

## ✨ Features

| Module | Description |
|--------|-------------|
| 📧 **Email Breach Intel** | HIBP, EmailRep, BreachDirectory, Gravatar |
| 🎯 **Risk Scoring** | 0-100 with confidence weighting |
| ⚡ **Async Parallel** | tokio::join! for 4 APIs at once |
| 📊 **Multi-Format Output** | JSON, CSV, TXT |
| 📝 **Audit Logging** | Every scan logged to `~/.reconx/audit.log` |
| 🔐 **Legal Compliance** | Authorization gate built-in |

---

## 🚀 Quick Start

    git clone https://github.com/jude84162-sys/ReconX.git
    cd ReconX/reconx-v2
    cargo build --release
    ./target/release/reconx email your@email.com --self
    ./target/release/reconx email your@email.com --self -o json -f report.json

---

## 📖 Usage

    ReconX v2 OSINT

    Usage: reconx <COMMAND>

    Commands:
      email  Email breach intelligence
      help   Print this message or the help of the given subcommand(s)

    Options:
      -h, --help     Print help
      -V, --version  Print version

### Email subcommand options

      --self-owned                Confirm the email belongs to you
      --authorized-for <REASON>   Reason for authorization
      --consent-file <PATH>       Path to signed consent form
  -o, --output <FORMAT>           txt | json | csv  (default: txt)
  -f, --file <PATH>               Output file (defaults to stdout)
      --verbose                   Verbose logging
      --breaches-only             Skip reputation and gravatar checks
      --timeout <SECONDS>         Request timeout (default: 10)

---

## 🏗 Architecture

    reconx-v2/
    ├── Cargo.toml                 # Workspace
    ├── web/                       # Next.js 14 + Clerk dashboard (Phase 7)
    ├── Dockerfile                 # Multi-stage build
    ├── crates/
    │   ├── reconx-core/          # Types, errors, traits, auth
    │   ├── reconx-common/        # Tracing, audit log, retry
    │   ├── reconx-breach/        # 4 APIs + aggregator + risk
    │   └── reconx-cli/           # clap-based CLI binary
    └── .github/workflows/ci.yml  # fmt + clippy + test + build

Data flow:

    CLI (reconx-cli)
         |
         v
   BreachModule (reconx-breach)
         |
   +-----+-----+-----+-----+
   v     v     v     v     v
  HIBP EmailRep BreachDir Gravatar
   |     |     |     |     |
   +-----+-----+-----+-----+
         |
         v
   Aggregator -> Risk Score
         |
         v
   JSON / CSV / TXT
         |
         v
   Audit log (~/.reconx/audit.log)

---

## ⚙️ Configuration

Create `reconx-v2/.env`:

    HIBP_API_KEY=your_key_here
    EMAILREP_API_KEY=your_key_here
    RUST_LOG=info

`HIBP_API_KEY` is required for HIBP free tier as of 2024. Get one at https://haveibeenpwned.com/API/Key.

---

## 🧪 Development

    cd reconx-v2
    cargo fmt --all
    cargo clippy --all-targets -- -D warnings
    cargo test --all
    cargo build --release

### Web dashboard

The Phase 7 dashboard lives in `web/` and provides a dark Next.js 14 + Clerk
UI shell with protected dashboard and scan routes. It currently uses mock API
responses; Rust API integration is planned for Phase 8.

    cd web
    Copy-Item .env.local.example .env.local
    # Add NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY and CLERK_SECRET_KEY
    npm install
    npm run dev

Full check:

    cargo fmt --all -- --check && \
    cargo clippy --all-targets -- -D warnings && \
    cargo test --all && \
    cargo build --release

---

## 🗺 Roadmap

- [x] **v0.2.0** — Email breach intelligence (current)
- [ ] **v0.3.0** — Username scanner (250+ sites)
- [ ] **v0.4.0** — Image EXIF + pHash
- [ ] **v0.5.0** — Phone number recon
- [ ] **v0.6.0** — Gmail-specific intel
- [x] **Phase 7** — Web dashboard UI and Clerk auth shell

See [root README](../README.md) for v1 (Python) docs.

---

## 📄 License

MIT — see [LICENSE](../LICENSE).

---

## 🙏 Acknowledgments

- HIBP (Troy Hunt)
- EmailRep.io
- BreachDirectory
- Gravatar
