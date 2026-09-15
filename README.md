<div align="center">

# 🔍 ReconX

**All-in-One OSINT Suite**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-1.5.0-informational.svg)](CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://github.com/jude84162-sys/ReconX/actions/workflows/ci.yml/badge.svg)](https://github.com/jude84162-sys/ReconX/actions/workflows/ci.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](.github/PULL_REQUEST_TEMPLATE.md)

ReconX is a comprehensive open-source intelligence (OSINT) framework that
gathers information from publicly available sources. It features username
hunting across **536 platforms**, domain intelligence, IP profiling, and
Fediverse/Instagram lookups — all from a single CLI.

</div>

---

## ✨ Features

| Module | Description |
|--------|-------------|
| 🔍 **Username Search** | Hunt a username across **536 platforms** — social media, gaming, dev, dating, Fediverse, and more |
| 🌐 **Domain Intel** | **275-subdomain** brute-force enum, WHOIS lookup, HTTP security headers, technology detection |
| 📍 **IP Profiling** | Geolocation, ASN/BGP info, reverse DNS, **23-port** TCP scan, threat intel (AlienVault OTX, AbuseIPDB) |
| 🭓 **Fediverse** | `fedifinder`, `fediverse-observer`, `fediverse-osint` — discover and inspect Mastodon-compatible accounts |
| 📸 **Instagram** | `masto`, `inflact`, `osintgram` wrappers (see [Legal](#-legal--disclaimer)) |
| 📧 **Email Breach** | Async breach/reputation intelligence, k-anonymity password checks, incident-response links — **library only, no CLI entry point yet** |

### Username Module Coverage

Social media, developer platforms, gaming, art & design, music & video,
link-in-bio, finance, education, research, cybersecurity, Fediverse,
crypto/NFT, Asian platforms, dating, sports/fitness, podcasts, productivity,
hosting/cloud, and more — see `reconx/modules/username.py` for the full list.

## 🚀 Quick Start

```bash
# Install from PyPI
pip install reconx

# Or install from a clone (editable)
git clone https://github.com/jude84162-sys/ReconX.git
cd ReconX
pip install -e .
```

```bash
# Modern subcommand syntax
reconx username johndoe
reconx domain example.com
reconx ip 8.8.8.8
reconx list

# Legacy flag syntax (still supported)
reconx -u johndoe
reconx -d example.com
reconx -i 8.8.8.8

# Via the module entry point
python -m reconx -u johndoe
```

## 📖 Usage

Run `reconx --help` for the full option list.

**Target options**

| Flag | Description |
|------|-------------|
| `-u, --username <name>` | Search a username across platforms |
| `-d, --domain <domain>` | Domain intelligence gathering |
| `-i, --ip <ip>` | IP geolocation and profiling |
| `--fedifinder <target>` | Find Fediverse accounts (`domain` or `@user@instance`) |
| `--fediverse-observer <instance>` | Inspect a Fediverse instance |
| `--fediverse-osint <username>` | Search Fediverse instances for a username |
| `--masto <handle>` | Look up a Mastodon account (requires the `masto` CLI) |
| `--inflact <username>` | Fetch a public Inflact profile |
| `--osintgram <username>` | Run an external Osintgram command (requires `OSINTGRAM_PATH`) |

**Configuration**

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --timeout` | `10` | Request timeout in seconds |
| `-w, --workers` | `20` | Number of concurrent threads |
| `--verbose` | off | Enable verbose output |

**Output**

| Flag | Description |
|------|-------------|
| `-o, --output {json,csv,txt}` | Export results to a file |
| `-f, --file <name>` | Output filename (default: `reconx_results.<ext>`) |
| `--no-banner` | Skip the banner |
| `--quiet` | Suppress banner and non-essential output |
| `--list` | List all available modules |

## 🔑 API Keys

Optional integrations read keys from environment variables or a local
`config.json` (see `reconx/config.json.example`). Environment variables take
priority.

| Variable | Used by |
|----------|---------|
| `ABUSEIPDB_API_KEY` | IP threat intelligence |
| `OSINTGRAM_PATH` | Path to an Osintgram checkout (`--osintgram`) |

Keys are never logged and are redacted from error output and URLs.

## 🛠️ Development

```bash
# Install with dev tooling
pip install -e ".[dev]"

# Run the test suite (fully offline — network calls are mocked)
pytest
```

CI runs the test suite on Python 3.10, 3.11, 3.12 and 3.13 (see
`.github/workflows/ci.yml`).

The lint/security job (`black`, `isort`, `flake8`, `bandit`) is currently
**advisory** — the codebase predates formatter adoption, so those steps report
without blocking. To promote it to a real gate, run `black .` and `isort .`
once, clear the `flake8` output, then remove the `continue-on-error` lines.

## ⚠️ Legal & Disclaimer

ReconX is intended for **educational purposes and authorized security testing
only**. The authors assume no liability and are not responsible for any misuse
or damage caused by this program.

The `inflact` and `osintgram` modules interact with third-party services and
may violate their terms of service; `inflact` honours `robots.txt` and refuses
to fetch a URL it is not allowed to. **Always ensure you have proper written
authorization before conducting reconnaissance on any target**, and comply with
the CFAA and GDPR in your jurisdiction. Only use these modules against systems
you own or have explicit permission to test.

## 🤝 Contributing

Contributions are welcome! Please open a Pull Request using our
[PR template](.github/PULL_REQUEST_TEMPLATE.md), which asks you to declare a
risk tier and intent up front. Review expectations are documented in
[docs/REVIEW_GUIDELINES.md](docs/REVIEW_GUIDELINES.md).

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file.

Made with ❤️ by [jude84162-sys](https://github.com/jude84162-sys)
