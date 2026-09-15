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
# Install from the repository (recommended)
git clone https://github.com/jude84162-sys/ReconX.git
cd ReconX
pip install -e .

# Or install straight from GitHub without cloning
pip install git+https://github.com/jude84162-sys/ReconX.git
```

> **Note:** ReconX is **not yet published to PyPI**. The `reconx` name on PyPI
> is currently unregistered and does not belong to this project — do not
> `pip install reconx` expecting this tool.

### 📱 Android / Termux

If you are running ReconX from Termux on Android, install the base build tools
first and then clone or install the project inside the Termux environment:

```bash
pkg update && pkg upgrade
pkg install git python build-essential libffi openssl

# Clone the repo
cd $HOME
git clone https://github.com/jude84162-sys/ReconX.git
cd ReconX

# Install the package in editable mode
python -m pip install --upgrade pip
python -m pip install -e .
```

You can also install directly from GitHub without cloning:

```bash
pkg install git python
python -m pip install --upgrade pip
python -m pip install git+https://github.com/jude84162-sys/ReconX.git
```

After installation, the CLI is available as `reconx` from Termux:

```bash
reconx --help
reconx username johndoe
reconx domain example.com
reconx ip 8.8.8.8
reconx websift https://example.com
```

> **Tip:** Because mobile devices often have constrained resources, keep the
> `--workers` value modest when running scans in Termux; for example,
> `reconx username johndoe -w 10`.

### Optional companion tools

ReconX can launch companion tools without copying their code into this
repository. Clone GitGhost beside the ReconX directory:

```bash
cd ..
git clone https://github.com/cy3erm/gitghost
cd Reconx
reconx gitghost --local /path/to/authorized/checkout
reconx gitghost octocat
```

External scans can take several minutes because GitGhost inspects repository
history. ReconX allows up to 10 minutes for each companion-tool run.

GitGhost is not cloned or installed automatically. Set `GITGHOST_PATH` if it
is stored somewhere else:

```bash
export GITGHOST_PATH="$HOME/tools/gitghost"
reconx gitghost octocat
```

The requested `https://github.com/cy3erm/TikOsint` repository currently
returns 404. The `reconx tikosint` wrapper is available for a valid local
checkout once one exists; set `TIKOSINT_PATH` to that checkout:

```bash
export TIKOSINT_PATH="$HOME/tools/TikOsint"
reconx tikosint
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
| `gitghost <target>` | Run GitGhost against a public GitHub identity or local checkout |
| `tikosint [target]` | Run a local TikOsint checkout (requires `TIKOSINT_PATH`) |
| `websift <url>` | Extract public emails, phones, social links, URLs, and metadata from one page |

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

### WebSift

WebSift analyzes one publicly accessible HTTP(S) page. It extracts email
addresses, phone numbers, social-media links, page URLs, title, and description.
It does not crawl linked pages, bypass access controls, authenticate, or submit
data. Use it only on pages you are authorized to analyze and follow the
website's terms and applicable law.

```bash
reconx websift https://example.com -o json -f websift.json
# Legacy-compatible form:
reconx --websift https://example.com
```

## 🔑 API Keys

Optional integrations read keys from environment variables or a local
`config.json` (see `reconx/config.json.example`). Environment variables take
priority.

| Variable | Used by |
|----------|---------|
| `ABUSEIPDB_API_KEY` | IP threat intelligence |
| `OSINTGRAM_PATH` | Path to an Osintgram checkout (`--osintgram`) |
| `GITHUB_ENCRYPTION_KEY` | Fernet key used to decrypt the GitHub token in memory |
| `GITHUB_ENCRYPTED_TOKEN` | Fernet-encrypted GitHub token passed to GitGhost |
| `GITHUB_TOKEN` | Plain environment-token fallback for GitGhost |

Keys are never logged and are redacted from error output and URLs. For
GitGhost, prefer the encrypted environment variables; ReconX decrypts the
token only in memory and passes it only to the child process. Never commit the
key, encrypted value, or plaintext token.

To create an encrypted token without placing the plaintext in a project file,
run this in a private terminal and keep both printed values out of Git:

```powershell
python -c "from cryptography.fernet import Fernet; import getpass; k=Fernet.generate_key(); print('GITHUB_ENCRYPTION_KEY='+k.decode()); print('GITHUB_ENCRYPTED_TOKEN='+Fernet(k).encrypt(getpass.getpass('GitHub token: ').encode()).decode())"
```

Then set the values in your shell session:

```powershell
$env:GITHUB_ENCRYPTION_KEY = "PASTE_KEY_HERE"
$env:GITHUB_ENCRYPTED_TOKEN = "PASTE_ENCRYPTED_TOKEN_HERE"
reconx gitghost octocat
```

The previously exposed tokens must be revoked before creating a replacement.

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
