# 🔍 ReconX

**Web Recon & Vulnerability Suite** — 38 modules for Termux, Kali, and WSL.

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Kali%20%7C%20WSL-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-0-brightgreen.svg)]()
[![CI](https://github.com/jude84162-sys/ReconX/actions/workflows/ci.yml/badge.svg)](https://github.com/jude84162-sys/ReconX/actions/workflows/ci.yml)
[![Recon Test](https://github.com/jude84162-sys/ReconX/actions/workflows/recon-test.yml/badge.svg)](https://github.com/jude84162-sys/ReconX/actions/workflows/recon-test.yml)
[![Release](https://img.shields.io/github/v/release/jude84162-sys/ReconX)](https://github.com/jude84162-sys/ReconX/releases)
[![Downloads](https://img.shields.io/github/downloads/jude84162-sys/ReconX/total)](https://github.com/jude84162-sys/ReconX/releases)
[![Stars](https://img.shields.io/github/stars/jude84162-sys/ReconX)](https://github.com/jude84162-sys/ReconX/stargazers)

*38 recon and vulnerability-assessment modules in one interface — stdlib-first, optional Playwright/Chrome for the browser modules.*

---

## ✨ Features

### 🌐 Recon Modules (1-5)
- **Domain OSINT** — IPs (A/AAAA), WHOIS via socket, DNS records via DoH
- **IP OSINT** — Multi-source geolocation (ip-api.com + ipwho.is) with consensus
- **Port Scanner** — Multi-threaded, service detection, banner grabbing, vulnerability hints
- **DNS Deep Recon** — NS, MX, TXT, SOA, CAA, SPF/DMARC, zone transfer check
- **Subdomain Enumerator** — 7 passive sources + bruteforce, cross-validation with confidence scores

### 🔍 Web Discovery (6-10)
- **Web Fingerprint** — Detect 60+ technologies + security headers audit
- **Directory Buster** — Multi-baseline soft-404 detection, sensitivity scoring
- **Login Finder** — Search 87 login/admin paths (multi-language)
- **Register Finder** — Search 55 register/signup paths (multi-language)
- **Parameter Finder** — Test 101 URL parameters, detect reflection + size changes

### 🛡️ Security & Monitoring (11-13)
- **WAF Detector** — Detect 17 WAFs (Cloudflare, Akamai, Sucuri, Imperva, etc.)
- **Web Monitor** — Track page changes over time (body hash, size, headers, title)
- **SSL/TLS Analyzer** — Certificate, ciphers, protocol, grade (A+ to F)

### 🎯 Vulnerability Scanners (14-20, active)
- **SQLi, XSS, SSRF, SSTI, CMDi, JWT** — per-class scanners, plus an ALL runner

### 💰 Bounty & Content (21-23)
- **DIRB Content Scan** — Optional DIRB integration with wordlist selection
- **Bug Bounty Checks** — VCS, API docs, CORS, open redirect, GraphQL, JWT
- **Bug Bounty Nikto** — Multi-target parallel, WAF-aware, payout estimation

### 🎯 Full Recon (24-25)
- **Full Web Recon** — All recon tools in parallel + auto HTML/TXT/JSON reports
- **Fast Web Recon** — Skip subdomains + dirbuster (faster)

### 🚀 Attack Surface (26)
- **Attack Surface & Vuln Fuzzer** — crt.sh, Wayback, parameter triage, leak fuzzing

### 🧠 Advanced Modules (27-36)
- **GraphQL** — introspection, query batching, field-suggestion leakage
- **API / Swagger** — spec discovery + parameter type-mismatch fuzzing
- **Mass Assignment** — privileged fields and HTTP parameter pollution
- **BOLA / IDOR** — two-account object-level authorization mapping
- **Race Condition** — synchronized bursts for TOCTOU limit bypasses
- **Deserialization** — Java/PHP/Python/.NET/Ruby objects in client-controlled data
- **XXE & File Inclusion** — SOAP/SVG/XML entities + LFI traversal/wrappers
- **Cloud Metadata SSRF** — AWS/GCP/Azure/OCI endpoints + internal ports
- **Bucket Permissions** — S3/Azure Blob/GCP bucket discovery (read-only)
- **DOM XSS** — headless Chromium via Playwright, static taint fallback

All advanced modules share a differential response analyzer (semantic similarity,
DOM structure, reflection context) and a WAF-evasion mutation engine that retries
blocked payloads with URL/double-URL/hex/Unicode/entity/comment encodings.

### 📡 Live Hosts & Screenshots (37-38)
- **Live Host Prober** — httpx/httprobe-style HTTP(S) liveness check: status code, title,
  server, content-type, redirect chain and TLS protocol for every discovered host
- **Screenshot Gallery** — Aquatone-style: probes hosts, captures the live ones with
  Playwright or headless Chrome, and writes `outputs/screenshots/index.html`;
  authenticated captures via `--header` / `--cookie` (values never printed or stored)

### 🆕 Unique Features
- **DNS over HTTPS (DoH)** — No `nslookup`/`dig` needed (Cloudflare + Google fallback)
- **Socket-based WHOIS** — No `whois` command needed (port 43)
- **Thread-safe DNS resolution** — No global `setdefaulttimeout` bugs
- **Multi-source consensus** — Cross-verifies IP geolocation
- **Confidence scoring** — Every finding includes confidence + indicators
- **Zero external tools** — Python stdlib only
- **Parallel execution** — Independent steps run simultaneously

---

## 📊 Accuracy Notes

We don't claim "99% accuracy" — here's the honest picture:

| Tool | Accuracy | Notes |
|---|---|---|
| **SSL/TLS Analyzer** | ~99% | Direct TCP connection, no guessing |
| **DNS Deep (DoH)** | ~99% | Live queries via Cloudflare/Google |
| **Domain OSINT (IPs)** | ~99% | Socket resolution |
| **Port Scanner** | 95-99% | Depends on firewall/timeout |
| **IP OSINT** | ~95% | Multi-source consensus |
| **Web Fingerprint (Server)** | 85-95% | Header-based, reliable |
| **WAF Detector** | 85-95% | Signature-based (17 WAFs) |
| **Login Finder** | 80-90% | Form + title + text analysis |
| **Register Finder** | 80-90% | Form + password + text analysis |
| **WHOIS (Socket)** | ~90% | Some TLDs block port 43 |
| **Web Fingerprint (Tech)** | 70-85% | Body patterns → some false positives |
| **Web Monitor** | ~95% | Hash + size + headers comparison |
| **Parameter Finder** | 70-85% | Reflection + size + status diff |
| **GraphQL / API Checks** | 85-95% | Introspection/spec responses are definitive |
| **Bucket Checker** | ~90% | Provider listing responses |
| **DOM XSS (headless)** | ~95% | Only when Playwright is installed |
| **BOLA Mapper** | 60-80% | Confirm object ownership manually |
| **Race Condition** | 60-75% | Depends on server timing |
| **Subdomain Enum** | 60-80% | Depends on external sources |
| **Directory Buster** | 60-75% | Soft-404 detection can fail |

**Reality check:** No OSINT tool is 100% accurate. Verify critical findings manually.

---

## 🚀 Installation

### Requirements
- Python 3.8+ (stdlib only — no pip packages required)
- Optional: Playwright + Chromium for headless DOM XSS and screenshots (`pip install playwright && playwright install chromium`) — the screenshotter falls back to any installed Chrome/Chromium/Edge

### Quick Start

```bash
git clone https://github.com/jude84162-sys/ReconX.git
cd ReconX

# Interactive CLI
python cli.py

# Non-interactive
python recon.py example.com
📖 Usage

Interactive CLI (Recommended)

```bash
python cli.py
```

36 tools organized into 9 sections:

```
── Recon Modules ──
[1]  🌐 Domain OSINT
[2]  🌍 IP OSINT (multi-source)
[3]  🔍 Port Scanner
[4]  🌐 DNS Deep Recon
[5]  🌐 Subdomain Enumerator

── Web Discovery ──
[6]  🌍 Web Fingerprint
[7]  📂 Directory Buster
[8]  🔐 Login Finder
[9]  📝 Register Finder
[10] 🔗 Parameter Finder

── Security & Monitoring ──
[11] 🛡️  WAF Detector
[12] 👁️  Web Monitor
[13] 🔐 SSL/TLS Analyzer

── Web Vuln Scanners (active) ──
[14] 💉 SQL Injection      [15] 🎯 XSS             [16] 🌐 SSRF
[17] 📐 SSTI               [18] 💻 Command Inj.    [19] 🔑 JWT
[20] 🚀 ALL Web Vuln Scanners

── Bug Bounty & Content ──
[21] 🎯 DIRB Content Scan  [22] 🐛 Bug Bounty Checks  [23] 💰 Bug Bounty Nikto

── Full Recon (recommended) ──
[24] 🎯 Full Web Recon   (parallel)
[25] ⚡ Fast Web Recon   (skip subs/dirs)

── Attack Surface ──
[26] 🚀 Attack Surface & Vuln Fuzzer

── Advanced API & Logic ──
[27] 📊 GraphQL            [28] 🔌 API / Swagger
[29] 📦 Mass Assignment    [30] 👤 BOLA / IDOR Mapper
[31] ⚡ Race Condition

── Deep Injection & Cloud ──
[32] 🧩 Deserialization    [33] 📄 XXE & LFI
[34] ☁️  Cloud Metadata     [35] 🪣 Bucket Permissions

── Client-Side ──
[36] 🧠 DOM XSS (headless browser)

── Live Hosts & Screenshots ──
[37] 📡 Live Host Prober  (httpx / httprobe)
[38] 📸 Screenshot Gallery (aquatone-style)
```

Full Recon (Scriptable)

```bash
# Standard scan (13 tools, parallel)
python recon.py example.com

# Fast scan (skip subdomains + dirbuster)
python recon.py example.com --fast

# Save JSON report
python recon.py example.com --json

# Custom output
python recon.py example.com --output report.json

# More IPs in IP OSINT (default: 3)
python recon.py example.com --max-ips 5

# Screenshot every live subdomain after the scan (outputs/screenshots)
python recon.py example.com --screenshots
```

Module-Level Usage

```bash
# Domain OSINT
python -m modules.web.domain_osint example.com

# DNS Deep
python -m modules.network.dns_deep example.com

# Port scan
python -m modules.network.port_scan 8.8.8.8 top100

# Subdomain enum
python -m modules.web.subfinder_clone example.com

# SSL/TLS
python -m modules.network.ssl_analyzer example.com

# Dir buster
python -m modules.web.dir_buster https://example.com

# Login finder
python -m modules.web.login_finder https://github.com

# Register finder
python -m modules.web.register_finder https://github.com

# Parameter finder
python -m modules.web.param_finder "https://example.com/?id=1"

# WAF detector
python -m modules.web.waf_detector https://cloudflare.com

# Web monitor (run twice to detect changes)
python -m modules.web.web_monitor https://example.com

# GraphQL introspection / batching
python -m modules.vuln.advanced.graphql_scanner https://example.com/graphql

# API / Swagger discovery + type-mismatch fuzzing
python -m modules.vuln.advanced.api_fuzzer https://api.example.com

# Deserialization inspector (passive)
python -m modules.vuln.advanced.deserialization https://example.com

# XXE and LFI
python -m modules.vuln.advanced.xxe_lfi "https://example.com/view?page=home"

# Cloud metadata SSRF
python -m modules.vuln.advanced.cloud_metadata "https://example.com/fetch?url=x"

# BOLA / IDOR with two accounts
python -m modules.vuln.advanced.bola_mapper "https://api.example.com/orders/1" \
    "Bearer ACCOUNT_A" "Bearer ACCOUNT_B"

# Race condition burst
python -m modules.vuln.advanced.race_condition "https://example.com/redeem" \
    --data '{"coupon":"X"}' --threads 20 --max-expected 1

# DOM XSS (headless if Playwright is available)
python -m modules.vuln.web.dom_xss https://example.com --no-browser

# Which subdomains are live over HTTP(S)? (httpx / httprobe style)
python -m modules.web.live_probe api.example.com dev.example.com -f hosts.txt

# Screenshot live hosts + build a gallery (Playwright or headless Chrome)
python -m modules.web.aquatone_clone -f hosts.txt -o outputs/screenshots
python -m modules.web.aquatone_clone --from-json outputs/subdomains_20260101_120000.json

# Authenticated captures: extra headers and cookies per target origin
python -m modules.web.aquatone_clone app.example.com \
  --header "Authorization: Bearer $TOKEN" --cookie "session=$SESSION; csrftoken=$CSRF"
```

---

📁 Project Structure

```
ReconX/
├── cli.py                       # Interactive menu (38 tools)
├── recon.py                     # Full web recon (parallel, auto reports)
├── README.md
├── LICENSE
│
├── modules/
│   ├── network/                 # Network-layer tools
│   │   ├── port_scan.py         # Port scanner
│   │   ├── dns_deep.py          # DNS records via DoH
│   │   ├── ssl_analyzer.py      # SSL/TLS analysis
│   │   ├── ip_osint.py          # IP geolocation (multi-source)
│   │   └── nikto_scan.py        # Nikto wrapper (optional)
│   │
│   ├── web/                     # Web-layer tools
│   │   ├── domain_osint.py      # Domain recon
│   │   ├── subdomain_enum.py    # Subdomain wrapper
│   │   ├── subfinder_clone.py   # 7 passive sources + brute
│   │   ├── web_fingerprint.py   # Tech detection
│   │   ├── dir_buster.py        # Path discovery
│   │   ├── login_finder.py      # Login page finder
│   │   ├── register_finder.py   # Register page finder
│   │   ├── param_finder.py      # Parameter finder
│   │   ├── waf_detector.py      # WAF detection
│   │   ├── web_monitor.py       # Change detection
│   │   ├── live_probe.py        # Live host prober (httpx/httprobe)
│   │   └── aquatone_clone.py    # Screenshot gallery (Playwright/Chrome)
│   │
│   ├── vuln/                    # Vulnerability scanners
│   │   ├── web/                 # SQLi, XSS, SSRF, SSTI, CMDi, JWT, DOM XSS
│   │   ├── advanced/            # GraphQL, API, BOLA, race, XXE, cloud, buckets
│   │   ├── scanner_manager.py   # Unified scanner registry/runner
│   │   └── bounty_checks.py     # Bug-bounty checks
│   │
│   ├── report/                  # Report generators
│   │   └── html_report.py       # HTML dashboard
│   │
│   └── utils/                   # Utilities
│       ├── env_detect.py        # Environment detection
│       └── http_client.py       # Differential analysis + WAF mutation engine
│
├── tests/                       # stdlib unittest suite (loopback only)
│   ├── test_live_probe.py       # Prober parsing, probing, batches, reports
│   └── test_screenshot_targets.py  # Screenshot target parsing + job setup
│
└── outputs/                     # Generated reports (gitignored)
```

---

🧪 Running Tests

```bash
python -m unittest discover -s tests -t . -v
```

Stdlib `unittest` only. The suite binds to `127.0.0.1` and never touches the internet,
so it runs offline and needs no browser.

---

🖥️ Platform Status

Platform Status Notes
Termux (Android) ✅ Tested
Kali Linux ✅ Full support
WSL (Ubuntu/Debian/Kali) ✅ Tested
Native Linux ✅ Tested
macOS ✅ Should work
Windows (native) ⚠️ Untested (use WSL)

---

📝 Example Output

```bash
$ python recon.py example.com

╔══════════════════════════════════════════════════════════════════╗
║           Comprehensive Web Recon  [DEEP MODE] v4              ║
╚══════════════════════════════════════════════════════════════════╝

  🎯 Target: example.com
  📅 Time:   2026-09-21 14:59:13

──────────────────────────────────────────────────────────────────
  [1/13] 🌐 Domain OSINT
──────────────────────────────────────────────────────────────────
  ✓ IPs resolved:       10
  ✓ Registrar:          RESERVED-Internet Assigned Numbers Authority

⚡ Running 11 steps in PARALLEL...

...

══════════════════════════════════════════════════════════════════
  📊 FINAL SUMMARY — example.com
══════════════════════════════════════════════════════════════════

  🔐 WEB DISCOVERY
    Login pages:     0
    Register pages:  0
    Accepted params: 0
    Reflected params: 0
    WAF:             Cloudflare

  ⚠ RISK SUMMARY
    🔴 Critical:     0
    🟠 High:         0
    🟡 Medium:       3
    🔵 Low:          1
    Total:           5

  INDICATORS
    🟡 [MEDIUM  ] Port 80: HTTP - check outdated software
    🟡 [MEDIUM  ] No DMARC record (email spoofing risk)
    🔵 [LOW     ] Missing security headers
    ⚪ [INFO    ] WAF detected: Cloudflare (0.99)

✓ JSON:  outputs/recon_example.com_...json
✓ TXT:   outputs/recon_example.com_...txt
✓ HTML:  outputs/recon_example.com_...html
```

---

⚠️ Legal Disclaimer

ReconX is intended for authorized security testing and OSINT research only.

✅ Use for:

· Systems you own or have explicit permission to test
· Defensive security research
· Personal OSINT investigations
· Educational purposes

❌ Do NOT use for:

· Unauthorized surveillance
· Systems belonging to others without consent
· Harassment, stalking, or illegal activities
· Any use that violates local/international law

Note: Port scanning, directory busting and the active scanners (14-36) generate visible traffic. Advanced modules can send crafted objects, XML entities and repeated requests; some tests are state-changing. Always ensure you have written permission before scanning any target.

Users are responsible for complying with all applicable laws.

---

🤝 Contributing

Pull requests welcome. Please:

1. Fork the repository
2. Create a feature branch (git checkout -b feature/amazing-tool)
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

---

📄 License

MIT License — see LICENSE

---

🙏 Acknowledgments

· crt.sh, urlscan.io, AlienVault OTX — passive DNS sources
· hackertarget.com, rapiddns.io, web.archive.org, threatcrowd.org — subdomain sources
· ip-api.com, ipwho.is — geolocation APIs
· Cloudflare, Google — DNS-over-HTTPS resolvers
· Nikto by Chris Sullo & David Lodge — vulnerability scanning
· Subfinder by ProjectDiscovery — inspiration
· httpx and httprobe — live-host probing inspiration
· Aquatone by Michael Henriksen — screenshot-gallery inspiration

---

<div align="center">

Built with ❤️ for the OSINT community

⭐ Star this repo if you find it useful!

</div>
