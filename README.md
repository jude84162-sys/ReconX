# 🔍 ReconX

**Comprehensive Web Recon Toolkit** — 15 tools for Termux, Kali, and WSL.

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Kali%20%7C%20WSL-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-0-brightgreen.svg)]()
[![CI](https://github.com/jude84162-sys/ReconX/actions/workflows/ci.yml/badge.svg)](https://github.com/jude84162-sys/ReconX/actions/workflows/ci.yml)
[![Recon Test](https://github.com/jude84162-sys/ReconX/actions/workflows/recon-test.yml/badge.svg)](https://github.com/jude84162-sys/ReconX/actions/workflows/recon-test.yml)
[![Release](https://img.shields.io/github/v/release/jude84162-sys/ReconX)](https://github.com/jude84162-sys/ReconX/releases)
[![Downloads](https://img.shields.io/github/downloads/jude84162-sys/ReconX/total)](https://github.com/jude84162-sys/ReconX/releases)
[![Stars](https://img.shields.io/github/stars/jude84162-sys/ReconX)](https://github.com/jude84162-sys/ReconX/stargazers)

*15 web reconnaissance tools in one interface — pure recon, no exploitation.*

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

### 🎯 Full Recon (14-15)
- **Full Web Recon** — All 13 tools in parallel + auto HTML/TXT/JSON reports
- **Fast Web Recon** — Skip subdomains + dirbuster (faster)

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
| **Subdomain Enum** | 60-80% | Depends on external sources |
| **Directory Buster** | 60-75% | Soft-404 detection can fail |

**Reality check:** No OSINT tool is 100% accurate. Verify critical findings manually.

---

## 🚀 Installation

### Requirements
- Python 3.8+ (stdlib only — no pip packages required)

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

15 tools organized into 4 sections:

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

── Full Recon (recommended) ──
[14] 🎯 Full Web Recon   (parallel, 13 tools)
[15] ⚡ Fast Web Recon   (skip subs/dirs)
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
```

---

📁 Project Structure

```
ReconX/
├── cli.py                       # Interactive menu (15 tools)
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
│   │   └── web_monitor.py       # Change detection
│   │
│   ├── report/                  # Report generators
│   │   └── html_report.py       # HTML dashboard
│   │
│   └── utils/                   # Utilities
│       └── env_detect.py        # Environment detection
│
└── outputs/                     # Generated reports (gitignored)
```

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

Note: Port scanning and directory busting generate visible traffic. The WAF detector sends harmless probe payloads. Always ensure you have permission before scanning any target.

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

---

<div align="center">

Built with ❤️ for the OSINT community

⭐ Star this repo if you find it useful!

</div>
