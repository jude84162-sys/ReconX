# 🔍 ReconX

**Comprehensive Web Recon Toolkit** — Cross-platform reconnaissance for Termux, Kali, and WSL.

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Kali%20%7C%20WSL-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/Dependencies-0-brightgreen.svg)]()

*10 web reconnaissance tools in one interface — no external tools needed.*

---

## ✨ Features

### 🌐 Domain & DNS
- **🌐 Domain OSINT** — IPs (A/AAAA), WHOIS via socket, DNS records via DoH
- **🌐 DNS Deep Recon** — NS, MX, TXT, SOA, CAA, SPF/DMARC, zone transfer check

### 🌍 Network
- **🌍 IP OSINT** — Multi-source geolocation (ip-api.com + ipwho.is) with consensus
- **🔍 Port Scanner** — Multi-threaded, service detection, banner grabbing, vulnerability hints
- **🔐 SSL/TLS Analyzer** — Certificate, ciphers, protocol, grade (A+ to F)

### 🛡️ Web Recon
- **🌐 Subdomain Enumerator** — 7 passive sources + bruteforce, cross-validation
- **🌍 Web Fingerprint** — Detect 60+ technologies + security headers audit
- **📂 Directory Buster** — Multi-baseline soft-404 detection, sensitivity scoring
- **🔴 Nikto Wrapper** — Nikto integration for vulnerability scanning (requires nikto)

### 🎯 Combined
- **⚡ Full Web Recon** — All tools in parallel + auto HTML/TXT/JSON reports
- **⚡ Fast Web Recon** — Skip subdomains + dirbuster (faster)

### 🆕 Unique Features
- **DNS over HTTPS (DoH)** — No `nslookup`/`dig` needed (Cloudflare + Google fallback)
- **Socket-based WHOIS** — No `whois` command needed (port 43)
- **Thread-safe DNS resolution** — No global `setdefaulttimeout` bugs
- **Multi-source consensus** — Cross-verifies IP geolocation
- **Zero external tools** — Python stdlib only (nikto optional for vuln scan)
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
| **WHOIS (Socket)** | ~90% | Some TLDs block port 43 |
| **Web Fingerprint (Tech)** | 70-85% | Body patterns → some false positives |
| **Subdomain Enum** | 60-80% | Depends on external sources |
| **Directory Buster** | 60-75% | Soft-404 detection can fail |

**Reality check:** No OSINT tool is 100% accurate. Results should be verified manually for critical decisions.

---

## 🚀 Installation

### Requirements
- Python 3.8+
- Optional: `nikto` (for vulnerability scanning)

### Quick Start

```bash
git clone https://github.com/jude84162-sys/ReconX.git
cd ReconX

# Interactive CLI
python cli.py

# Non-interactive
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

# Nikto (if installed)
python -m modules.network.nikto_scan example.com 443
```

---

📁 Project Structure

```
ReconX/
├── cli.py                       # Interactive menu (10 tools)
├── recon.py                     # Full web recon (parallel, auto reports)
├── requirements.txt             # Optional deps
├── LICENSE                      # MIT License
├── README.md                    # This file
│
├── modules/
│   ├── __init__.py
│   │
│   ├── network/                 # Network-layer tools
│   │   ├── __init__.py
│   │   ├── port_scan.py         # Port scanner
│   │   ├── dns_deep.py          # DNS records (DoH)
│   │   ├── ssl_analyzer.py      # SSL/TLS analysis
│   │   └── nikto_scan.py        # Nikto wrapper (optional)
│   │
│   ├── web/                     # Web-layer tools
│   │   ├── __init__.py
│   │   ├── domain_osint.py      # Domain recon
│   │   ├── subdomain_enum.py    # Subdomain wrapper
│   │   ├── subfinder_clone.py   # 7 passive sources + brute
│   │   ├── web_fingerprint.py   # Tech detection
│   │   └── dir_buster.py        # Path discovery
│   │
│   ├── report/                  # Report generators
│   │   ├── __init__.py
│   │   └── html_report.py       # HTML dashboard
│   │
│   └── utils/                   # Utilities
│       ├── __init__.py
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

📝 Examples

Full Web Recon

```bash
$ python recon.py example.com

╔══════════════════════════════════════════════════════════════════╗
║              Comprehensive Web Recon  [DEEP MODE] v3             ║
╚══════════════════════════════════════════════════════════════════╝

  🎯 Target: example.com
  📅 Time:   2026-09-21 12:00:00

──────────────────────────────────────────────────────────────────
  [1/9] 🌐 Domain OSINT
──────────────────────────────────────────────────────────────────
  ✓ IPs resolved:       2
  ✓ Subdomains found:   0
  ✓ Registrar:          RESERVED-Internet Assigned Numbers Authority

⚡ Running 7 steps in PARALLEL...

──────────────────────────────────────────────────────────────────
  [3/9] 🔍 Port Scanner
──────────────────────────────────────────────────────────────────
  Scanning 22 ports on 93.184.216.34...
  ██████████████████████████████ 100.0% (22/22)
  ✓ Open ports:         2
      • 80    http
      • 443   https

══════════════════════════════════════════════════════════════════
  📊 FINAL SUMMARY — example.com
══════════════════════════════════════════════════════════════════

  🌐 DOMAIN
    IPs:             2
    Subdomains:      0

  🌍 IP
    Primary:         93.184.216.34
    Country:         United States
    ISP:             Edgecast Inc.

  🔐 SSL/TLS
    Grade:           A+
    Protocol:        TLSv1.3

  ⚠ RISK SUMMARY
    🔴 Critical:     0
    🟠 High:         0
    🟡 Medium:       16
    🔵 Low:          1
    Total:           17

✓ JSON:  outputs/recon_example.com_20260921_120000.json
✓ TXT:   outputs/recon_example.com_20260921_120000.txt
✓ HTML:  outputs/recon_example.com_20260921_120000.html
```

DNS Deep Recon

```bash
$ python -m modules.network.dns_deep example.com

[*] DNS Deep: example.com
  [*] Querying DNS records via DoH (parallel)...
  [*] Attempting AXFR via a.iana-servers.net...

[+] Nameservers (2):
    • a.iana-servers.net
    • b.iana-servers.net
[+] SPF: v=spf1 -all
[!] DMARC: MISSING
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

Note: Port scanning and directory busting generate visible traffic. Always ensure you have permission before scanning any target.

Users are responsible for complying with all applicable laws.

---

🤝 Contributing

Pull requests welcome. Please:

1. Fork the repository
2. Create a feature branch (git checkout -b feature/amazing-tool)
3. Commit your changes (git commit -m 'Add amazing tool')
4. Push to the branch (git push origin feature/amazing-tool)
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
· Subfinder by ProjectDiscovery — inspiration for subdomain enumeration

---

<div align="center">

Built with ❤️ for the OSINT community

⭐ Star this repo if you find it useful!

</div>
