<div align="center">

# 🔍 ReconX

**All-in-One OSINT Suite**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/Platforms-100%2B-orange.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)]()

ReconX is a comprehensive open-source intelligence (OSINT) framework that
gathers information from publicly available sources. It features username
hunting across 100+ platforms, email reconnaissance, domain intelligence,
and IP geolocation — all from a single, elegant CLI.

</div>

---

## ✨ Features

| Module | Description |
|--------|-------------|
| 🔍 **Username Search** | Hunt a username across **100+ social media platforms** and websites simultaneously |
| 📧 **Email Recon** | Check breaches (HIBP), Gravatar profiles, domain DNS/SPF/DMARC records |
| 🌐 **Domain Intel** | DNS enumeration, WHOIS lookup, **150+ subdomain brute-force**, tech detection, security headers |
| 📍 **IP Profiling** | Geolocation, ASN/BGP info, reverse DNS, **22 common port scan**, threat intel (OTX) |

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/jude84162-sys/ReconX.git
cd ReconX

# Install dependencies
pip install -r requirements.txt

# Run a username search
python -m reconx -u johndoe

# Email reconnaissance
python -m reconx -e user@example.com

# Domain intelligence
python -m reconx -d example.com

# IP profiling
python -m reconx -i 8.8.8.8
```

## 📖 Usage

```
usage: reconx [-h] [-v] [-u USERNAME] [-e EMAIL] [-d DOMAIN] [-i IP]
               [-t TIMEOUT] [-w WORKERS] [--verbose] [-o {json,csv,txt}]
               [-f FILE] [--no-banner] [--list]

ReconX - All-in-One OSINT Suite

Target Options:
  -u, --username   Search for a username across platforms
  -e, --email      Email address reconnaissance
  -d, --domain     Domain intelligence gathering
  -i, --ip         IP geolocation and profiling

Configuration:
  -t, --timeout    Request timeout in seconds (default: 10)
  -w, --workers    Number of concurrent threads (default: 20)
  --verbose        Enable verbose output

Output Options:
  -o, --output     Export results (json, csv, txt)
  -f, --file       Output filename
  --no-banner      Skip the banner display
  --list           List all available modules
```

## 🎯 Examples

### Username Search
```bash
# Basic search
python -m reconx -u johndoe

# With more threads (faster)
python -m reconx -u johndoe -w 50

# Export to JSON
python -m reconx -u johndoe -o json -f results.json
```

### Email Reconnaissance
```bash
python -m reconx -e user@example.com
```

### Domain Intelligence
```bash
python -m reconx -d example.com
python -m reconx -d example.com -o json -f domain_report.json
```

### IP Profiling
```bash
python -m reconx -i 8.8.8.8
python -m reconx -i 1.1.1.1 -o csv -f ip_report.csv
```

### List Modules
```bash
python -m reconx --list
```

## 🏗 Project Structure

```
ReconX/
├── reconx/
│   ├── __init__.py          # Package init
│   ├── __main__.py          # Entry point
│   ├── cli.py               # CLI argument parser
│   ├── core/
│   │   └── engine.py        # Module base class & engine
│   ├── modules/
│   │   ├── username.py      # Username recon (100+ sites)
│   │   ├── email.py         # Email recon
│   │   ├── domain.py        # Domain intel
│   │   └── ip.py            # IP profiling
│   └── utils/
│       ├── http.py          # HTTP helpers
│       └── output.py        # Rich console output
├── requirements.txt
├── LICENSE
└── README.md
```

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| `requests` | HTTP requests |
| `rich` | Beautiful terminal output |
| `dnspython` | Advanced DNS lookups |
| `python-whois` | WHOIS lookups |

## ⚠️ Disclaimer

> **ReconX is intended for educational purposes and authorized security testing only.**
> The authors assume no liability and are not responsible for any misuse or damage
> caused by this program. Always ensure you have proper authorization before
> conducting reconnaissance on any target.

## 🤝 Contributing

Contributions are welcome! Feel free to open a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Made with ❤️ by [jude84162-sys](https://github.com/jude84162-sys)**

</div>
