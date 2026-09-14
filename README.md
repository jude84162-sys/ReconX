<div align="center">

# 🔍 ReconX

**All-in-One OSINT Suite**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/Platforms-500%2B-orange.svg)]()
[![Tests](https://github.com/jude84162-sys/ReconX/actions/workflows/ci.yml/badge.svg)](https://github.com/jude84162-sys/ReconX/actions/workflows/ci.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)]()

ReconX is a comprehensive open-source intelligence (OSINT) framework that
gathers information from publicly available sources. It features username
hunting across **500+ platforms**, domain intelligence,
and IP geolocation — all from a single, elegant CLI.

> **Note:** Email reconnaissance has been moved to ReconX v2 (Rust) for improved performance and capabilities.

</div>

---

## ✨ Features

| Module | Description |
|--------|-------------|
| 🔍 **Username Search** | Hunt a username across **500+ social media platforms**, gaming sites, dev platforms, dating apps, Fediverse, and more |
| 🌐 **Domain Intel** | DNS enumeration, WHOIS lookup, **150+ subdomain brute-force**, tech detection, security headers |
| 📍 **IP Profiling** | Geolocation, ASN/BGP info, reverse DNS, **22 common port scan**, threat intel (OTX) |

### Username Module Covers 500+ Platforms:
- **Social Media**: Twitter/X, Instagram, Facebook, TikTok, LinkedIn, Reddit, Threads, Bluesky, Mastodon (15+ instances), Truth Social, Parler, Gab, VK, Cohost, Post.news, and more
- **Developer**: GitHub, GitLab, Codeberg, SourceHut, Stack Overflow, HackerRank, LeetCode, Codeforces, Codewars, Dev.to, Replit, CodePen, Observable, ShaderToy, Arduino, Raspberry Pi, and more
- **Gaming**: Steam, Xbox, PSN, Roblox, Minecraft, Osu!, Chess.com, Faceit, Epic Games, Battle.net, Ubisoft, Rockstar, GOG, itch.io, Speedrun.com, BoardGameGeek, and more
- **Art & Design**: ArtStation, Behance, Dribbble, Figma, Canva, Unsplash, 500px, Pixiv, DeviantArt, Sketchfab, ViewBug, GuruShots, EyeEm, VSCO, SmugMug, and more
- **Music & Video**: YouTube, Twitch, Spotify, SoundCloud, Vimeo, Dailymotion, Bandcamp, Rate Your Music, Discogs, Mixcloud, Audius, Audiomack, ReverbNation, Jamendo, Splice, and more
- **Link-in-Bio**: Linktree, Carrd, Bento.me, Solo.to, Milkshake, Beacons, Lnk.Bio, Stan Store, HeyLink, Willlow, Taplink, and more
- **Finance**: PayPal, Venmo, Cash.app, Wise, Monzo, Revolut, Liberapay, Patreon, BuyMeACoffee, Gumroad, Subscribestar, and more
- **Education**: LeetCode, Coursera, Udemy, Khan Academy, Duolingo, freeCodeCamp, Codecademy, Brilliant, TED, EdX, Udacity, Pluralsight, Skillshare, FutureLearn, and more
- **Research**: ResearchGate, Academia.edu, ORCID, Google Scholar, Semantic Scholar, arXiv, SSRN, Mendeley, and more
- **Cybersecurity**: HackerOne, Bugcrowd, Hack The Box, TryHackMe, Shodan, VirusTotal, Censys, PentestIT, Exploit-DB, GreyNoise, and more
- **Fediverse**: Mastodon.social, Mastodon.online, Fosstodon, Hachyderm, Pixelfed, PeerTube, Lemmy, Kbin, Misskey, Pleroma, WriteFreely, Bookwyrm, Friendica, Diaspora, Akkoma
- **Crypto/NFT**: OpenSea, Rarible, Foundation, SuperRare, Zora, Mirror, ENS, Etherscan, Blockscout, Dune Analytics
- **Asian Platforms**: Bilibili, Douyin, Zhihu, Weibo, WeChat, QQ, Xiaohongshu, Douban, Toutiao, Kuaishou, Naver, Daum, LINE, KakaoTalk, Mixi
- **Dating**: OkCupid, Tinder, Bumble, Hinge, Coffee Meets Bagel, Match.com, eHarmony, EliteSingles, POF
- **Sports/Fitness**: Strava, Nike Run Club, MapMyRun, Garmin Connect, Fitbit, Peloton, Whoop, Zwift, Komoot, AllTrails
- **Podcasts**: Anchor, Buzzsprout, Podbean, Spreaker, Transistor, Simplecast, Podcast Index
- **Productivity**: Notion, Coda, Airtable, Miro, Trello, Asana, Monday.com, Basecamp, Wrike, Toggl, Slack, Discord
- **Hosting/Cloud**: GitHub Pages, GitLab Pages, Netlify, Vercel, Railway, Fly.io, Render, Cloudflare Pages, Glitch, Surge.sh, PythonAnywhere
- **And 100+ more...**

> 📧 **Email Reconnaissance**: Now available in ReconX v2 (Rust) — see [reconx-v2/](reconx-v2/)
## 🚀 Quick Start

```bash
# Install via pip (recommended)
pip install reconx

# Or clone the repository
git clone https://github.com/jude84162-sys/ReconX.git
cd ReconX
pip install -e .

# Run a username search
reconx -u johndoe

# Or using python module
python -m reconx -u johndoe
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
  --no-banner, --quiet
                   Skip the banner display
  --list           List all available modules
```

## 🎯 Examples

### Username Search
```bash
# Basic search
reconx -u johndoe

# With more threads (faster)
reconx -u johndoe -w 50

# Export to JSON
reconx -u johndoe -o json -f results.json

# Export to CSV
reconx -u johndoe -o csv -f results.csv
```

### Domain Intelligence
```bash
reconx -d example.com
reconx -d example.com -o json -f domain_report.json
```

### IP Profiling
```bash
reconx -i 8.8.8.8
reconx -i 1.1.1.1 -o csv -f ip_report.csv
```

### Configuring API Keys
For enhanced threat intelligence (AbuseIPDB), set the API key as an environment variable:

```bash
# Linux/macOS
export ABUSEIPDB_API_KEY="your_api_key_here"

# Windows PowerShell
$env:ABUSEIPDB_API_KEY="your_api_key_here"

# Or create a config.json file (see config.json.example)
```

### List Modules
```bash
reconx --list
```

## 🏗 Project Structure

```
ReconX/
├── .github/workflows/
│   ├── ci.yml              # CI: lint, test (3.8-3.12), security scan, smoke test
│   └── release.yml         # CD: auto-publish to PyPI on release
├── reconx/
│   ├── __init__.py          # Package init
│   ├── __main__.py          # Entry point
│   ├── cli.py               # CLI argument parser
│   ├── core/
│   │   └── engine.py        # Module base class & engine
│   ├── modules/
│   │   ├── username.py      # Username recon (250+ sites)
│   │   ├── domain.py        # Domain intel
│   │   └── ip.py            # IP profiling
│   └── utils/
│       ├── http.py          # HTTP helpers
│       └── output.py        # Rich console output
├── tests/
│   ├── test_engine.py       # Core engine tests
│   ├── test_modules.py      # Module validation tests
│   └── test_cli.py          # CLI & export tests
├── setup.py                  # Package configuration
├── pyproject.toml            # Modern Python project config
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
| `beautifulsoup4` | HTML parsing for new modules |
## 🧪 Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ -v --cov=reconx

# Lint
flake8 reconx/ tests/ --max-line-length=120
black --check --line-length=120 reconx/ tests/
```

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
