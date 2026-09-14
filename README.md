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

## 🚀 Quick Start

```bash
# Install via pip (recommended)
pip install reconx

# Or clone the repository
git clone [https://github.com/jude84162-sys/ReconX.git](https://github.com/jude84162-sys/ReconX.git)
cd ReconX
pip install -e .

# Run a username search
reconx -u johndoe

# Or use the modern subcommand syntax
reconx username johndoe

# Or using python module
python -m reconx -u johndoe

📖 Usage
usage: reconx [-h] [-v] [-u USERNAME] [-d DOMAIN] [-i IP]
               [-t TIMEOUT] [-w WORKERS] [--verbose] [-o {json,csv,txt}]
               [-f FILE] [--no-banner] [--quiet] [--list]

ReconX - All-in-One OSINT Suite

Target Options:
  -u, --username   Search for a username across platforms
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

Both legacy flags and subcommands are supported:
# Legacy syntax
reconx -u johndoe
reconx -d example.com
reconx -i 8.8.8.8

# Modern syntax
reconx username johndoe
reconx domain example.com
reconx ip 8.8.8.8
reconx list

⚠️ Disclaimer
​ReconX is intended for educational purposes and authorized security testing only.
The authors assume no liability and are not responsible for any misuse or damage
caused by this program. Always ensure you have proper authorization before
conducting reconnaissance on any target.

​🤝 Contributing
​Contributions are welcome! Feel free to open a Pull Request.

​📄 License
​This project is licensed under the MIT License - see the LICENSE file for details.
Made with ❤️ by jude84162-sys

