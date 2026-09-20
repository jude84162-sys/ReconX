#!/usr/bin/env python3
"""
CB-UserHunter Clone
Username OSINT across 100+ platforms without external dependencies.
"""

import os
import sys
import re
import json
import ssl
import socket
import argparse
import logging
import concurrent.futures
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from pathlib import Path

# ============================================================
# Colors
# ============================================================

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


# ============================================================
# Platform Database — 100+ sites
# ============================================================

PLATFORMS = {
    # === Social Media ===
    "Facebook":       {"url": "https://www.facebook.com/{}",           "type": "social",   "method": "status"},
    "Twitter/X":      {"url": "https://nitter.net/{}",                 "type": "social",   "method": "content", "not_found": ["User not found", "doesn't exist"]},
    "Instagram":      {"url": "https://www.instagram.com/{}/",         "type": "social",   "method": "content", "not_found": ["Sorry, this page isn't available"]},
    "Snapchat":       {"url": "https://www.snapchat.com/add/{}",       "type": "social",   "method": "status"},
    "TikTok":         {"url": "https://www.tiktok.com/@{}",            "type": "social",   "method": "content", "not_found": ["Couldn't find this account"]},
    "Pinterest":      {"url": "https://www.pinterest.com/{}/",         "type": "social",   "method": "content", "not_found": ["User not found"]},
    "Tumblr":         {"url": "https://{}.tumblr.com",                 "type": "social",   "method": "status"},
    "Reddit":         {"url": "https://www.reddit.com/user/{}/about.json", "type": "social", "method": "content", "not_found": ["\"error\": 404", "USER_DOESNT_EXIST"]},
    "Mastodon":       {"url": "https://mastodon.social/@{}",           "type": "social",   "method": "status"},
    "VK":             {"url": "https://vk.com/{}",                     "type": "social",   "method": "status"},
    "OK.ru":          {"url": "https://ok.ru/{}",                      "type": "social",   "method": "status"},
    "Weibo":          {"url": "https://weibo.com/{}",                  "type": "social",   "method": "status"},
    "Quora":          {"url": "https://www.quora.com/profile/{}",      "type": "social",   "method": "status"},
    "Minds":          {"url": "https://www.minds.com/{}",              "type": "social",   "method": "status"},
    "Bumble":         {"url": "https://bumble.com/en/{}",              "type": "social",   "method": "status"},

    # === Developer ===
    "GitHub":         {"url": "https://github.com/{}",                 "type": "dev",      "method": "content", "not_found": ["Not Found", "404"]},
    "GitLab":         {"url": "https://gitlab.com/{}",                 "type": "dev",      "method": "status"},
    "Bitbucket":      {"url": "https://bitbucket.org/{}/",             "type": "dev",      "method": "status"},
    "StackOverflow":  {"url": "https://stackoverflow.com/users/filter?search={}", "type": "dev", "method": "status"},
    "Dev.to":         {"url": "https://dev.to/{}",                     "type": "dev",      "method": "content", "not_found": ["404", "not found"]},
    "Hashnode":       {"url": "https://hashnode.com/@{}",              "type": "dev",      "method": "status"},
    "CodePen":        {"url": "https://codepen.io/{}",                 "type": "dev",      "method": "content", "not_found": ["404", "not found"]},
    "Replit":         {"url": "https://replit.com/@{}",                "type": "dev",      "method": "status"},
    "SourceForge":    {"url": "https://sourceforge.net/u/{}/profile",  "type": "dev",      "method": "status"},
    "HackerNews":     {"url": "https://news.ycombinator.com/user?id={}","type": "dev",     "method": "content", "not_found": ["No such user"]},
    "HackerOne":      {"url": "https://hackerone.com/{}",              "type": "dev",      "method": "status"},
    "Bugcrowd":       {"url": "https://bugcrowd.com/{}",               "type": "dev",      "method": "status"},
    "Keybase":        {"url": "https://keybase.io/{}",                 "type": "dev",      "method": "content", "not_found": ["not found"]},
    "Gitea":          {"url": "https://gitea.com/{}",                  "type": "dev",      "method": "status"},
    "Launchpad":      {"url": "https://launchpad.net/~{}",             "type": "dev",      "method": "status"},
    "DockerHub":      {"url": "https://hub.docker.com/u/{}",           "type": "dev",      "method": "status"},
    "NPM":            {"url": "https://www.npmjs.com/~{}",             "type": "dev",      "method": "status"},
    "PyPI":           {"url": "https://pypi.org/user/{}",              "type": "dev",      "method": "status"},
    "Crates.io":      {"url": "https://crates.io/users/{}",            "type": "dev",      "method": "status"},
    "Nuget":          {"url": "https://www.nuget.org/profiles/{}",     "type": "dev",      "method": "status"},
    "Packagist":      {"url": "https://packagist.org/users/{}/",       "type": "dev",      "method": "status"},
    "Kaggle":         {"url": "https://www.kaggle.com/{}",             "type": "dev",      "method": "status"},
    "LeetCode":       {"url": "https://leetcode.com/{}/",              "type": "dev",      "method": "status"},
    "HackerRank":     {"url": "https://www.hackerrank.com/{}",         "type": "dev",      "method": "status"},
    "Codewars":       {"url": "https://www.codewars.com/users/{}",     "type": "dev",      "method": "status"},

    # === Gaming ===
    "Steam":          {"url": "https://steamcommunity.com/id/{}",      "type": "gaming",   "method": "content", "not_found": ["profile could not be found"]},
    "Twitch":         {"url": "https://www.twitch.tv/{}",              "type": "gaming",   "method": "content", "not_found": ["time machine"]},
    "Xbox":           {"url": "https://xboxgamertag.com/search/{}",    "type": "gaming",   "method": "status"},
    "PSN":            {"url": "https://psnprofiles.com/{}",            "type": "gaming",   "method": "status"},
    "Roblox":         {"url": "https://www.roblox.com/user.aspx?username={}", "type": "gaming", "method": "status"},
    "Minecraft":      {"url": "https://namemc.com/profile/{}",         "type": "gaming",   "method": "status"},
    "Discord.bio":    {"url": "https://discord.bio/p/{}",              "type": "gaming",   "method": "status"},
    "Epic Games":     {"url": "https://fortnitetracker.com/profile/all/{}", "type": "gaming", "method": "status"},
    "Chess.com":      {"url": "https://www.chess.com/member/{}",       "type": "gaming",   "method": "status"},
    "Lichess":        {"url": "https://lichess.org/@/{}",              "type": "gaming",   "method": "status"},
    "Faceit":         {"url": "https://www.faceit.com/en/players/{}",  "type": "gaming",   "method": "status"},
    "Speedrun":       {"url": "https://www.speedrun.com/user/{}",      "type": "gaming",   "method": "status"},

    # === Music / Creator ===
    "YouTube":        {"url": "https://www.youtube.com/@{}",           "type": "music",    "method": "content", "not_found": ["This page isn't available"]},
    "Spotify":        {"url": "https://open.spotify.com/user/{}",      "type": "music",    "method": "content", "not_found": ["Page not found"]},
    "SoundCloud":     {"url": "https://soundcloud.com/{}",             "type": "music",    "method": "content", "not_found": ["We can't find that user"]},
    "Bandcamp":       {"url": "https://bandcamp.com/{}",               "type": "music",    "method": "status"},
    "Mixcloud":       {"url": "https://www.mixcloud.com/{}/",          "type": "music",    "method": "status"},
    "Last.fm":        {"url": "https://www.last.fm/user/{}",           "type": "music",    "method": "status"},
    "Vimeo":          {"url": "https://vimeo.com/{}",                  "type": "music",    "method": "status"},
    "Dailymotion":    {"url": "https://www.dailymotion.com/{}",        "type": "music",    "method": "status"},
    "Rumble":         {"url": "https://rumble.com/user/{}",            "type": "music",    "method": "status"},
    "Odysee":         {"url": "https://odysee.com/@{}",                "type": "music",    "method": "status"},
    "Bitchute":       {"url": "https://www.bitchute.com/channel/{}",   "type": "music",    "method": "status"},
    "Patreon":        {"url": "https://www.patreon.com/{}",            "type": "music",    "method": "status"},
    "Ko-fi":          {"url": "https://ko-fi.com/{}",                  "type": "music",    "method": "status"},
    "BuyMeACoffee":   {"url": "https://www.buymeacoffee.com/{}",       "type": "music",    "method": "status"},

    # === Crypto ===
    "BitcoinTalk":    {"url": "https://bitcointalk.org/index.php?action=profile;u={}", "type": "crypto", "method": "status"},
    "OpenSea":        {"url": "https://opensea.io/{}",                 "type": "crypto",   "method": "status"},
    "Rarible":        {"url": "https://rarible.com/{}",                "type": "crypto",   "method": "status"},
    "Foundation":     {"url": "https://foundation.app/@{}",            "type": "crypto",   "method": "status"},
    "CoinMarketCap":  {"url": "https://coinmarketcap.com/community/profile/{}", "type": "crypto", "method": "status"},
    "BscScan":        {"url": "https://bscscan.com/address/{}",        "type": "crypto",   "method": "status"},
    "Etherscan":      {"url": "https://etherscan.io/address/{}",       "type": "crypto",   "method": "status"},

    # === Blogging / Community ===
    "Medium":         {"url": "https://medium.com/@{}",                "type": "blog",     "method": "content", "not_found": ["404", "Out of nothing"]},
    "Substack":       {"url": "https://{}.substack.com",               "type": "blog",     "method": "status"},
    "Blogger":        {"url": "https://{}.blogspot.com",               "type": "blog",     "method": "status"},
    "WordPress":      {"url": "https://{}.wordpress.com",              "type": "blog",     "method": "status"},
    "Ghost":          {"url": "https://{}.ghost.io",                   "type": "blog",     "method": "status"},
    "Disqus":         {"url": "https://disqus.com/by/{}/",             "type": "blog",     "method": "status"},
    "About.me":       {"url": "https://about.me/{}",                   "type": "blog",     "method": "status"},
    "Linktree":       {"url": "https://linktr.ee/{}",                  "type": "blog",     "method": "status"},
    "Beacons":        {"url": "https://beacons.ai/{}",                 "type": "blog",     "method": "status"},
    "Carrd":          {"url": "https://{}.carrd.co",                   "type": "blog",     "method": "status"},

    # === Cybersecurity ===
    "HackTheBox":     {"url": "https://app.hackthebox.com/profile/{}", "type": "cyber",   "method": "status"},
    "TryHackMe":      {"url": "https://tryhackme.com/p/{}",            "type": "cyber",   "method": "status"},
    "VulnHub":        {"url": "https://www.vulnhub.com/author/{}/",    "type": "cyber",   "method": "status"},
    "CVE":            {"url": "https://www.cve.org/",                  "type": "cyber",   "method": "status"},
    "ExploitDB":      {"url": "https://www.exploit-db.com/author?author={}", "type": "cyber", "method": "status"},
    "SecurityFocus":  {"url": "https://www.securityfocus.com/",        "type": "cyber",   "method": "status"},
    "Reddit NetSec":  {"url": "https://www.reddit.com/r/netsec/search?q=author%3A{}", "type": "cyber", "method": "status"},
    "XSS.is":         {"url": "https://xss.is/members/?username={}",   "type": "cyber",   "method": "status"},
    "Exploit.in":     {"url": "https://exploit.in/user/{}",            "type": "cyber",   "method": "status"},
    "Nulled":         {"url": "https://nulled.to/member.php?username={}","type": "cyber",  "method": "status"},

    # === Design / Creative ===
    "Behance":        {"url": "https://www.behance.net/{}",            "type": "design",   "method": "content", "not_found": ["Sorry, we couldn't find"]},
    "Dribbble":       {"url": "https://dribbble.com/{}",               "type": "design",   "method": "content", "not_found": ["404", "not found"]},
    "Flickr":         {"url": "https://www.flickr.com/people/{}",      "type": "design",   "method": "content", "not_found": ["404"]},
    "DeviantArt":     {"url": "https://www.deviantart.com/{}",         "type": "design",   "method": "status"},
    "ArtStation":     {"url": "https://www.artstation.com/{}",         "type": "design",   "method": "status"},
    "500px":          {"url": "https://500px.com/p/{}",                "type": "design",   "method": "status"},
    "Unsplash":       {"url": "https://unsplash.com/@{}",              "type": "design",   "method": "status"},

    # === Professional ===
    "LinkedIn":       {"url": "https://www.linkedin.com/in/{}",        "type": "prof",     "method": "status"},
    "AngelList":      {"url": "https://angel.co/u/{}",                 "type": "prof",     "method": "status"},
    "Crunchbase":     {"url": "https://www.crunchbase.com/person/{}",  "type": "prof",     "method": "status"},
    "ProductHunt":    {"url": "https://www.producthunt.com/@{}",       "type": "prof",     "method": "content", "not_found": ["404", "not found"]},
    "Upwork":         {"url": "https://www.upwork.com/freelancers/~{}","type": "prof",     "method": "status"},
    "Fiverr":         {"url": "https://www.fiverr.com/{}",             "type": "prof",     "method": "status"},
    "Freelancer":     {"url": "https://www.freelancer.com/u/{}",       "type": "prof",     "method": "status"},
    "Toptal":         {"url": "https://www.toptal.com/resume/{}",      "type": "prof",     "method": "status"},

    # === Q&A / Forums ===
    "AskFM":          {"url": "https://ask.fm/{}",                     "type": "forum",    "method": "status"},
    "Scribd":         {"url": "https://www.scribd.com/{}",             "type": "forum",    "method": "status"},
    "Slideshare":     {"url": "https://www.slideshare.net/{}",         "type": "forum",    "method": "status"},
    "Issuu":          {"url": "https://issuu.com/{}",                  "type": "forum",    "method": "status"},
    "Wattpad":        {"url": "https://www.wattpad.com/user/{}",       "type": "forum",    "method": "status"},
    "Goodreads":      {"url": "https://www.goodreads.com/{}",          "type": "forum",    "method": "status"},
    "Librarything":   {"url": "https://www.librarything.com/profile/{}","type": "forum",   "method": "status"},

    # === Shopping / Marketplace ===
    "Etsy":           {"url": "https://www.etsy.com/shop/{}",          "type": "shop",     "method": "status"},
    "eBay":           {"url": "https://www.ebay.com/usr/{}",           "type": "shop",     "method": "status"},
    "Amazon":         {"url": "https://www.amazon.com/gp/profile/amzn1.account.{}", "type": "shop", "method": "status"},
    "AliExpress":     {"url": "https://www.aliexpress.com/store/{}",   "type": "shop",     "method": "status"},

    # === Other ===
    "Gravatar":       {"url": "https://en.gravatar.com/{}",            "type": "other",    "method": "status"},
    "Imgur":          {"url": "https://imgur.com/user/{}",             "type": "other",    "method": "status"},
    "Giphy":          {"url": "https://giphy.com/{}",                  "type": "other",    "method": "status"},
    "Tenor":          {"url": "https://tenor.com/users/{}",            "type": "other",    "method": "status"},
    "Strava":         {"url": "https://www.strava.com/athletes/{}",    "type": "other",    "method": "status"},
    "Duolingo":       {"url": "https://www.duolingo.com/profile/{}",   "type": "other",    "method": "status"},
    "Ravelry":        {"url": "https://www.ravelry.com/people/{}",     "type": "other",    "method": "status"},
    "Untappd":        {"url": "https://untappd.com/user/{}",           "type": "other",    "method": "status"},
}


# ============================================================
# HTTP Fetcher
# ============================================================

def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, timeout=8):
    """Fetch URL and return (status, body)."""
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/json,*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as r:
            return r.status, r.read(30000).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(10000).decode("utf-8", errors="ignore")
        except Exception:
            return e.code, ""
    except (socket.timeout, urllib.error.URLError):
        return None, None
    except Exception:
        return None, None


# ============================================================
# Check Single Platform
# ============================================================

def _check_platform(username, platform, config):
    """Check if username exists on a platform."""
    url = config["url"].format(username)
    method = config.get("method", "status")

    status, body = _fetch(url, timeout=8)

    result = {
        "platform": platform,
        "type": config.get("type", "other"),
        "url": url,
        "status": None,
        "reason": None,
    }

    if status is None:
        result["status"] = "error"
        result["reason"] = "connection_failed"
        return result

    # Content-based check
    if method == "content" and body:
        body_lower = body.lower()

        # Check for "not found" markers
        not_found_markers = config.get("not_found", [])
        for marker in not_found_markers:
            if marker.lower() in body_lower:
                result["status"] = "not_found"
                result["reason"] = f"marker: {marker}"
                return result

    # Status-based
    if status == 200:
        result["status"] = "found"
        result["reason"] = "http_200"
    elif status == 404:
        result["status"] = "not_found"
        result["reason"] = "http_404"
    elif status == 403:
        result["status"] = "unknown"
        result["reason"] = "http_403 (blocked)"
    elif status == 429:
        result["status"] = "unknown"
        result["reason"] = "rate_limited"
    elif 300 <= status < 400:
        result["status"] = "unknown"
        result["reason"] = f"http_{status}_redirect"
    else:
        result["status"] = "unknown"
        result["reason"] = f"http_{status}"

    return result


# ============================================================
# Main Search
# ============================================================

def search_username(username, workers=30, filter_type=None, verbose=False):
    """Search username across all platforms."""
    results = {
        "timestamp": datetime.now().isoformat(),
        "username": username,
        "found": [],
        "not_found": [],
        "unknown": [],
        "errors": [],
        "total_platforms": len(PLATFORMS),
        "duration": 0,
    }

    start = datetime.now()

    # Filter by type
    platforms_to_check = PLATFORMS
    if filter_type:
        platforms_to_check = {
            k: v for k, v in PLATFORMS.items()
            if v.get("type") == filter_type
        }

    print(f"\n  {C.CYAN}[*]{C.RESET} Searching '{username}' across "
          f"{len(platforms_to_check)} platforms...")
    print(f"  {C.GRAY}(this may take 30-60 seconds){C.RESET}\n")

    completed = 0
    total = len(platforms_to_check)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(_check_platform, username, name, config): name
            for name, config in platforms_to_check.items()
        }

        for future in concurrent.futures.as_completed(futures):
            completed += 1

            # Progress
            if completed % 10 == 0 or completed == total:
                pct = (completed / total) * 100
                sys.stdout.write(
                    f"\r  {C.CYAN}[{completed}/{total}]{C.RESET} {pct:.0f}%"
                )
                sys.stdout.flush()

            platform = futures[future]
            try:
                r = future.result(timeout=15)

                if r["status"] == "found":
                    results["found"].append(r)
                    if verbose:
                        print(f"\n  {C.GREEN}[+]{C.RESET} {r['platform']}")
                elif r["status"] == "not_found":
                    results["not_found"].append(r["platform"])
                elif r["status"] == "unknown":
                    results["unknown"].append(r)
                else:
                    results["errors"].append(r)
            except Exception as e:
                results["errors"].append({"platform": platform, "error": str(e)})

    print()
    results["duration"] = (datetime.now() - start).total_seconds()

    # Sort
    results["found"].sort(key=lambda x: (x["type"], x["platform"]))

    return results


# ============================================================
# Google Dorks
# ============================================================

def generate_dorks(username):
    """Generate Google Dorks for a username."""
    return [
        f'"{username}"',
        f'"{username}" site:linkedin.com',
        f'"{username}" site:twitter.com OR site:x.com',
        f'"{username}" site:facebook.com',
        f'"{username}" site:github.com',
        f'"{username}" site:instagram.com',
        f'"{username}" email',
        f'"{username}" @gmail.com',
        f'"{username}" "full name"',
        f'"{username}" filetype:pdf',
        f'"{username}" inurl:profile',
        f'"{username}" -site:example.com',
    ]


# ============================================================
# Report Printer
# ============================================================

def print_report(results, show_dorks=True):
    """Pretty-print results."""
    found = results["found"]
    not_found = results["not_found"]
    unknown = results["unknown"]
    errors = results["errors"]

    print("\n" + "=" * 70)
    print(f"  {C.BOLD}CB-UserHunter Clone — Report{C.RESET}")
    print("=" * 70)

    print(f"\n  {C.CYAN}Username:{C.RESET}        {results['username']}")
    print(f"  {C.CYAN}Platforms:{C.RESET}       {results['total_platforms']}")
    print(f"  {C.CYAN}Duration:{C.RESET}        {results['duration']:.1f}s")
    print(f"  {C.GREEN}Found:{C.RESET}           {len(found)}")
    print(f"  {C.GRAY}Not found:{C.RESET}       {len(not_found)}")
    print(f"  {C.YELLOW}Unknown:{C.RESET}         {len(unknown)}")
    print(f"  {C.RED}Errors:{C.RESET}          {len(errors)}")

    if found:
        print(f"\n  {C.GREEN}{C.BOLD}═══ FOUND ON ═══{C.RESET}\n")

        # Group by type
        by_type = {}
        for item in found:
            by_type.setdefault(item["type"], []).append(item)

        for t in sorted(by_type.keys()):
            print(f"  {C.BOLD}[{t.upper()}]{C.RESET}")
            for item in by_type[t]:
                print(f"    {C.GREEN}✓{C.RESET} {item['platform']:<20} {item['url']}")
            print()

    if show_dorks:
        print(f"  {C.BOLD}═══ GOOGLE DORKS ═══{C.RESET}\n")
        for dork in generate_dorks(results["username"]):
            encoded = urllib.parse.quote(dork)
            print(f"    • {dork}")
            print(f"      {C.GRAY}https://www.google.com/search?q={encoded}{C.RESET}")
        print()

    print("=" * 70 + "\n")


def save_report(results, output_dir="outputs"):
    """Save JSON report."""
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cb_userhunter_{results['username']}_{ts}.json"
    filepath = path / filename

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)

    print(f"  {C.GREEN}[✓]{C.RESET} Report saved: {filepath}\n")
    return filepath


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="CB-UserHunter Clone — Username OSINT (no install needed)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cb_userhunter.py johndoe
  python cb_userhunter.py torvalds --type dev
  python cb_userhunter.py johndoe -o report.json
  python cb_userhunter.py johndoe --workers 50
        """
    )

    parser.add_argument("username", help="Username to search")
    parser.add_argument("--type", choices=list(set(v["type"] for v in PLATFORMS.values())),
                        help="Filter by platform type")
    parser.add_argument("--workers", type=int, default=30, help="Concurrent workers (default 30)")
    parser.add_argument("--output", "-o", default="outputs", help="Output directory")
    parser.add_argument("--no-dorks", action="store_true", help="Hide Google Dorks")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--json-only", action="store_true", help="Only save JSON, no report")
    parser.add_argument("--version", action="version", version="CB-UserHunter Clone v1.0.0")

    args = parser.parse_args()

    # Banner
    print(f"""{C.CYAN}
╔═══════════════════════════════════════════════════════════════╗
║  CB-UserHunter Clone — Username OSINT                        ║
║  {len(PLATFORMS)} platforms • Google Dorks • No installation needed    ║
╚═══════════════════════════════════════════════════════════════╝{C.RESET}""")

    # Search
    results = search_username(
        args.username,
        workers=args.workers,
        filter_type=args.type,
        verbose=args.verbose,
    )

    # Print report
    if not args.json_only:
        print_report(results, show_dorks=not args.no_dorks)

    # Save
    save_report(results, args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}  [!] Interrupted{C.RESET}\n")
        sys.exit(130)
