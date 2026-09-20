# modules/social_deep.py
"""ReconX - Social Media Deep Analysis."""

import ssl
import re
import logging
import urllib.request
import urllib.error
from datetime import datetime

logger = logging.getLogger("ReconX.social")


def _fetch(url, timeout=10):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                              "AppleWebKit/537.36 Chrome/120.0.0.0",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read(200000).decode("utf-8", errors="ignore")
    except Exception:
        return None


def run_social_deep(username, platform="github"):
    """Deep social media analysis."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "username": username,
        "platform": platform,
        "profile": {},
        "search_urls": {},
        "indicators": [],
        "summary": {},
        "error": None,
    }

    # Search URLs for all platforms
    result["search_urls"] = {
        "GitHub": f"https://github.com/{username}",
        "Twitter/X": f"https://nitter.net/{username}",
        "Instagram": f"https://www.instagram.com/{username}/",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Facebook": f"https://www.facebook.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "Telegram": f"https://t.me/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}/",
        "Tumblr": f"https://{username}.tumblr.com",
        "Twitch": f"https://www.twitch.tv/{username}",
        "Medium": f"https://medium.com/@{username}",
        "Dev.to": f"https://dev.to/{username}",
        "Keybase": f"https://keybase.io/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
    }

    # Deep dive based on platform
    if platform == "github":
        body = _fetch(f"https://github.com/{username}")
        if body:
            # Extract metadata
            name_match = re.search(r'<span class="p-name[^"]*"[^>]*>([^<]+)</span>', body)
            bio_match = re.search(r'<div class="p-note[^"]*"[^>]*>([^<]+)</div>', body)
            followers_match = re.search(r'(\d+)\s*followers', body)
            repos_match = re.search(r'(\d+)\s*repositories', body)

            result["profile"] = {
                "name": name_match.group(1).strip() if name_match else None,
                "bio": bio_match.group(1).strip()[:200] if bio_match else None,
                "followers": int(followers_match.group(1)) if followers_match else None,
                "repositories": int(repos_match.group(1)) if repos_match else None,
                "url": f"https://github.com/{username}",
            }

            if result["profile"].get("followers") and result["profile"]["followers"] > 1000:
                result["indicators"].append(("INFO", f"Popular account ({result['profile']['followers']} followers)"))

    # Search all platforms
    result["summary"] = {
        "platforms_checked": len(result["search_urls"]),
        "profile_found": bool(result["profile"]),
        "indicators": len(result["indicators"]),
    }

    return result


def print_social_deep_report(result):
    print("\n" + "=" * 70)
    print("  Social Media Deep - ReconX")
    print("=" * 70)

    print(f"\n[*] Username: {result.get('username')}")

    profile = result.get("profile", {})
    if profile:
        print(f"\n[+] Profile ({result.get('platform')}):")
        for k, v in profile.items():
            if v is not None:
                print(f"    {k}: {v}")

    if result.get("indicators"):
        print(f"\n[!] Indicators:")
        for level, reason in result["indicators"]:
            print(f"    [{level}] {reason}")

    print(f"\n[+] Search URLs ({len(result.get('search_urls', {}))} platforms):")
    for name, url in result.get("search_urls", {}).items():
        print(f"    • {name:<12} {url}")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    username = sys.argv[1] if len(sys.argv) > 1 else "torvalds"
    result = run_social_deep(username)
    print_social_deep_report(result)
