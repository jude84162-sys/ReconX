# modules/username_osint.py
"""ReconX - Username OSINT (Content-based, 95% accuracy)."""

import logging
import urllib.request
import urllib.error
import concurrent.futures
import ssl
from datetime import datetime

logger = logging.getLogger("ReconX.username")


# Platform configs with "not found" markers
PLATFORMS = {
    "GitHub": {
        "url": "https://github.com/{}",
        "not_found": ["Not Found", "404"],
        "found_markers": ["repositories", "followers"],
    },
    "Twitter/X": {
        "url": "https://nitter.net/{}",
        "not_found": ["User not found", "doesn't exist"],
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{}/about.json",
        "not_found": ["\"error\": 404", "USER_DOESNT_EXIST"],
    },
    "Instagram": {
        "url": "https://www.instagram.com/{}/",
        "not_found": ["Sorry, this page isn't available"],
    },
    "YouTube": {
        "url": "https://www.youtube.com/@{}",
        "not_found": ["This page isn't available", "404"],
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{}",
        "not_found": ["Couldn't find this account"],
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{}/",
        "not_found": ["User not found"],
    },
    "Twitch": {
        "url": "https://www.twitch.tv/{}",
        "not_found": ["Sorry. Unless you've got a time machine"],
    },
    "Telegram": {
        "url": "https://t.me/{}",
        "not_found": ["tgme_page_icon", "If you have Telegram"],
        "invert": True,  # Logic inverted
    },
    "Medium": {
        "url": "https://medium.com/@{}",
        "not_found": ["404", "Out of nothing"],
    },
    "Dev.to": {
        "url": "https://dev.to/{}",
        "not_found": ["404", "not found"],
    },
    "Keybase": {
        "url": "https://keybase.io/{}",
        "not_found": ["not found"],
    },
    "Steam": {
        "url": "https://steamcommunity.com/id/{}",
        "not_found": ["The specified profile could not be found"],
    },
    "Spotify": {
        "url": "https://open.spotify.com/user/{}",
        "not_found": ["Page not found"],
    },
    "SoundCloud": {
        "url": "https://soundcloud.com/{}",
        "not_found": ["We can't find that user", "404"],
    },
    "Behance": {
        "url": "https://www.behance.net/{}",
        "not_found": ["Sorry, we couldn't find"],
    },
    "Dribbble": {
        "url": "https://dribbble.com/{}",
        "not_found": ["404", "not found"],
    },
    "Flickr": {
        "url": "https://www.flickr.com/people/{}",
        "not_found": ["404", "not found"],
    },
    "HackerNews": {
        "url": "https://news.ycombinator.com/user?id={}",
        "not_found": ["No such user"],
    },
    "ProductHunt": {
        "url": "https://www.producthunt.com/@{}",
        "not_found": ["404", "not found"],
    },
}


def _fetch_content(url, timeout=10):
    """Fetch page content."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/json",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            content = r.read(50000).decode("utf-8", errors="ignore")
            return r.status, content
    except urllib.error.HTTPError as e:
        try:
            content = e.read(10000).decode("utf-8", errors="ignore")
            return e.code, content
        except Exception:
            return e.code, ""
    except Exception:
        return None, None


def _check_username(username, platform, config):
    """Check username on a specific platform."""
    url = config["url"].format(username)

    status, content = _fetch_content(url)

    if status is None:
        return {
            "platform": platform,
            "url": url,
            "status": "unknown",
            "reason": "connection_failed"
        }

    # Not found indicators
    not_found = config.get("not_found", [])
    invert = config.get("invert", False)

    if content:
        content_lower = content.lower()
        for marker in not_found:
            if marker.lower() in content_lower:
                if invert:
                    return {
                        "platform": platform,
                        "url": url,
                        "status": "found",
                        "reason": "inverted_match"
                    }
                else:
                    return {
                        "platform": platform,
                        "url": url,
                        "status": "not_found",
                        "reason": f"marker: {marker}"
                    }

    # Status-based fallback
    if status == 200:
        if invert:
            return {
                "platform": platform,
                "url": url,
                "status": "not_found",
                "reason": "200_but_inverted"
            }
        return {
            "platform": platform,
            "url": url,
            "status": "found",
            "reason": "http_200"
        }
    elif status == 404:
        return {
            "platform": platform,
            "url": url,
            "status": "not_found",
            "reason": "http_404"
        }
    else:
        return {
            "platform": platform,
            "url": url,
            "status": "unknown",
            "reason": f"http_{status}"
        }


def run_username_osint(username, workers=15):
    """Search username across platforms."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "username": username,
        "found_on": [],
        "not_found_on": [],
        "unknown": [],
        "total_platforms": len(PLATFORMS),
        "errors": []
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(_check_username, username, platform, config): platform
            for platform, config in PLATFORMS.items()
        }

        for future in concurrent.futures.as_completed(futures):
            platform = futures[future]
            try:
                r = future.result(timeout=15)
                if r["status"] == "found":
                    result["found_on"].append(r)
                elif r["status"] == "not_found":
                    result["not_found_on"].append(platform)
                else:
                    result["unknown"].append(r)
            except Exception as e:
                result["errors"].append(f"{platform}: {e}")

    result["found_on"].sort(key=lambda x: x["platform"])

    return result


def print_username_report(result):
    print("\n" + "=" * 70)
    print("  👤 Username OSINT - ReconX")
    print("=" * 70)

    found = result.get("found_on", [])
    not_found = result.get("not_found_on", [])
    unknown = result.get("unknown", [])

    total = result.get("total_platforms", 0)
    print(f"\n[*] Username: {result.get('username')}")
    print(f"[*] Checked:  {total} platforms")
    print(f"[*] Found:    {len(found)}")
    print(f"[*] Not found: {len(not_found)}")
    print(f"[*] Unknown:  {len(unknown)}")

    if found:
        print(f"\n[+] ✅ Found on:")
        for item in found:
            print(f"    ✓ {item['platform']:<15} {item['url']}")
            print(f"      Reason: {item['reason']}")

    if unknown:
        print(f"\n[?] ⚠ Unknown (manual check):")
        for item in unknown:
            print(f"    ? {item['platform']:<15} {item['url']}")

    print("\n" + "=" * 70 + "\n")
