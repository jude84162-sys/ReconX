#!/usr/bin/env python3
"""
Public Social Media OSINT Tool
Gathers only publicly available information about Instagram/Facebook accounts.

No login. No API keys. No external dependencies (uses urllib only).
"""

import re
import json
import ssl
import logging
import urllib.request
import urllib.error
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger("ReconX.social_media")


# ============================================================
# HTTP Helper
# ============================================================

def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, timeout=15, headers=None):
    """Fetch URL. Returns (status, body)."""
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/json,*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
    }
    if headers:
        default_headers.update(headers)

    try:
        req = urllib.request.Request(url, headers=default_headers)
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as r:
            return r.status, r.read(500000).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(50000).decode("utf-8", errors="ignore")
        except Exception:
            return e.code, ""
    except Exception as e:
        logger.debug(f"Fetch error for {url}: {e}")
        return None, None


# ============================================================
# Main Class
# ============================================================

class SocialMediaOSINT:
    """Gathers public info about social media accounts."""

    def __init__(self):
        self.results = {}

    # ------------------------------------------------------------
    # Instagram
    # ------------------------------------------------------------

    def check_instagram_username(self, username: str) -> Dict:
        """Check if Instagram username exists (public info only)."""
        url = f"https://www.instagram.com/{username}/"
        result = {
            "exists": False,
            "url": url,
            "public_info": {},
            "error": None,
        }

        status, body = _fetch(url, timeout=15)

        if status is None:
            result["error"] = "connection_failed"
            return result

        if status == 404:
            result["error"] = "Account not found"
            return result

        if status == 200 and body:
            # Detect "not found" pages
            if "Sorry, this page isn't available" in body:
                result["error"] = "Account not found"
                return result

            # Extract meta tags
            meta_tags = re.findall(
                r'<meta[^>]+(?:property|name)=["\']([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']',
                body
            )

            info = {}
            for tag, content in meta_tags:
                if "og:" in tag or "twitter:" in tag:
                    info[tag] = content

            # Parse followers/following/posts from description
            og_desc = info.get("og:description", "")
            followers = self._parse_stat(og_desc, "Followers")
            following = self._parse_stat(og_desc, "Following")
            posts = self._parse_stat(og_desc, "Posts")

            if info:
                result["exists"] = True
                result["public_info"] = info
                result["stats"] = {
                    "followers": followers,
                    "following": following,
                    "posts": posts,
                    "name": info.get("og:title", "").split("•")[0].split("(")[0].strip(),
                    "bio": og_desc[:200] if og_desc else None,
                    "profile_pic": info.get("og:image"),
                }
        else:
            result["error"] = f"Status: {status}"

        return result

    # ------------------------------------------------------------
    # Facebook
    # ------------------------------------------------------------

    def check_facebook_username(self, username: str) -> Dict:
        """Check if Facebook username exists (public info only)."""
        url = f"https://www.facebook.com/{username}"
        result = {
            "exists": False,
            "url": url,
            "public_info": {},
            "error": None,
        }

        status, body = _fetch(url, timeout=15)

        if status is None:
            result["error"] = "connection_failed"
            return result

        if status == 200 and body:
            # Detect "not found" pages
            not_found_markers = [
                "Page Not Found",
                "content isn't available",
                "this content isn't available",
            ]
            if any(marker in body for marker in not_found_markers):
                result["error"] = "Account not found or private"
                return result

            # Extract meta tags
            meta_tags = re.findall(
                r'<meta[^>]+(?:property|name)=["\']([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']',
                body
            )

            info = {}
            for tag, content in meta_tags:
                if "og:" in tag or "twitter:" in tag:
                    info[tag] = content

            if info:
                result["exists"] = True
                result["public_info"] = info
        else:
            result["error"] = f"Status: {status}"

        return result

    # ------------------------------------------------------------
    # Search public posts (via Google + DDG)
    # ------------------------------------------------------------

    def search_public_posts(self, username: str) -> List[Dict]:
        """Search for public mentions of username."""
        results = []

        # Method 1: Google search
        google_url = (
            f"https://www.google.com/search?"
            f"q=site%3Ainstagram.com+%22{username}%22"
        )
        status, body = _fetch(google_url, timeout=15)

        if body:
            # Extract Instagram URLs
            urls = re.findall(
                r'https?://[^\s<>"]+instagram\.com[^\s<>"]*',
                body
            )
            for url in set(urls[:10]):
                results.append({
                    "type": "search_result",
                    "source": "Google",
                    "url": url,
                })

        # Method 2: DuckDuckGo
        ddg_url = (
            f"https://html.duckduckgo.com/html/?"
            f"q=site%3Ainstagram.com+%22{username}%22"
        )
        status, body = _fetch(ddg_url, timeout=15)

        if body:
            urls = re.findall(
                r'https?://[^\s<>"]+instagram\.com[^\s<>"]*',
                body
            )
            for url in set(urls[:10]):
                results.append({
                    "type": "search_result",
                    "source": "DuckDuckGo",
                    "url": url,
                })

        return results

    # ------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------

    def _parse_stat(self, text: str, label: str) -> Optional[int]:
        """Parse 'Followers, 1,234' format."""
        try:
            pattern = rf"{label},?\s*([\d,]+)"
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return int(match.group(1).replace(",", ""))
        except Exception:
            pass
        return None

    def _clean_html(self, text: str) -> str:
        """Strip HTML tags."""
        text = re.sub(r"<[^>]+>", "", text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()


# ============================================================
# Report
# ============================================================

def print_social_media_report(result):
    print("\n" + "=" * 70)
    print("  Public Social Media OSINT - ReconX")
    print("=" * 70)

    username = result.get("username", "?")
    print(f"\n[*] Username: {username}")

    # Instagram
    ig = result.get("instagram", {})
    if ig.get("exists"):
        print(f"\n[+] ✓ Instagram: EXISTS")
        print(f"    URL: {ig['url']}")
        stats = ig.get("stats", {})
        if stats.get("name"):
            print(f"    Name: {stats['name']}")
        if stats.get("followers"):
            print(f"    Followers: {stats['followers']:,}")
        if stats.get("following"):
            print(f"    Following: {stats['following']:,}")
        if stats.get("posts"):
            print(f"    Posts: {stats['posts']:,}")
        if stats.get("bio"):
            print(f"    Bio: {stats['bio'][:150]}")
    else:
        print(f"\n[-] ✗ Instagram: {ig.get('error', 'Not found')}")

    # Facebook
    fb = result.get("facebook", {})
    if fb.get("exists"):
        print(f"\n[+] ✓ Facebook: EXISTS")
        print(f"    URL: {fb['url']}")
        info = fb.get("public_info", {})
        title = info.get("og:title", "")
        desc = info.get("og:description", "")
        if title:
            print(f"    Title: {title[:100]}")
        if desc:
            print(f"    Description: {desc[:150]}")
    else:
        print(f"\n[-] ✗ Facebook: {fb.get('error', 'Not found')}")

    # Public posts
    posts = result.get("public_posts", [])
    if posts:
        print(f"\n[+] Public mentions ({len(posts)}):")
        seen = set()
        for p in posts[:10]:
            url = p.get("url")
            if url and url not in seen:
                seen.add(url)
                print(f"    • [{p.get('source', '?')}] {url}")
    else:
        print(f"\n[-] No public mentions found")

    print("\n" + "=" * 70)
    print("  [!] Note: Only PUBLIC information was gathered.")
    print("  [!] Private accounts cannot be accessed.")
    print("=" * 70 + "\n")


# ============================================================
# Main
# ============================================================

def run_social_media_osint(username):
    """Main entry point."""
    tool = SocialMediaOSINT()

    result = {
        "timestamp": datetime.now().isoformat(),
        "username": username,
    }

    print(f"\n[*] Checking '{username}' on Instagram...")
    result["instagram"] = tool.check_instagram_username(username)

    print(f"[*] Checking '{username}' on Facebook...")
    result["facebook"] = tool.check_facebook_username(username)

    print(f"[*] Searching for public mentions...")
    result["public_posts"] = tool.search_public_posts(username)

    result["summary"] = {
        "instagram_exists": result["instagram"].get("exists", False),
        "facebook_exists": result["facebook"].get("exists", False),
        "public_mentions": len(result["public_posts"]),
    }

    return result


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.social_media_osint <username>")
        sys.exit(1)

    username = sys.argv[1]
    result = run_social_media_osint(username)
    print_social_media_report(result)
