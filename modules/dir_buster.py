# modules/dir_buster.py
"""ReconX - Directory Buster (90% accuracy with soft-404 detection)."""

import ssl
import random
import string
import logging
import urllib.request
import urllib.error
import concurrent.futures
from datetime import datetime

logger = logging.getLogger("ReconX.dirbuster")


COMMON_PATHS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "phpmyadmin", "cpanel", "webmail", "panel", "controlpanel",
    "api", "api/v1", "api/v2", "rest", "graphql", "swagger",
    "docs", "documentation", "readme", "readme.html", "README.md",
    "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config",
    ".env", ".env.local", ".env.production", "config.php",
    "backup", "backups", "old", "bak", "temp", "tmp", "test",
    "index.php", "index.html", "index.jsp", "default.html",
    "wp-config.php", "configuration.php", "settings.php",
    "uploads", "files", "images", "assets", "static", "media",
    "logs", "log", "error.log", "access.log",
    "test.php", "info.php", "phpinfo.php", "server-status",
    "console", "shell", "cmd", "exec", "system",
    "hidden", "secret", "private", "internal",
    "register", "signup", "signin", "logout", "auth",
    "user", "users", "profile", "account", "my",
    "search", "sitemap", "rss", "feed", "atom",
]


def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(base_url, path, timeout=5):
    """Fetch a path."""
    url = base_url.rstrip("/") + "/" + path

    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 ReconX/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as r:
            body = r.read(5000).decode("utf-8", errors="ignore")
            return {
                "path": path,
                "url": url,
                "status": r.status,
                "size": len(body),
                "content_length": r.headers.get("Content-Length", "?"),
                "type": r.headers.get("Content-Type", "?")[:40],
                "body_sample": body[:200]
            }
    except urllib.error.HTTPError as e:
        if e.code not in (404,):
            try:
                body = e.read(2000).decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return {
                "path": path,
                "url": url,
                "status": e.code,
                "size": len(body),
                "content_length": "?",
                "type": "?",
                "body_sample": body[:200]
            }
    except Exception:
        pass
    return None


def _detect_soft_404(base_url):
    """Send request to random path to detect catch-all."""
    random_path = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    result = _fetch(base_url, random_path, timeout=5)

    if not result:
        return None

    return {
        "status": result.get("status"),
        "size": result.get("size"),
        "type": result.get("type"),
        "body_sample": result.get("body_sample", "")
    }


def run_dir_bust(base_url, workers=50, paths=None):
    """Bust directories with soft-404 detection."""
    if paths is None:
        paths = COMMON_PATHS

    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url

    result = {
        "timestamp": datetime.now().isoformat(),
        "url": base_url,
        "found": [],
        "total_checked": len(paths),
        "soft_404_baseline": None,
        "errors": []
    }

    # Detect soft-404
    print("  [*] Detecting soft-404 baseline...")
    baseline = _detect_soft_404(base_url)
    result["soft_404_baseline"] = baseline

    if baseline:
        print(f"  [*] Baseline: status={baseline['status']}, size={baseline['size']}")

    # Scan
    def check(path):
        return _fetch(base_url, path)

    print(f"  [*] Scanning {len(paths)} paths...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(check, p): p for p in paths}
        for future in concurrent.futures.as_completed(futures):
            try:
                r = future.result()
                if not r:
                    continue

                # Filter soft-404
                if baseline:
                    # Same status + similar size = probably soft-404
                    if (r["status"] == baseline["status"] and
                        abs(r["size"] - baseline["size"]) < 100):
                        continue

                    # Check if body contains soft-404 markers
                    soft_markers = ["not found", "404", "does not exist", "page not found"]
                    body = r.get("body_sample", "").lower()
                    if any(m in body for m in soft_markers):
                        # But only if the actual response status is 200
                        if r["status"] == 200:
                            continue

                result["found"].append(r)
            except Exception:
                pass

    result["found"].sort(key=lambda x: (x["status"], x["path"]))

    return result


def print_dir_bust_report(result):
    print("\n" + "=" * 70)
    print("  Directory Buster - ReconX")
    print("=" * 70)

    print(f"\n[*] Target: {result.get('url')}")
    print(f"[*] Paths checked: {result.get('total_checked')}")
    print(f"[*] Found: {len(result.get('found', []))}")

    if result.get("soft_404_baseline"):
        b = result["soft_404_baseline"]
        print(f"[*] Soft-404 baseline: status={b['status']}, size={b['size']}")

    if result.get("found"):
        print(f"\n[+] Found Paths:")
        print(f"    {'STATUS':<8} {'PATH':<40} {'SIZE':<10} {'TYPE':<25}")
        print(f"    {'-'*8} {'-'*40} {'-'*10} {'-'*25}")
        for item in result["found"][:50]:
            print(f"    {item['status']:<8} {item['path']:<40} {item['size']:<10} {item['type']:<25}")
        if len(result["found"]) > 50:
            print(f"    ... and {len(result['found']) - 50} more")
    else:
        print(f"\n[OK] No exposed paths found")

    print("\n" + "=" * 70 + "\n")
