# modules/dir_buster.py
"""ReconX - Directory Buster (Enhanced soft-404 detection).
Uses multi-baseline + body hash for accurate filtering.
"""

import ssl
import random
import string
import hashlib
import logging
import urllib.request
import urllib.error
import concurrent.futures
from datetime import datetime

logger = logging.getLogger("ReconX.dirbuster")


# ============================================================
# Wordlist
# ============================================================

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
    ".htaccess", ".htpasswd", ".svn/entries", ".DS_Store",
    "composer.json", "package.json", "yarn.lock",
    "Makefile", "Dockerfile", "docker-compose.yml",
    "web.config", "crossdomain.xml", "clientaccesspolicy.xml",
    "health", "healthz", "status", "ping", "version",
    "metrics", "debug", "trace", "actuator",
    "wp-json/wp/v2/users", "xmlrpc.php",
    "install", "setup", "install.php", "setup.php",
    "phpinfo", "info", "test",
]


# ============================================================
# Config
# ============================================================

SENSITIVE_PATHS = [
    ".env", ".git", ".svn", ".htaccess", ".htpasswd",
    "wp-config", "config.php", "settings.php", "configuration.php",
    "backup", "backups", "old", "bak",
    "phpmyadmin", "admin", "administrator",
    "shell", "cmd", "exec", "console",
    "phpinfo", "info.php", "test.php",
    "docker-compose", "Dockerfile", ".DS_Store",
    "composer.json", "package.json",
]

SOFT_404_MARKERS = [
    "not found",
    "404",
    "page not found",
    "does not exist",
    "doesn't exist",
    "could not be found",
    "page doesn't exist",
    "nothing here",
    "no such file",
    "cannot be found",
    "the requested url was not found",
    "the page you requested",
    "error 404",
    "not available",
    "requested page",
]


def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ============================================================
# HTTP Fetch
# ============================================================

def _fetch(base_url, path, timeout=8, max_body=8000):
    """
    Fetch a path.
    Returns dict with: status, size, hash, type, body_sample, url, redirect
    """
    url = base_url.rstrip("/") + "/" + path.lstrip("/")

    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                              "AppleWebKit/537.36 Chrome/120.0.0.0",
                "Accept": "text/html,*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "close",
            },
        )

        # Don't follow redirects automatically — we want to see them
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(
            NoRedirect,
            urllib.request.HTTPSHandler(context=_make_ctx()),
        )

        try:
            r = opener.open(req, timeout=timeout)
            status = r.status
            headers = dict(r.headers)
            body = r.read(max_body)
        except urllib.error.HTTPError as e:
            status = e.code
            headers = dict(e.headers) if e.headers else {}
            try:
                body = e.read(max_body)
            except Exception:
                body = b""

        body_text = body.decode("utf-8", errors="ignore")
        body_hash = hashlib.md5(body[:5000]).hexdigest()

        return {
            "path": path,
            "url": url,
            "status": status,
            "size": len(body),
            "hash": body_hash,
            "type": headers.get("Content-Type", "?")[:40],
            "server": headers.get("Server", "?")[:40],
            "location": headers.get("Location", "")[:200],
            "body_sample": body_text[:500],
            "body_lower": body_text[:2000].lower(),
            "redirect": 300 <= status < 400,
        }

    except Exception as e:
        logger.debug(f"fetch {url} failed: {e}")
        return None


# ============================================================
# Soft-404 Baseline (multi-probe)
# ============================================================

def _random_path(length=16):
    """Generate random path."""
    return "".join(
        random.choices(string.ascii_lowercase + string.digits, k=length)
    )


def _detect_soft_404(base_url, probes=3):
    """
    Probe with multiple random paths.
    Returns the most common response signature.
    """
    signatures = []

    for i in range(probes):
        rand_path = _random_path(16 + i)
        result = _fetch(base_url, rand_path, timeout=8)

        if result:
            signatures.append({
                "status": result["status"],
                "size": result["size"],
                "hash": result["hash"],
                "type": result["type"],
                "body_lower": result.get("body_lower", ""),
            })

    if not signatures:
        return None

    # If all same hash → strong soft-404
    hashes = [s["hash"] for s in signatures]
    if len(set(hashes)) == 1:
        return {
            "status": signatures[0]["status"],
            "size": signatures[0]["size"],
            "hash": signatures[0]["hash"],
            "type": signatures[0]["type"],
            "consistent": True,
            "probes": len(signatures),
        }

    # Otherwise, take most common status
    statuses = [s["status"] for s in signatures]
    mode_status = max(set(statuses), key=statuses.count)

    # Average size
    sizes = [s["size"] for s in signatures if s["status"] == mode_status]
    avg_size = sum(sizes) / len(sizes) if sizes else 0

    return {
        "status": mode_status,
        "size": int(avg_size),
        "hash": None,
        "type": signatures[0]["type"],
        "consistent": False,
        "probes": len(signatures),
    }


# ============================================================
# Filter Logic
# ============================================================

def _is_soft_404(result, baseline):
    """
    Determine if result is actually a soft-404 (false positive).
    Uses: status + size + hash + body markers.
    """
    if not baseline:
        return False

    # === Rule 1: Same hash as baseline → definitely soft-404 ===
    if baseline.get("hash") and result.get("hash") == baseline["hash"]:
        return True

    # === Rule 2: Exact status match AND size within 5% ===
    if result["status"] == baseline["status"]:
        size_diff = abs(result["size"] - baseline["size"])
        # 5% tolerance or 200 bytes (whichever is larger)
        threshold = max(baseline["size"] * 0.05, 200)
        if size_diff < threshold:
            # Additional check: body markers
            body = result.get("body_lower", "")
            marker_hits = sum(1 for m in SOFT_404_MARKERS if m in body)
            if marker_hits > 0:
                return True

    # === Rule 3: Status 200 but body has strong 404 markers ===
    if result["status"] == 200:
        body = result.get("body_lower", "")
        marker_hits = sum(1 for m in SOFT_404_MARKERS if m in body)
        # Strong indication if 2+ markers AND size close to baseline
        if marker_hits >= 2:
            size_diff = abs(result["size"] - baseline.get("size", 0))
            if size_diff < max(baseline.get("size", 0) * 0.1, 500):
                return True

    return False


def _classify_finding(result, baseline):
    """Classify a finding's importance."""
    path = result["path"].lower()
    status = result["status"]

    # Is it sensitive?
    is_sensitive = any(s in path for s in SENSITIVE_PATHS)

    # Severity
    if is_sensitive and status == 200:
        severity = "CRITICAL"
    elif is_sensitive and status in (401, 403):
        severity = "HIGH"  # exists but protected
    elif status == 200 and result["size"] > 1000:
        severity = "MEDIUM"
    elif status in (401, 403):
        severity = "MEDIUM"
    elif status in (301, 302):
        severity = "LOW"
    else:
        severity = "INFO"

    return {
        "severity": severity,
        "sensitive": is_sensitive,
    }


# ============================================================
# Main
# ============================================================

def run_dir_bust(base_url, workers=40, paths=None, timeout=8):
    """Bust directories with enhanced soft-404 detection."""
    if paths is None:
        paths = COMMON_PATHS

    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url

    result = {
        "timestamp": datetime.now().isoformat(),
        "url": base_url,
        "found": [],
        "filtered_soft404": 0,
        "total_checked": len(paths),
        "soft_404_baseline": None,
        "soft_404_probes": 0,
        "sensitive_findings": [],
        "errors": [],
    }

    # === Detect soft-404 baseline ===
    print(f"  [*] Detecting soft-404 baseline (3 probes)...")
    baseline = _detect_soft_404(base_url, probes=3)
    result["soft_404_baseline"] = baseline

    if baseline:
        consistent = "✓ consistent" if baseline.get("consistent") else "~ variable"
        print(f"  [*] Baseline: status={baseline['status']}, "
              f"size={baseline['size']}, {consistent}")
    else:
        print(f"  [!] No baseline detected (server may be unreachable)")

    # === Scan ===
    print(f"  [*] Scanning {len(paths)} paths ({workers} workers)...")

    def check(path):
        return _fetch(base_url, path, timeout=timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(check, p): p for p in paths}

        for future in concurrent.futures.as_completed(futures):
            try:
                r = future.result(timeout=timeout + 5)
                if not r:
                    continue

                # Filter soft-404
                if _is_soft_404(r, baseline):
                    result["filtered_soft404"] += 1
                    continue

                # Classify
                classification = _classify_finding(r, baseline)

                finding = {
                    "path": r["path"],
                    "url": r["url"],
                    "status": r["status"],
                    "size": r["size"],
                    "type": r["type"],
                    "redirect": r.get("redirect", False),
                    "location": r.get("location", ""),
                    "severity": classification["severity"],
                    "sensitive": classification["sensitive"],
                }
                result["found"].append(finding)

                if classification["sensitive"]:
                    result["sensitive_findings"].append(finding)

            except Exception as e:
                result["errors"].append(str(e))

    # Sort by severity then path
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    result["found"].sort(key=lambda x: (
        severity_order.get(x["severity"], 99),
        x["path"]
    ))

    return result


# ============================================================
# Report
# ============================================================

def print_dir_bust_report(result):
    print("\n" + "=" * 70)
    print("  Directory Buster - ReconX")
    print("=" * 70)

    print(f"\n[*] Target: {result.get('url')}")
    print(f"[*] Paths checked: {result.get('total_checked')}")
    print(f"[*] Filtered (soft-404): {result.get('filtered_soft404', 0)}")
    print(f"[*] Found: {len(result.get('found', []))}")

    if result.get("soft_404_baseline"):
        b = result["soft_404_baseline"]
        consistent = "consistent" if b.get("consistent") else "variable"
        print(f"[*] Soft-404 baseline: status={b['status']}, "
              f"size={b['size']}, {consistent} ({b.get('probes', 0)} probes)")

    # Sensitive findings first
    sensitive = result.get("sensitive_findings", [])
    if sensitive:
        print(f"\n  {C_RED}{C_BOLD}[!] SENSITIVE FINDINGS ({len(sensitive)}):{C_RST}")
        for item in sensitive:
            marker = "🔴" if item["severity"] == "CRITICAL" else "🟠"
            print(f"    {marker} [{item['status']}] {item['path']:<45} "
                  f"({item['size']} B)")
            if item.get("location"):
                print(f"        → {item['location']}")

    # All findings
    found = result.get("found", [])
    if found:
        print(f"\n[+] All Findings ({len(found)}):")
        print(f"    {'SEV':<9} {'STATUS':<7} {'PATH':<40} {'SIZE':<10} {'TYPE'}")
        print(f"    {'-'*9} {'-'*7} {'-'*40} {'-'*10} {'-'*20}")

        for item in found[:50]:
            sev_icon = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🔵",
                "INFO": "⚪",
            }.get(item["severity"], "⚪")
            path_display = item["path"][:40]
            print(f"    {sev_icon} {item['severity']:<6} "
                  f"{item['status']:<7} {path_display:<40} "
                  f"{item['size']:<10} {item['type'][:20]}")

        if len(found) > 50:
            print(f"    ... and {len(found) - 50} more")
    else:
        print(f"\n[OK] No exposed paths found")

    print("\n" + "=" * 70 + "\n")


# ============================================================
# Colors
# ============================================================

C_RED = "\033[91m"
C_BOLD = "\033[1m"
C_RST = "\033[0m"


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.web.dir_buster <url>")
        sys.exit(1)

    url = sys.argv[1]
    print(f"\n[*] Directory Buster: {url}")

    result = run_dir_bust(url)
    print_dir_bust_report(result)
