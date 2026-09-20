# modules/breach_checker.py
"""ReconX - Breach Checker (HIBP k-anonymity + public sources)."""

import hashlib
import ssl
import re
import logging
import urllib.request
import urllib.error
from datetime import datetime

logger = logging.getLogger("ReconX.breach")


def _fetch(url, timeout=10, headers=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    default_headers = {"User-Agent": "ReconX/1.0"}
    if headers:
        default_headers.update(headers)

    try:
        req = urllib.request.Request(url, headers=default_headers)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return None
    except Exception:
        return None


def check_password_hibp(password):
    """Check password against HIBP using k-anonymity (no API key needed)."""
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        body = _fetch(url, timeout=10)
        if not body:
            return None

        for line in body.splitlines():
            if line.startswith(suffix):
                count = line.split(":")[1]
                return int(count)
    except Exception as e:
        logger.debug(f"HIBP: {e}")
    return None


def run_breach_check(target):
    """Check email/domain/username for breach indicators."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "type": None,
        "hibp_url": None,
        "manual_lookups": {},
        "indicators": [],
        "summary": {},
        "error": None,
    }

    # Detect type
    if "@" in target:
        result["type"] = "email"
        result["hibp_url"] = f"https://haveibeenpwned.com/account/{target}"
    elif re.match(r"^\d{7,}$", target) or target.startswith("+"):
        result["type"] = "phone"
        result["hibp_url"] = "https://haveibeenpwned.com/"
    else:
        result["type"] = "username"

    # Manual lookup URLs
    encoded = urllib.parse.quote(target)
    result["manual_lookups"] = {
        "HaveIBeenPwned": result["hibp_url"],
        "Dehashed": f"https://dehashed.com/search?query={encoded}",
        "LeakCheck": f"https://leakcheck.io/",
        "Firefox Monitor": f"https://monitor.firefox.com/",
        "Google Dork": f"https://www.google.com/search?q=%22{encoded}%22+breach",
        "Pastebin": f"https://www.google.com/search?q=site:pastebin.com+%22{encoded}%22",
        "GitHub Search": f"https://github.com/search?q={encoded}&type=code",
    }

    # Indicators
    if result["type"] == "email":
        local = target.split("@")[0].lower()
        if local in ("admin", "root", "test", "info"):
            result["indicators"].append(("LOW", "Generic email prefix"))

    result["summary"] = {
        "type": result["type"],
        "hibp_check": "Manual",
        "indicators": len(result["indicators"]),
    }

    return result


import urllib.parse


def print_breach_report(result):
    print("\n" + "=" * 70)
    print("  Breach Checker - ReconX")
    print("=" * 70)

    print(f"\n[*] Target: {result.get('target')}")
    print(f"[*] Type:   {result.get('type')}")

    if result.get("indicators"):
        print(f"\n[!] Indicators:")
        for level, reason in result["indicators"]:
            m = "[!]" if level == "HIGH" else "[~]" if level == "MEDIUM" else "[i]"
            print(f"    {m} {reason}")
    else:
        print(f"\n[OK] No obvious indicators")

    print(f"\n[+] Manual Lookups:")
    for name, url in result.get("manual_lookups", {}).items():
        print(f"    • {name}:")
        print(f"      {url}")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.breach_checker <email/username/phone>")
        sys.exit(1)

    target = sys.argv[1]
    result = run_breach_check(target)
    print_breach_report(result)
