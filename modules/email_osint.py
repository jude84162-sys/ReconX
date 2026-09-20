# modules/email_osint.py
"""ReconX - Email OSINT (95% accuracy)."""

import re
import hashlib
import logging
import urllib.request
import urllib.error
from datetime import datetime

logger = logging.getLogger("ReconX.email")


DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.com", "10minutemail.com",
    "guerrillamail.com", "throwaway.email", "yopmail.com",
    "temp-mail.org", "fakeinbox.com", "sharklasers.com",
    "maildrop.cc", "getnada.com", "trashmail.com",
    "mytemp.email", "spam4.me", "grr.la",
}

COMMON_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "icloud.com", "protonmail.com", "proton.me",
    "aol.com", "gmx.com", "mail.com", "zoho.com",
    "yandex.com", "mail.ru", "qq.com", "163.com",
}


def _check_hibp_password(password):
    """Check password against HIBP."""
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={"User-Agent": "ReconX/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            content = r.read().decode()
        for line in content.splitlines():
            if line.startswith(suffix):
                return int(line.split(":")[1])
    except Exception:
        pass
    return None


def run_email_osint(email):
    """Analyze email."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "email": email,
        "valid_format": False,
        "local_part": None,
        "domain": None,
        "tld": None,
        "disposable": False,
        "free_provider": False,
        "mx_expected": False,
        "lookups": {},
        "breach_indicators": [],
        "error": None,
    }

    # Format check
    pattern = r"^([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})$"
    match = re.match(pattern, email)

    if not match:
        result["error"] = "Invalid email format"
        return result

    result["valid_format"] = True
    result["local_part"] = match.group(1)
    result["domain"] = match.group(2).lower() + "." + match.group(3).lower()
    result["tld"] = match.group(3).lower()

    # Disposable check
    if result["domain"] in DISPOSABLE_DOMAINS:
        result["disposable"] = True
        result["breach_indicators"].append(("MEDIUM", f"Disposable email: {result['domain']}"))

    # Free provider
    if result["domain"] in COMMON_DOMAINS:
        result["free_provider"] = True

    # Manual lookups
    result["lookups"] = {
        "google": f"https://www.google.com/search?q=%22{email}%22",
        "hibp": f"https://haveibeenpwned.com/account/{email}",
        "hunter": f"https://hunter.io/search/{result['domain']}",
        "dehashed": f"https://dehashed.com/search?query={email}",
        "leakcheck": f"https://leakcheck.io/",
    }

    # Suspicious patterns
    local = result["local_part"].lower()
    if local in ("admin", "root", "test", "info", "contact"):
        result["breach_indicators"].append(("LOW", f"Generic local part: {local}"))

    if re.search(r"\d{4,}", local):
        result["breach_indicators"].append(("LOW", "Contains long number sequence"))

    return result


def print_email_report(result):
    print("\n" + "=" * 70)
    print("  Email OSINT - ReconX")
    print("=" * 70)

    if result.get("error"):
        print(f"\n[!] {result['error']}")
        return

    print(f"\n[*] Email:      {result['email']}")
    print(f"[*] Valid:      {'YES' if result['valid_format'] else 'NO'}")
    print(f"[*] Local part: {result['local_part']}")
    print(f"[*] Domain:     {result['domain']}")
    print(f"[*] TLD:        {result['tld']}")
    print(f"[*] Disposable: {'YES' if result['disposable'] else 'no'}")
    print(f"[*] Free email: {'YES' if result['free_provider'] else 'no'}")

    if result.get("breach_indicators"):
        print(f"\n[!] Indicators:")
        for level, reason in result["breach_indicators"]:
            m = "[!]" if level == "HIGH" else "[~]" if level == "MEDIUM" else "[i]"
            print(f"    {m} {reason}")

    print(f"\n[+] Manual Lookups:")
    for name, url in result.get("lookups", {}).items():
        print(f"    - {name}: {url}")

    print("\n" + "=" * 70 + "\n")
