# modules/web/register_finder.py
"""ReconX - Register Page Finder (pure reconnaissance)."""

import re, ssl, logging, urllib.request, urllib.error, concurrent.futures
from datetime import datetime

logger = logging.getLogger("ReconX.register_finder")

REGISTER_PATHS = [
    "register", "register.php", "register.html", "register.aspx", "register.jsp",
    "signup", "sign-up", "sign_up", "signup.php", "signup.html",
    "join", "join-us",
    "user/register", "users/register", "account/register", "accounts/register",
    "user/signup", "users/signup", "account/signup",
    "auth/register", "auth/signup", "auth/create",
    "admin/register", "admin/signup",
    "api/register", "api/signup", "api/v1/register", "api/v1/signup",
    "create-account", "new-account", "create_account",
    "registro", "registrar", "inscription", "inscrire",
    "registrieren", "anmeldung", "registrati", "iscrizione",
    "kayit", "registraciya", "регистрация",
    "registreren", "registrera", "zarejestruj",
    "wp-login.php?action=register", "wp-signup.php",
    "account/create", "profile/create",
    "enroll", "enrollment",
    "new-user", "newuser", "adduser", "add-user",
]

REGISTER_INDICATORS = [
    r'<input[^>]+(?:type=["\']password["\']|name=["\'](?:password|passwd|pwd)["\'])',
    r'<form[^>]+(?:action|id|class)=["\'][^"\']*(?:register|signup|sign-up|join)',
    r'(?i)create\s+(?:an?\s+)?account',
    r'(?i)sign\s+up',
    r'(?i)register\s+(?:now|free|today)',
    r'(?i)already\s+have\s+an\s+account',
    r'(?i)join\s+(?:now|free|us)',
    r'(?i)confirm\s+password',
    r'(?i)repeat\s+password',
    r'(?i)email\s+address',
    r'(?i)date\s+of\s+birth',
]

def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _fetch(url, timeout=8):
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Accept": "text/html,application/xhtml+xml,*/*",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as r:
            return r.status, r.read(80000).decode("utf-8", errors="ignore"), r.url
    except urllib.error.HTTPError as e:
        try: body = e.read(30000).decode("utf-8", errors="ignore")
        except: body = ""
        return e.code, body, url
    except Exception:
        return None, None, None

def _check_register_path(base_url, path, timeout=8):
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    status, body, final_url = _fetch(url, timeout=timeout)
    result = {"path": path, "url": url, "final_url": final_url,
              "status": status, "is_register": False, "confidence": 0.0,
              "indicators": [], "redirected": False}
    if status is None or status == 404 or status >= 500:
        return None
    if final_url and final_url != url:
        result["redirected"] = True
    if body and status in (200, 401, 403):
        has_pwd = re.search(r'<input[^>]+type=["\']password["\']', body, re.IGNORECASE)
        if has_pwd:
            result["confidence"] = 0.50
            result["indicators"].append("password_field")
        if re.search(r'<form[^>]+(?:action|id|class)=["\'][^"\']*(?:register|signup|sign-up|join|create)', body, re.IGNORECASE):
            result["confidence"] = max(result["confidence"], 0.85)
            result["indicators"].append("register_form_action")
        text_hits = sum(1 for p in REGISTER_INDICATORS[2:] if re.search(p, body))
        if text_hits >= 2:
            result["confidence"] = max(result["confidence"], 0.65)
            result["indicators"].append(f"text_hits_{text_hits}")
        title_match = re.search(r"<title[^>]*>([^<]*)</title>", body, re.IGNORECASE)
        if title_match:
            title = title_match.group(1).lower()
            if any(kw in title for kw in ["register", "sign up", "signup", "create account", "join"]):
                result["confidence"] = min(result["confidence"] + 0.15, 0.99)
                result["indicators"].append("register_title")
    if result["confidence"] >= 0.5:
        result["is_register"] = True
    return result

def run_register_finder(base_url, workers=30, custom_paths=None, timeout=8):
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    paths = custom_paths if custom_paths else REGISTER_PATHS
    result = {"timestamp": datetime.now().isoformat(), "url": base_url,
              "found": [], "total_checked": len(paths), "errors": []}
    print(f"  [*] Searching {len(paths)} register paths...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_check_register_path, base_url, p, timeout): p for p in paths}
        for future in concurrent.futures.as_completed(futures):
            try:
                r = future.result(timeout=timeout + 5)
                if r and r["is_register"]:
                    result["found"].append(r)
            except Exception as e:
                result["errors"].append(str(e))
    result["found"].sort(key=lambda x: -x["confidence"])
    return result

def print_register_finder_report(result):
    print("\n" + "=" * 70)
    print("  Register Finder — ReconX")
    print("=" * 70)
    print(f"\n[*] Target: {result.get('url')}")
    print(f"[*] Paths checked: {result.get('total_checked')}")
    print(f"[*] Register pages found: {len(result.get('found', []))}")
    if result.get("found"):
        print(f"\n[+] Register Pages:")
        for item in result["found"]:
            conf = item["confidence"]
            marker = "🟢" if conf >= 0.85 else "🟡" if conf >= 0.65 else "🔵"
            print(f"\n  {marker} [{item['status']}] {item['url']}")
            print(f"       Confidence: {conf:.2f}")
            print(f"       Indicators: {', '.join(item['indicators'])}")
            if item.get("redirected"):
                print(f"       → Redirected: {item['final_url']}")
    else:
        print(f"\n[OK] No register pages found")
    print("\n" + "=" * 70 + "\n")

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print("Usage: python -m modules.web.register_finder <url>")
        sys.exit(1)
    print(f"\n[*] Register Finder: {sys.argv[1]}")
    print_register_finder_report(run_register_finder(sys.argv[1]))
