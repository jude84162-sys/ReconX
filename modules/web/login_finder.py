# modules/web/login_finder.py
"""ReconX - Login Page Finder (pure reconnaissance)."""

import re, ssl, logging, urllib.request, urllib.error, concurrent.futures
from datetime import datetime

logger = logging.getLogger("ReconX.login_finder")

LOGIN_PATHS = [
    "login", "login.php", "login.html", "login.aspx", "login.jsp",
    "signin", "sign-in", "sign_in", "signin.php", "signin.html",
    "log-in", "log_in", "logon", "log-on",
    "auth", "auth/login", "auth/signin",
    "user/login", "users/login", "account/login", "accounts/login",
    "admin", "admin/login", "admin/signin", "admin/auth",
    "administrator", "administrator/login",
    "panel", "panel/login", "cpanel", "cpanel/login",
    "dashboard", "dashboard/login",
    "portal", "portal/login",
    "manage", "management", "manager/login",
    "console", "console/login",
    "backend", "backend/login",
    "controlpanel", "control-panel",
    "webadmin", "web-admin",
    "wp-admin", "wp-login.php", "wp-login",
    "administrator/index.php",
    "admin/login",
    "web/login",
    "api/login", "api/auth", "api/v1/login", "api/v1/auth",
    "oauth", "oauth/login", "oauth2", "oauth/authorize",
    "sso", "sso/login", "saml", "saml/login", "cas", "cas/login",
    "entrar", "iniciar-sesion", "connexion", "identification",
    "anmelden", "einloggen", "accedi", "accesso",
    "giris", "oturum", "войти", "вход", "inloggen", "logga-in", "zaloguj",
    "login/", "signin/", "auth/",
    "account", "my-account", "profile/login",
]

LOGIN_INDICATORS = [
    r'<input[^>]+type=["\']password["\']',
    r'<input[^>]+name=["\']password["\']',
    r'<input[^>]+name=["\']passwd["\']',
    r'<input[^>]+name=["\']pwd["\']',
    r'<form[^>]+(?:action|id|class)=["\'][^"\']*login',
    r'<form[^>]+(?:action|id|class)=["\'][^"\']*signin',
    r'<form[^>]+(?:action|id|class)=["\'][^"\']*auth',
    r'(?i)sign\s+in', r'(?i)log\s+in',
    r'(?i)forgot\s+password', r'(?i)remember\s+me',
    r'(?i)username\s+or\s+email', r'(?i)enter\s+your\s+password',
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
            "Accept-Language": "en-US,en;q=0.9",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as r:
            return r.status, r.read(80000).decode("utf-8", errors="ignore"), r.url
    except urllib.error.HTTPError as e:
        try: body = e.read(30000).decode("utf-8", errors="ignore")
        except: body = ""
        return e.code, body, url
    except Exception:
        return None, None, None

def _check_login_path(base_url, path, timeout=8):
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    status, body, final_url = _fetch(url, timeout=timeout)
    result = {"path": path, "url": url, "final_url": final_url,
              "status": status, "is_login": False, "confidence": 0.0,
              "indicators": [], "redirected": False}
    if status is None or status == 404 or status >= 500:
        return None
    if final_url and final_url != url:
        result["redirected"] = True
    if body and status in (200, 401, 403):
        if re.search(r'<input[^>]+type=["\']password["\']', body, re.IGNORECASE):
            result["is_login"] = True
            result["confidence"] = 0.95
            result["indicators"].append("password_input_field")
        if re.search(r'<form[^>]+(?:action|id|class)=["\'][^"\']*(?:login|signin|auth)', body, re.IGNORECASE):
            result["confidence"] = min(result["confidence"] + 0.15, 0.99)
            result["indicators"].append("login_form_action")
        text_hits = sum(1 for p in LOGIN_INDICATORS[8:] if re.search(p, body))
        if text_hits >= 2:
            result["confidence"] = max(result["confidence"], 0.60)
            result["indicators"].append(f"text_hits_{text_hits}")
        title_match = re.search(r"<title[^>]*>([^<]*)</title>", body, re.IGNORECASE)
        if title_match:
            title = title_match.group(1).lower()
            if any(kw in title for kw in ["login", "sign in", "signin", "log in", "auth"]):
                result["confidence"] = min(result["confidence"] + 0.10, 0.99)
                result["indicators"].append("login_title")
    if status in (401, 403) and any(kw in path.lower() for kw in ["login", "signin", "auth", "admin"]):
        result["confidence"] = max(result["confidence"], 0.50)
        result["indicators"].append(f"status_{status}_protected")
    if result["confidence"] >= 0.5:
        result["is_login"] = True
    return result

def run_login_finder(base_url, workers=30, custom_paths=None, timeout=8):
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    paths = custom_paths if custom_paths else LOGIN_PATHS
    result = {"timestamp": datetime.now().isoformat(), "url": base_url,
              "found": [], "total_checked": len(paths), "errors": []}
    print(f"  [*] Searching {len(paths)} login paths...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_check_login_path, base_url, p, timeout): p for p in paths}
        for future in concurrent.futures.as_completed(futures):
            try:
                r = future.result(timeout=timeout + 5)
                if r and r["is_login"]:
                    result["found"].append(r)
            except Exception as e:
                result["errors"].append(str(e))
    result["found"].sort(key=lambda x: -x["confidence"])
    return result

def print_login_finder_report(result):
    print("\n" + "=" * 70)
    print("  Login Finder — ReconX")
    print("=" * 70)
    print(f"\n[*] Target: {result.get('url')}")
    print(f"[*] Paths checked: {result.get('total_checked')}")
    print(f"[*] Login pages found: {len(result.get('found', []))}")
    if result.get("found"):
        print(f"\n[+] Login Pages:")
        for item in result["found"]:
            conf = item["confidence"]
            marker = "🟢" if conf >= 0.85 else "🟡" if conf >= 0.65 else "🔵"
            print(f"\n  {marker} [{item['status']}] {item['url']}")
            print(f"       Confidence: {conf:.2f}")
            print(f"       Indicators: {', '.join(item['indicators'])}")
            if item.get("redirected"):
                print(f"       → Redirected: {item['final_url']}")
    else:
        print(f"\n[OK] No login pages found")
    print("\n" + "=" * 70 + "\n")

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print("Usage: python -m modules.web.login_finder <url>")
        sys.exit(1)
    print(f"\n[*] Login Finder: {sys.argv[1]}")
    print_login_finder_report(run_login_finder(sys.argv[1]))
