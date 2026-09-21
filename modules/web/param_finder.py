# modules/web/param_finder.py
"""ReconX - Parameter Finder (pure reconnaissance)."""

import re, ssl, logging, urllib.request, urllib.error, concurrent.futures
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger("ReconX.param_finder")

COMMON_PARAMS = [
    "id", "user", "username", "userid", "user_id", "uid",
    "name", "firstname", "lastname", "email", "phone",
    "page", "p", "pg", "pagenum", "page_id", "pageid",
    "q", "query", "s", "search", "keyword", "kw",
    "cat", "category", "catid", "category_id", "type", "t",
    "action", "act", "do", "method", "mode", "func", "function",
    "file", "filename", "path", "dir", "folder", "url", "link",
    "lang", "language", "locale", "country", "region",
    "sort", "order", "orderby", "limit", "offset", "start", "count",
    "token", "key", "api_key", "apikey", "auth", "session",
    "redirect", "return", "return_url", "next", "back", "ref",
    "debug", "test", "admin", "preview", "view", "display",
    "format", "output", "json", "xml", "callback",
    "version", "v", "ver", "rev",
    "config", "setting", "option", "opt",
    "cache", "nocache", "rand", "random",
    "source", "src", "from", "origin",
    "target", "dest", "destination",
    "include", "require", "load", "read",
]

REFLECT_INDICATORS = [
    r'<input[^>]+name=["\']({param})["\']',
    r'<textarea[^>]+name=["\']({param})["\']',
    r'<select[^>]+name=["\']({param})["\']',
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
            "Accept": "text/html,*/*",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as r:
            return r.status, r.read(100000).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(50000).decode("utf-8", errors="ignore")
        except: return e.code, ""
    except Exception:
        return None, None

def _test_param(base_url, param, timeout=8):
    try:
        parsed = urlparse(base_url)
        existing = parse_qs(parsed.query)
        test_value = f"reconx{hash(param) % 10000}"
        existing[param] = [test_value]
        new_query = urlencode(existing, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        status, body = _fetch(test_url, timeout=timeout)
        if status is None:
            return None
        base_status, base_body = _fetch(base_url, timeout=timeout)
        result = {"param": param, "test_url": test_url, "status": status,
                  "accepted": False, "reflected": False,
                  "confidence": 0.0, "indicators": []}
        if base_status is None:
            return None
        if body:
            if test_value in body:
                result["reflected"] = True
                result["confidence"] = 0.85
                result["indicators"].append("value_reflected")
            for pattern_tmpl in REFLECT_INDICATORS:
                pattern = pattern_tmpl.replace("{param}", re.escape(param))
                if re.search(pattern, body, re.IGNORECASE):
                    result["confidence"] = max(result["confidence"], 0.75)
                    result["indicators"].append("input_field_exists")
                    break
        if status != base_status:
            result["confidence"] = max(result["confidence"], 0.55)
            result["indicators"].append(f"status_changed_{base_status}_to_{status}")
        if body and base_body and len(base_body) > 0:
            diff_pct = abs(len(body) - len(base_body)) / len(base_body) * 100
            if diff_pct > 15:
                result["confidence"] = max(result["confidence"], 0.50)
                result["indicators"].append(f"size_diff_{int(diff_pct)}pct")
        if result["confidence"] >= 0.5:
            result["accepted"] = True
        return result
    except Exception as e:
        logger.debug(f"param {param} failed: {e}")
        return None

def run_param_finder(base_url, workers=20, custom_params=None, timeout=8):
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    if "?" not in base_url:
        base_url = base_url.rstrip("/") + "/?id=1"
    params = custom_params if custom_params else COMMON_PARAMS
    result = {"timestamp": datetime.now().isoformat(), "url": base_url,
              "accepted": [], "total_checked": len(params), "errors": []}
    print(f"  [*] Testing {len(params)} parameters...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_test_param, base_url, p, timeout): p for p in params}
        for future in concurrent.futures.as_completed(futures):
            try:
                r = future.result(timeout=timeout + 5)
                if r and r["accepted"]:
                    result["accepted"].append(r)
            except Exception as e:
                result["errors"].append(str(e))
    result["accepted"].sort(key=lambda x: -x["confidence"])
    return result

def print_param_finder_report(result):
    print("\n" + "=" * 70)
    print("  Parameter Finder — ReconX")
    print("=" * 70)
    print(f"\n[*] Target: {result.get('url')}")
    print(f"[*] Params tested: {result.get('total_checked')}")
    print(f"[*] Accepted params: {len(result.get('accepted', []))}")
    if result.get("accepted"):
        print(f"\n[+] Accepted Parameters:")
        for item in result["accepted"]:
            conf = item["confidence"]
            marker = "🟢" if conf >= 0.80 else "🟡" if conf >= 0.60 else "🔵"
            print(f"\n  {marker} {item['param']}  [{item['status']}]")
            print(f"       Confidence: {conf:.2f}")
            print(f"       Indicators: {', '.join(item['indicators'])}")
            if item.get("reflected"):
                print(f"       ⚠ Reflected in response")
    else:
        print(f"\n[OK] No parameters accepted")
    print("\n" + "=" * 70 + "\n")

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print("Usage: python -m modules.web.param_finder <url-with-params>")
        sys.exit(1)
    print(f"\n[*] Parameter Finder: {sys.argv[1]}")
    print_param_finder_report(run_param_finder(sys.argv[1]))
