# modules/web/web_monitor.py
"""ReconX - Web Monitor (detects changes over time)."""

import os, re, ssl, json, hashlib, logging, urllib.request, urllib.error
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("ReconX.web_monitor")
MONITOR_DIR = Path.home() / ".reconx" / "monitor"

def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _fetch(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Accept": "text/html,application/xhtml+xml,*/*",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as r:
            return {"status": r.status, "headers": dict(r.headers),
                    "body": r.read(500000).decode("utf-8", errors="ignore"),
                    "final_url": r.url}
    except urllib.error.HTTPError as e:
        try: body = e.read(100000).decode("utf-8", errors="ignore")
        except: body = ""
        return {"status": e.code, "headers": dict(e.headers) if e.headers else {},
                "body": body, "final_url": url}
    except Exception as e:
        return {"error": str(e)}

def _hash_body(body):
    if not body:
        return ""
    normalized = re.sub(r'\s+', ' ', body)
    normalized = re.sub(r'\d{10,}', 'TIMESTAMP', normalized)
    normalized = re.sub(r'[a-f0-9]{32,}', 'HASH', normalized)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]

def _url_to_key(url):
    return re.sub(r'[^a-zA-Z0-9]', '_', url)[:100]

def _snapshot_path(url):
    MONITOR_DIR.mkdir(parents=True, exist_ok=True)
    return MONITOR_DIR / f"{_url_to_key(url)}.json"

def run_web_monitor(url, check_headers=True, check_body=True):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = {"timestamp": datetime.now().isoformat(), "url": url,
              "first_check": False, "changed": False, "changes": [],
              "current": {}, "error": None}
    print(f"  [*] Fetching {url}...")
    response = _fetch(url)
    if response.get("error"):
        result["error"] = response["error"]
        return result
    body = response.get("body", "")
    headers = response.get("headers", {})
    snapshot = {"timestamp": datetime.now().isoformat(), "status": response["status"],
                "final_url": response.get("final_url"), "body_hash": _hash_body(body),
                "body_size": len(body),
                "headers_hash": hashlib.sha256(json.dumps(sorted(headers.items()), default=str).encode()).hexdigest()[:16],
                "title": "", "server": headers.get("Server", "?")}
    title_match = re.search(r"<title[^>]*>([^<]*)</title>", body, re.IGNORECASE)
    if title_match:
        snapshot["title"] = title_match.group(1).strip()[:200]
    result["current"] = snapshot
    path = _snapshot_path(url)
    previous = None
    if path.exists():
        try: previous = json.loads(path.read_text())
        except: previous = None
    if not previous:
        result["first_check"] = True
        path.write_text(json.dumps(snapshot, indent=2))
        return result
    if check_body:
        if snapshot["body_hash"] != previous.get("body_hash"):
            result["changed"] = True
            result["changes"].append({"type": "body_content",
                                      "old_hash": previous.get("body_hash"),
                                      "new_hash": snapshot["body_hash"]})
        if snapshot["body_size"] != previous.get("body_size"):
            diff = snapshot["body_size"] - previous.get("body_size", 0)
            result["changes"].append({"type": "body_size",
                                      "old_size": previous.get("body_size"),
                                      "new_size": snapshot["body_size"],
                                      "diff_bytes": diff})
    if check_headers:
        if snapshot["headers_hash"] != previous.get("headers_hash"):
            result["changed"] = True
            result["changes"].append({"type": "headers"})
        if snapshot.get("server") != previous.get("server"):
            result["changed"] = True
            result["changes"].append({"type": "server_header",
                                      "old": previous.get("server"),
                                      "new": snapshot.get("server")})
    if snapshot["status"] != previous.get("status"):
        result["changed"] = True
        result["changes"].append({"type": "http_status",
                                  "old": previous.get("status"),
                                  "new": snapshot["status"]})
    if snapshot["title"] != previous.get("title"):
        result["changed"] = True
        result["changes"].append({"type": "page_title",
                                  "old": previous.get("title"),
                                  "new": snapshot["title"]})
    path.write_text(json.dumps(snapshot, indent=2))
    return result

def print_web_monitor_report(result):
    print("\n" + "=" * 70)
    print("  Web Monitor — ReconX")
    print("=" * 70)
    if result.get("error"):
        print(f"\n[!] {result['error']}")
        return
    print(f"\n[*] URL: {result.get('url')}")
    current = result.get("current", {})
    print(f"[*] Status: {current.get('status')}")
    print(f"[*] Title:  {current.get('title') or '(none)'}")
    print(f"[*] Size:   {current.get('body_size', 0)} bytes")
    print(f"[*] Server: {current.get('server')}")
    if result.get("first_check"):
        print(f"\n[+] First check — baseline saved")
    elif result.get("changed"):
        print(f"\n[!] CHANGES DETECTED:")
        for ch in result["changes"]:
            t = ch["type"]
            if t == "body_content":
                print(f"    🟡 Body content changed")
            elif t == "body_size":
                diff = ch["diff_bytes"]
                sign = "+" if diff > 0 else ""
                print(f"    🟡 Body size: {ch['old_size']} → {ch['new_size']} ({sign}{diff} bytes)")
            elif t == "headers":
                print(f"    🟡 HTTP headers changed")
            elif t == "server_header":
                print(f"    🔴 Server header: {ch['old']} → {ch['new']}")
            elif t == "http_status":
                print(f"    🔴 HTTP status: {ch['old']} → {ch['new']}")
            elif t == "page_title":
                print(f"    🟡 Title: {ch['old']} → {ch['new']}")
    else:
        print(f"\n[OK] No changes detected")
    print("\n" + "=" * 70 + "\n")

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print("Usage: python -m modules.web.web_monitor <url>")
        sys.exit(1)
    print(f"\n[*] Web Monitor: {sys.argv[1]}")
    print_web_monitor_report(run_web_monitor(sys.argv[1]))
