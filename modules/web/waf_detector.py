# modules/web/waf_detector.py
"""ReconX - WAF Detector (pure reconnaissance)."""

import re, ssl, logging, urllib.request, urllib.error
from datetime import datetime

logger = logging.getLogger("ReconX.waf")

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {"Server": [r"cloudflare"], "CF-RAY": [r".*"], "cf-cache-status": [r".*"]},
        "cookies": [r"__cfduid", r"__cf_bm", r"cf_clearance"],
        "body": [r"cloudflare", r"cf-error-details"],
    },
    "Sucuri": {
        "headers": {"Server": [r"Sucuri"], "X-Sucuri-ID": [r".*"], "X-Sucuri-Cache": [r".*"]},
        "cookies": [], "body": [r"sucuri", r"cloudproxy"],
    },
    "AWS WAF": {
        "headers": {"Server": [r"awselb", r"AmazonS3"], "X-Amzn-RequestId": [r".*"]},
        "cookies": [r"aws-waf-token", r"awswaf"], "body": [],
    },
    "Akamai": {
        "headers": {"Server": [r"AkamaiGHost"], "X-Akamai-Transformed": [r".*"]},
        "cookies": [r"AKA_A2"], "body": [r"akamai"],
    },
    "Imperva (Incapsula)": {
        "headers": {"X-Iinfo": [r".*"], "X-CDN": [r"Incapsula"]},
        "cookies": [r"incap_ses", r"visid_incap", r"nlbi"],
        "body": [r"incapsula", r"imperva"],
    },
    "F5 BIG-IP ASM": {
        "headers": {"Server": [r"BIG-IP", r"BIGIP"], "X-WA-Info": [r".*"]},
        "cookies": [r"TS[0-9a-f]{8}", r"BIGipServer"],
        "body": [r"the requested url was rejected", r"support id"],
    },
    "Fortinet FortiWeb": {
        "headers": {"Server": [r"FortiWeb"]},
        "cookies": [r"FORTIWAFSID"], "body": [r"fortiweb"],
    },
    "Barracuda": {
        "headers": {"Server": [r"Barracuda"]},
        "cookies": [r"barra_counter_session"], "body": [r"barracuda"],
    },
    "ModSecurity": {
        "headers": {"Server": [r"ModSecurity", r"mod_security", r"NOYB"]},
        "cookies": [], "body": [r"mod_security", r"modsecurity", r"not acceptable"],
    },
    "Wordfence": {
        "headers": {}, "cookies": [r"wordfence_verifiedHuman"],
        "body": [r"wordfence"],
    },
    "Fastly": {
        "headers": {"X-Served-By": [r"cache-"], "X-Fastly-Request-ID": [r".*"]},
        "cookies": [], "body": [r"fastly"],
    },
    "StackPath": {
        "headers": {"Server": [r"StackPath"]}, "cookies": [], "body": [r"stackpath"],
    },
    "Google Cloud Armor": {
        "headers": {"Server": [r"Google Frontend", r"gws"], "X-Cloud-Trace-Context": [r".*"]},
        "cookies": [], "body": [],
    },
    "Azure Front Door": {
        "headers": {"X-Azure-Ref": [r".*"], "X-FD-HealthProbe": [r".*"]},
        "cookies": [], "body": [],
    },
    "Reblaze": {
        "headers": {"Server": [r"Reblaze"]},
        "cookies": [r"rbzid", r"rbzsessionid"], "body": [r"reblaze"],
    },
    "Wallarm": {
        "headers": {"Server": [r"nginx-wallarm"]}, "cookies": [], "body": [r"wallarm"],
    },
    "DDoS-Guard": {
        "headers": {"Server": [r"DDoS-Guard"]},
        "cookies": [r"__ddg"], "body": [r"ddos-guard"],
    },
}

WAF_TEST_PAYLOADS = [
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
]

def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _fetch(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Accept": "text/html,*/*",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as r:
            return {"status": r.status,
                    "headers": {k: v for k, v in r.headers.items()},
                    "body": r.read(50000).decode("utf-8", errors="ignore")}
    except urllib.error.HTTPError as e:
        try: body = e.read(30000).decode("utf-8", errors="ignore")
        except: body = ""
        return {"status": e.code,
                "headers": {k: v for k, v in (e.headers.items() if e.headers else [])},
                "body": body}
    except Exception:
        return None

def _match_patterns(text, patterns):
    if not text:
        return False
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return True
    return False

def _detect_waf(response):
    if not response:
        return []
    detections = []
    headers = response.get("headers", {})
    body = response.get("body", "")
    cookies = headers.get("Set-Cookie", "") + " " + headers.get("set-cookie", "")
    for waf_name, sigs in WAF_SIGNATURES.items():
        confidence = 0.0
        matched = []
        for header_name, patterns in sigs.get("headers", {}).items():
            for h_name, h_value in headers.items():
                if h_name.lower() == header_name.lower():
                    if _match_patterns(h_value, patterns):
                        confidence += 0.40
                        matched.append(f"header:{header_name}")
                        break
        for cookie_pat in sigs.get("cookies", []):
            if re.search(cookie_pat, cookies, re.IGNORECASE):
                confidence += 0.30
                matched.append(f"cookie")
                break
        for body_pat in sigs.get("body", []):
            if re.search(body_pat, body, re.IGNORECASE):
                confidence += 0.25
                matched.append(f"body")
                break
        if confidence >= 0.30:
            detections.append({"waf": waf_name, "confidence": min(confidence, 0.99), "matched": matched})
    return detections

def run_waf_detector(base_url, timeout=10):
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    result = {"timestamp": datetime.now().isoformat(), "url": base_url,
              "wafs_detected": [], "blocked_payloads": 0, "tests": [], "error": None}
    print(f"  [*] Testing normal request...")
    normal = _fetch(base_url, timeout=timeout)
    if not normal:
        result["error"] = "connection_failed"
        return result
    normal_detections = _detect_waf(normal)
    result["tests"].append({"type": "normal", "status": normal["status"], "detections": normal_detections})
    print(f"  [*] Testing {len(WAF_TEST_PAYLOADS)} suspicious payloads...")
    for payload in WAF_TEST_PAYLOADS:
        sep = "&" if "?" in base_url else "?"
        test_url = f"{base_url}{sep}q={payload}"
        r = _fetch(test_url, timeout=timeout)
        if not r:
            continue
        blocked = r["status"] in (403, 406, 419, 429, 503)
        if blocked:
            result["blocked_payloads"] += 1
        detections = _detect_waf(r)
        result["tests"].append({"type": "suspicious", "payload": payload[:30],
                                "status": r["status"], "blocked": blocked, "detections": detections})
    all_detections = {}
    for test in result["tests"]:
        for d in test.get("detections", []):
            name = d["waf"]
            if name not in all_detections:
                all_detections[name] = d
            else:
                all_detections[name]["confidence"] = min(all_detections[name]["confidence"] + 0.10, 0.99)
                all_detections[name]["matched"].extend(d["matched"])
    result["wafs_detected"] = sorted(all_detections.values(), key=lambda x: -x["confidence"])
    return result

def print_waf_report(result):
    print("\n" + "=" * 70)
    print("  WAF Detector — ReconX")
    print("=" * 70)
    if result.get("error"):
        print(f"\n[!] {result['error']}")
        return
    print(f"\n[*] Target: {result.get('url')}")
    wafs = result.get("wafs_detected", [])
    if wafs:
        print(f"\n[+] WAF Detected ({len(wafs)}):")
        for w in wafs:
            conf = w["confidence"]
            marker = "🟢" if conf >= 0.80 else "🟡" if conf >= 0.50 else "🔵"
            print(f"\n  {marker} {w['waf']}")
            print(f"       Confidence: {conf:.2f}")
            print(f"       Evidence:   {', '.join(w['matched'][:3])}")
    else:
        print(f"\n[OK] No WAF detected (target may be unprotected)")
    total_susp = sum(1 for t in result["tests"] if t["type"] == "suspicious")
    print(f"\n[*] Payload tests: {result.get('blocked_payloads', 0)}/{total_susp} blocked")
    print("\n" + "=" * 70 + "\n")

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print("Usage: python -m modules.web.waf_detector <url>")
        sys.exit(1)
    print(f"\n[*] WAF Detector: {sys.argv[1]}")
    print_waf_report(run_waf_detector(sys.argv[1]))
