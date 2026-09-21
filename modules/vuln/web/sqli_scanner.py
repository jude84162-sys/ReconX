# modules/vuln/web/sqli_scanner.py
"""ReconX - SQL Injection Scanner (sqlmap wrapper)."""

import shutil
import logging
import subprocess
import re
import tempfile
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("ReconX.sqli")


def is_available():
    return shutil.which("sqlmap") is not None


def scan(target, level=3, risk=2, timeout=300, params=None, verbose=False):
    """Run sqlmap on target URL."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "available": is_available(),
        "vulnerable": False,
        "findings": [],
        "dbms": None,
        "error": None,
        "duration": 0,
    }

    if not result["available"]:
        result["error"] = "sqlmap not installed (sudo apt install sqlmap)"
        return result

    # Build command
    out_dir = tempfile.mkdtemp(prefix="sqlmap_reconx_")
    cmd = [
        "sqlmap", "-u", target,
        "--batch",
        "--level", str(level),
        "--risk", str(risk),
        "--random-agent",
        "--output-dir", out_dir,
        "--flush-session",
    ]

    if params:
        cmd.extend(["-p", params])

    start = datetime.now()
    try:
        if verbose:
            print(f"    [>] {' '.join(cmd)}")

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = proc.stdout + proc.stderr
        result["duration"] = (datetime.now() - start).total_seconds()

        # Check if vulnerable
        if re.search(r"Parameter.*is vulnerable", output, re.IGNORECASE):
            result["vulnerable"] = True

            # Extract injectable params
            param_matches = re.findall(
                r"Parameter:\s*([^\s]+)\s*\(([^)]+)\)",
                output, re.IGNORECASE
            )
            seen = set()
            for param, ptype in param_matches:
                key = (param, ptype)
                if key in seen:
                    continue
                seen.add(key)
                result["findings"].append({
                    "id": f"sqli_{param}",
                    "title": f"SQL Injection in '{param}' parameter",
                    "parameter": param,
                    "type": ptype,
                    "severity": "critical",
                    "bug_class": "sql_injection",
                    "payout_potential": "$1000-$10000+",
                    "confidence": 0.95,
                    "url": target,
                    "evidence": f"sqlmap confirmed: {param} ({ptype})",
                    "source": "sqlmap",
                })

        # DBMS
        dbms_match = re.search(r"back-end DBMS:\s*([^\n]+)", output, re.IGNORECASE)
        if dbms_match:
            result["dbms"] = dbms_match.group(1).strip()

        # Also check if not vulnerable
        if not result["vulnerable"] and "not injectable" in output.lower():
            result["error"] = None  # not an error, just not vulnerable

    except subprocess.TimeoutExpired:
        result["error"] = f"timeout after {timeout}s"
    except Exception as e:
        result["error"] = str(e)

    return result


def print_report(result):
    print("\n" + "=" * 70)
    print("  SQL Injection Scanner — ReconX")
    print("=" * 70)

    if not result.get("available"):
        print(f"\n[!] {result.get('error', 'sqlmap not available')}")
        print(f"    Install: sudo apt install sqlmap")
        return

    if result.get("error") and not result.get("findings"):
        print(f"\n[!] {result['error']}")
        return

    print(f"\n[*] Target:   {result['target']}")
    print(f"[*] Duration: {result['duration']:.1f}s")

    if result["vulnerable"]:
        print(f"\n🔴 VULNERABLE TO SQL INJECTION")
        for f in result["findings"]:
            print(f"\n    Parameter: {f['parameter']}")
            print(f"    Type:      {f['type']}")
            print(f"    Payout:    {f['payout_potential']}")

        if result.get("dbms"):
            print(f"\n[*] DBMS: {result['dbms']}")
    else:
        print(f"\n[OK] Not vulnerable (or sqlmap couldn't confirm)")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.web.sqli_scanner <url-with-params>")
        print("Example: python -m modules.vuln.web.sqli_scanner 'http://testphp.vulnweb.com/artists.php?artist=1'")
        sys.exit(1)

    url = sys.argv[1]
    print(f"\n[*] SQLi scan: {url}")
    print(f"[*] This may take 1-5 minutes...")

    result = scan(url, verbose=True)
    print_report(result)
