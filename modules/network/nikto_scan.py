# modules/network/nikto_scan.py
"""
ReconX - Nikto Wrapper
======================
Runs Nikto web vulnerability scanner and parses output.

Requires: nikto (apt install nikto)
"""

import os
import re
import json
import shutil
import logging
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("ReconX.nikto")


# ============================================================
# Availability Check
# ============================================================

def is_nikto_available():
    """Check if nikto is installed."""
    return shutil.which("nikto") is not None


def get_nikto_version():
    """Get Nikto version."""
    if not is_nikto_available():
        return None
    try:
        r = subprocess.run(
            ["nikto", "-Version"],
            capture_output=True, text=True, timeout=10
        )
        # Parse version from output
        for line in (r.stdout + r.stderr).splitlines():
            if "nikto" in line.lower() and "v" in line.lower():
                match = re.search(r'v?(\d+\.\d+\.\d+)', line)
                if match:
                    return match.group(1)
    except Exception:
        pass
    return "unknown"


# ============================================================
# Nikto Runner
# ============================================================

def run_nikto(
    target,
    port=443,
    ssl=True,
    timeout=180,
    tuning=None,
    max_time=None,
    verbose=False,
):
    """
    Run Nikto scan on target.

    Args:
        target: hostname or IP
        port: port to scan (default 443)
        ssl: force SSL (default True for 443)
        timeout: max seconds for scan
        tuning: scan tuning string (e.g. "123b" for specific tests)
        max_time: Nikto -maxtime (e.g. "120s")
        verbose: show live output

    Returns:
        dict with findings, metadata
    """
    result = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "port": port,
        "ssl": ssl,
        "available": is_nikto_available(),
        "version": None,
        "findings": [],
        "target_info": {},
        "summary": {
            "total": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
        "error": None,
        "duration": 0,
    }

    if not result["available"]:
        result["error"] = "nikto not installed (apt install nikto)"
        return result

    result["version"] = get_nikto_version()

    # Build command
    cmd = ["nikto", "-h", target, "-p", str(port), "-nointeractive", "-ask", "no"]

    if ssl:
        cmd.append("-ssl")

    if tuning:
        cmd.extend(["-Tuning", tuning])

    if max_time:
        cmd.extend(["-maxtime", max_time])

    # Output to temp file (JSON format if supported, else txt)
    tmp_json = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    tmp_json_path = tmp_json.name
    tmp_json.close()

    # Nikto 2.5+ supports JSON output via -Format json
    cmd.extend(["-Format", "json", "-o", tmp_json_path])

    start = datetime.now()

    try:
        if verbose:
            print(f"  [*] Running: {' '.join(cmd)}")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        result["duration"] = (datetime.now() - start).total_seconds()

        # Try JSON parse first
        parsed = _parse_json_output(tmp_json_path)

        if not parsed:
            # Fallback: parse stdout
            parsed = _parse_text_output(proc.stdout + proc.stderr)

        if parsed:
            result["findings"] = parsed.get("findings", [])
            result["target_info"] = parsed.get("target_info", {})

            # Compute summary
            for f in result["findings"]:
                result["summary"]["total"] += 1
                sev = f.get("severity", "info").lower()
                if sev in result["summary"]:
                    result["summary"][sev] += 1

    except subprocess.TimeoutExpired:
        result["error"] = f"Nikto timeout after {timeout}s"
    except Exception as e:
        result["error"] = str(e)
    finally:
        # Cleanup
        try:
            os.unlink(tmp_json_path)
        except Exception:
            pass

    return result


# ============================================================
# Parsers
# ============================================================

def _parse_json_output(path):
    """Parse Nikto JSON output."""
    if not os.path.exists(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
    except Exception:
        return None

    if not content:
        return None

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return None

    # Nikto JSON structure varies by version [citation:9]
    findings = []

    # Find target info
    target_info = {}
    if "target" in data and isinstance(data["target"], dict):
        target_info = data["target"]
    elif "host" in data:
        target_info = {
            "host": data.get("host"),
            "ip": data.get("ip"),
            "port": data.get("port"),
            "banner": data.get("banner"),
        }

    # Find findings array
    raw_findings = (
        data.get("findings")
        or data.get("alerts")
        or data.get("items")
        or data.get("vulnerabilities")
        or []
    )

    for item in raw_findings:
        if not isinstance(item, dict):
            continue

        finding = {
            "id": item.get("id") or item.get("test_id") or item.get("plugin_id"),
            "method": item.get("method", "GET"),
            "url": item.get("url") or item.get("path"),
            "message": (
                item.get("msg")
                or item.get("message")
                or item.get("description")
                or item.get("text")
            ),
            "osvdb": item.get("osvdb") or item.get("osvdb_id"),
            "severity": _classify_severity(item),
        }

        if finding["message"]:
            findings.append(finding)

    return {"findings": findings, "target_info": target_info}


def _parse_text_output(text):
    """Fallback: parse Nikto text output."""
    findings = []
    target_info = {}

    # Target info: Server header
    server_match = re.search(r'\+ Server:\s*(.+)', text)
    if server_match:
        target_info["server"] = server_match.group(1).strip()

    # Target IP
    ip_match = re.search(r'\+ Target IP:\s*([^\s]+)', text)
    if ip_match:
        target_info["ip"] = ip_match.group(1).strip()

    # Findings: lines starting with "+ "
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("+ ") and not line.startswith("+ Target") and not line.startswith("+ Server") and not line.startswith("+ Start"):
            msg = line[2:].strip()

            # Skip generic info
            if any(skip in msg.lower() for skip in ["no cgi", "no end", "starting", "completed"]):
                continue

            # Try to extract URL
            url_match = re.search(r'(/[^\s:]*)', msg)
            url = url_match.group(1) if url_match else None

            # Try OSVDB
            osvdb_match = re.search(r'OSVDB-(\d+)', msg)

            findings.append({
                "id": None,
                "method": "GET",
                "url": url,
                "message": msg,
                "osvdb": osvdb_match.group(1) if osvdb_match else None,
                "severity": _classify_severity({"message": msg}),
            })

    return {"findings": findings, "target_info": target_info}


def _classify_severity(item):
    """Classify Nikto finding severity."""
    text = (item.get("message") or "").lower()
    osvdb = item.get("osvdb")

    # Critical keywords
    if any(kw in text for kw in [
        "remote code execution", "rce", "command execution",
        "sql injection", "sqli", "shell", "backdoor",
        "authentication bypass", "password", "default cred",
    ]):
        return "high"

    # Medium
    if any(kw in text for kw in [
        "xss", "cross site scripting", "csrf", "file upload",
        "directory listing", "exposed", "information disclosure",
        "outdated", "vulnerable", "phpinfo",
    ]):
        return "medium"

    # OSVDB reference = known vuln
    if osvdb:
        return "medium"

    # Info
    if any(kw in text for kw in [
        "server", "banner", "header", "cookie",
        "allows", "found", "identified",
    ]):
        return "info"

    return "low"


# ============================================================
# Report
# ============================================================

def print_nikto_report(result):
    """Print Nikto results."""
    print("\n" + "=" * 70)
    print("  Nikto Vulnerability Scan - ReconX")
    print("=" * 70)

    if not result.get("available"):
        print(f"\n[!] {result.get('error', 'Nikto not available')}")
        print(f"    Install: apt install nikto")
        return

    if result.get("error"):
        print(f"\n[!] {result['error']}")
        return

    print(f"\n[*] Target:    {result['target']}:{result['port']}")
    print(f"[*] Nikto:     v{result.get('version', '?')}")
    print(f"[*] SSL:       {'yes' if result['ssl'] else 'no'}")
    print(f"[*] Duration:  {result.get('duration', 0):.1f}s")

    info = result.get("target_info", {})
    if info.get("server"):
        print(f"[*] Server:    {info['server']}")
    if info.get("ip"):
        print(f"[*] Target IP: {info['ip']}")

    findings = result.get("findings", [])
    summary = result.get("summary", {})

    print(f"\n[*] Findings:  {summary.get('total', 0)} total")
    print(f"    🔴 High:    {summary.get('high', 0)}")
    print(f"    🟡 Medium:  {summary.get('medium', 0)}")
    print(f"    🔵 Low:     {summary.get('low', 0)}")
    print(f"    ⚪ Info:    {summary.get('info', 0)}")

    if findings:
        # Sort by severity
        sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        findings_sorted = sorted(
            findings,
            key=lambda x: sev_order.get(x.get("severity", "info"), 99)
        )

        print(f"\n[+] Findings:")
        for f in findings_sorted[:30]:
            sev = f.get("severity", "info")
            icon = {"high": "🔴", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev, "⚪")
            msg = (f.get("message") or "")[:80]
            url = f.get("url") or ""
            osvdb = f.get("osvdb")

            print(f"    {icon} {msg}")
            if url:
                print(f"       → {url}")
            if osvdb:
                print(f"       → OSVDB-{osvdb}")

        if len(findings_sorted) > 30:
            print(f"    ... and {len(findings_sorted) - 30} more")

    if not findings:
        print(f"\n[OK] No vulnerabilities found")

    print("\n" + "=" * 70 + "\n")


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.network.nikto_scan <target> [port]")
        print("Example: python -m modules.network.nikto_scan example.com 443")
        sys.exit(1)

    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    print(f"\n[*] Nikto scan: {target}:{port}")
    result = run_nikto(target, port=port, ssl=(port == 443))
    print_nikto_report(result)
