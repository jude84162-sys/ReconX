# modules/vuln/dirb_engine.py
"""ReconX - DIRB Enhanced Engine.

DIRB is a web content scanner that brute-forces directories and files.
This wrapper adds:
  - Enhanced parsing (status, size, redirects)
  - Severity classification
  - Confidence scoring
  - Sensitivity detection (.env, .git, admin, etc.)
  - JSON/HTML output
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

logger = logging.getLogger("ReconX.dirb")


# ============================================================
# Availability
# ============================================================

def is_dirb_available():
    return shutil.which("dirb") is not None


def get_dirb_version():
    if not is_dirb_available():
        return None
    try:
        r = subprocess.run(["dirb"], capture_output=True, text=True, timeout=5)
        text = r.stdout + r.stderr
        for line in text.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+)", line)
            if m and "version" in line.lower():
                return m.group(1)
    except Exception:
        pass
    return "unknown"


def get_wordlists():
    """Find available DIRB wordlists."""
    paths = [
        "/usr/share/dirb/wordlists",
        "/usr/share/wordlists/dirb",
        "/opt/dirb/wordlists",
    ]
    wordlists = {}
    for base in paths:
        if os.path.isdir(base):
            for f in sorted(os.listdir(base)):
                if f.endswith(".txt"):
                    wordlists[f] = os.path.join(base, f)
    return wordlists


# ============================================================
# Sensitivity Classification
# ============================================================

SENSITIVE_PATHS = {
    # (pattern, severity)
    r"\.env": ("critical", "Environment file — may contain secrets"),
    r"\.git": ("critical", "Git metadata — full source leak"),
    r"\.svn": ("high", "SVN metadata exposed"),
    r"\.hg": ("high", "Mercurial metadata exposed"),
    r"\.htaccess": ("high", "Apache config exposed"),
    r"\.htpasswd": ("critical", "Apache password file"),
    r"\.DS_Store": ("medium", "macOS metadata"),
    r"wp-config": ("critical", "WordPress config"),
    r"config\.php": ("critical", "PHP config file"),
    r"configuration\.php": ("critical", "Joomla config"),
    r"settings\.php": ("high", "PHP settings"),
    r"database\.yml": ("critical", "Database credentials"),
    r"docker-compose": ("high", "Docker orchestration"),
    r"Dockerfile": ("medium", "Docker build config"),
    r"\.sql": ("critical", "Database dump"),
    r"backup": ("high", "Backup file"),
    r"\.bak$": ("high", "Backup file"),
    r"\.old$": ("medium", "Old file"),
    r"admin": ("medium", "Admin panel"),
    r"phpmyadmin": ("high", "phpMyAdmin"),
    r"phpinfo": ("high", "PHP info"),
    r"server-status": ("high", "Apache status"),
    r"server-info": ("high", "Apache info"),
    r"\.well-known": ("info", "Well-known dir"),
    r"robots\.txt": ("info", "Robots file"),
    r"sitemap": ("info", "Sitemap"),
    r"\.log$": ("high", "Log file"),
    r"error\.log": ("high", "Error log"),
    r"access\.log": ("high", "Access log"),
    r"test": ("low", "Test file"),
    r"tmp": ("medium", "Temporary file"),
    r"temp": ("medium", "Temporary file"),
    r"\.swp$": ("medium", "Editor swap file"),
    r"\.save$": ("medium", "Editor save file"),
}


def _classify_path(path):
    """Classify path sensitivity."""
    lower = path.lower()
    for pattern, (severity, desc) in SENSITIVE_PATHS.items():
        if re.search(pattern, lower):
            return severity, desc
    return "info", "Regular path"


# ============================================================
# Run DIRB
# ============================================================

def run_dirb(target, wordlist=None, extensions=None, timeout=300,
             recurse=False, verbose=False, extra_args=None):
    """Run DIRB scan on target."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "wordlist": wordlist,
        "available": is_dirb_available(),
        "version": None,
        "findings": [],
        "summary": {},
        "error": None,
        "duration": 0,
    }

    if not result["available"]:
        result["error"] = "dirb not installed (sudo apt install dirb)"
        return result

    result["version"] = get_dirb_version()

    # Auto-pick wordlist
    if not wordlist:
        wordlists = get_wordlists()
        if "common.txt" in wordlists:
            wordlist = wordlists["common.txt"]
        elif wordlists:
            wordlist = list(wordlists.values())[0]
        else:
            wordlist = "/usr/share/dirb/wordlists/common.txt"

    result["wordlist"] = wordlist

    # Build command
    cmd = ["dirb", target, wordlist]

    if extensions:
        cmd.extend(["-X", extensions])

    if recurse:
        cmd.append("-r")

    # Silent-ish output to file
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8")
    tmp_path = tmp.name
    tmp.close()

    cmd.extend(["-o", tmp_path])
    cmd.append("-S")  # Silent mode

    if extra_args:
        cmd.extend(extra_args)

    start = datetime.now()
    try:
        if verbose:
            print(f"    [>] {' '.join(cmd)}")

        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        result["duration"] = (datetime.now() - start).total_seconds()

        # Parse output file
        if os.path.exists(tmp_path):
            result["findings"] = _parse_dirb_output(tmp_path)

    except subprocess.TimeoutExpired:
        result["error"] = f"timeout after {timeout}s"
        # Still try to parse partial output
        if os.path.exists(tmp_path):
            result["findings"] = _parse_dirb_output(tmp_path)
    except Exception as e:
        result["error"] = str(e)
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    # Summary
    by_sev = {}
    for f in result["findings"]:
        s = f.get("severity", "info")
        by_sev[s] = by_sev.get(s, 0) + 1

    result["summary"] = {
        "total": len(result["findings"]),
        "by_severity": by_sev,
    }

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    result["findings"].sort(
        key=lambda x: (sev_order.get(x.get("severity", "info"), 99),
                       x.get("path", ""))
    )

    return result


# ============================================================
# Parse DIRB Output
# ============================================================

def _parse_dirb_output(path):
    """Parse DIRB output file."""
    findings = []

    # DIRB output format:
    # + http://example.com/admin (CODE:200|SIZE:1234)
    # ==> DIRECTORY: http://example.com/admin/
    # + http://example.com/robots.txt (CODE:200|SIZE:234)
    pattern = re.compile(
        r'\+?\s*(?:\+?\s*)?(https?://\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)'
    )
    dir_pattern = re.compile(r'==>\s+DIRECTORY:\s+(https?://\S+)')

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return findings

    for match in pattern.finditer(content):
        url, status, size = match.groups()
        status = int(status)
        size = int(size)

        # Extract path from URL
        path_match = re.search(r'https?://[^/]+(/.+?)$', url)
        path_str = path_match.group(1) if path_match else "/"

        severity, desc = _classify_path(path_str)

        # Skip 404s (DIRB usually filters)
        if status == 404:
            continue

        # Confidence
        confidence = 0.85
        if status == 200 and size > 0:
            confidence = 0.95
        elif status in (301, 302):
            confidence = 0.80

        findings.append({
            "path": path_str,
            "url": url,
            "status": status,
            "size": size,
            "severity": severity,
            "confidence": confidence,
            "description": desc,
            "source": "dirb",
        })

    # Add directories (may not be in pattern above)
    for match in dir_pattern.finditer(content):
        url = match.group(1)
        # Skip if already captured
        if any(f["url"].rstrip("/") == url.rstrip("/") for f in findings):
            continue

        path_match = re.search(r'https?://[^/]+(/.+?)$', url)
        path_str = path_match.group(1) if path_match else "/"

        severity, desc = _classify_path(path_str)

        findings.append({
            "path": path_str,
            "url": url,
            "status": 200,
            "size": 0,
            "severity": severity,
            "confidence": 0.75,
            "description": f"Directory: {desc}",
            "source": "dirb",
        })

    return findings


# ============================================================
# Report
# ============================================================

def print_dirb_report(result):
    print("\n" + "=" * 70)
    print("  DIRB Enhanced Engine — ReconX")
    print("=" * 70)

    if not result.get("available"):
        print(f"\n[!] {result.get('error', 'DIRB not available')}")
        print(f"    Install: sudo apt install dirb")
        return

    if result.get("error") and not result.get("findings"):
        print(f"\n[!] {result['error']}")
        return

    print(f"\n[*] Target:    {result.get('target')}")
    print(f"[*] DIRB:      v{result.get('version', '?')}")
    print(f"[*] Wordlist:  {result.get('wordlist')}")
    print(f"[*] Duration:  {result.get('duration', 0):.1f}s")

    summary = result.get("summary", {})
    print(f"\n[*] Total:     {summary.get('total', 0)} paths")

    by_sev = summary.get("by_severity", {})
    icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    if by_sev:
        print(f"\n[*] By severity:")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_sev:
                print(f"    {icons[sev]} {sev.capitalize():<10} {by_sev[sev]}")

    findings = result.get("findings", [])
    if findings:
        print(f"\n[+] Findings:")
        for f in findings[:40]:
            sev = f.get("severity", "info")
            icon = icons.get(sev, "⚪")
            print(f"\n  {icon} [{f['status']}] {f['path']}")
            print(f"       Size: {f['size']} B  |  Confidence: {f['confidence']:.2f}")
            print(f"       {f['description']}")

        if len(findings) > 40:
            print(f"\n    ... and {len(findings) - 40} more")
    else:
        print(f"\n[OK] No paths found")

    print("\n" + "=" * 70 + "\n")


def save_dirb_report(result, output_dir="outputs"):
    """Save DIRB report to JSON."""
    p = Path(output_dir)
    p.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = result.get("target", "unknown").replace("://", "_").replace("/", "_")[:50]
    fp = p / f"dirb_{target}_{ts}.json"

    with open(fp, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)

    return fp


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.dirb_engine <url> [wordlist]")
        print("")
        print("Available wordlists:")
        for name, path in get_wordlists().items():
            print(f"  {name:<25} {path}")
        sys.exit(1)

    target = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"\n[*] DIRB scan: {target}")
    result = run_dirb(target, wordlist=wordlist, verbose=True)
    print_dirb_report(result)
