#!/usr/bin/env python3
"""
ReconX - Comprehensive Web Recon (v5.0 — Parallel)
=================================================
All-in-one web reconnaissance combining 8 tools:
  1. Domain OSINT
  2. IP OSINT (multi-source, multi-IP)
  3. Port Scanner
  4. DNS Deep Recon
  5. Subdomain Enumeration
  6. Web Fingerprint
  7. SSL/TLS Analysis
  8. Directory Buster

v2 changes:
  - Parallel execution of independent steps
  - Multi-IP support (scans up to 3 IPs)
  - Graceful failure handling
  - Better progress reporting

Usage:
    python recon.py <domain>
    python recon.py <domain> --fast
    python recon.py <domain> --json
    python recon.py <domain> --output report.json
    python recon.py <domain> --max-ips 5
"""

import sys
import json
import time
import logging
import argparse
import concurrent.futures
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

# Time limits (seconds) for the parallel stage. A step still running at its
# limit is reported as timed out and its result is left out of the report.
STEP_TIMEOUT = 300
STEP_TIMEOUTS = {"subdomains": 480}
RECON_DEADLINE = 600
SCREENSHOT_TIMEOUT = 600

# Deep-mode dirb step: threaded scan of the dirb wordlist
DIRB_WORKERS = 30
DIRB_BUDGET = 120


# ============================================================
# Colors
# ============================================================

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    MAGENTA = "\033[95m"


# ============================================================
# Banner
# ============================================================

def banner(target, deep=True):
    mode = "DEEP" if deep else "FAST"
    print(f"""
{C.CYAN}╔══════════════════════════════════════════════════════════════════╗
║  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗                     ║
║  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║                     ║
║  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║                     ║
║  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║                     ║
║  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║                     ║
║  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝                     ║
║                                                                  ║
║           Comprehensive Web Recon  [{mode} MODE] v5.0            ║
╚══════════════════════════════════════════════════════════════════╝{C.RESET}

{C.BOLD}  🎯 Target:{C.RESET} {C.YELLOW}{target}{C.RESET}
{C.BOLD}  📅 Time:{C.RESET}   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
""")


def section(num, total, title):
    print(f"\n{C.CYAN}{'─' * 70}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  [{num}/{total}] {title}{C.RESET}")
    print(f"{C.CYAN}{'─' * 70}{C.RESET}")


# ============================================================
# Step Wrapper (captures exceptions)
# ============================================================

def _safe_step(name, fn, *args, **kwargs):
    """Run a step and capture any exception."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        print(f"  {C.RED}✗ [{name}] failed: {e}{C.RESET}")
        import traceback
        traceback.print_exc()
        return {}


# ============================================================
# 1. Domain OSINT
# ============================================================

def step_domain(target, ips=None):
    section(1, 14, "🌐 Domain OSINT")
    try:
        from modules.web.domain_osint import run_domain_osint
        result = run_domain_osint(target, deep=False, ips=ips)

        ips = result.get("ips", {}).get("A", [])
        subs = result.get("subdomains", [])
        whois = result.get("whois", {})

        print(f"  {C.GREEN}✓{C.RESET} IPs resolved:       {len(ips)}")
        for ip in ips[:5]:
            print(f"      • {ip}")
        print(f"  {C.GREEN}✓{C.RESET} Subdomains found:   {len(subs)}")
        for s in subs[:5]:
            print(f"      → {s['hostname']}")

        if whois.get("registrar"):
            print(f"  {C.GREEN}✓{C.RESET} Registrar:          {whois['registrar']}")
        if whois.get("creation_date"):
            print(f"  {C.GREEN}✓{C.RESET} Created:            {whois['creation_date']}")
        if whois.get("expiry_date"):
            print(f"  {C.GREEN}✓{C.RESET} Expires:            {whois['expiry_date']}")

        return result
    except Exception as e:
        print(f"  {C.RED}✗ Domain OSINT failed: {e}{C.RESET}")
        return {}


# ============================================================
# 2. IP OSINT (multi-IP)
# ============================================================

def step_ip_multi(ips, max_ips=3):
    section(2, 14, f"🌍 IP OSINT (checking {min(len(ips), max_ips)} of {len(ips)})")
    if not ips:
        print(f"  {C.YELLOW}⏭ Skipped (no IP resolved){C.RESET}")
        return {"results": [], "consensus": {}}

    try:
        from modules.network.ip_osint import run_ip_osint

        ips_to_check = ips[:max_ips]
        results = []

        # Parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_ips) as ex:
            futures = {ex.submit(run_ip_osint, ip): ip for ip in ips_to_check}
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                try:
                    r = future.result(timeout=20)
                    results.append({"ip": ip, "data": r})
                except Exception as e:
                    print(f"  {C.RED}✗ IP {ip} failed: {e}{C.RESET}")

        # Print
        for item in results:
            ip = item["ip"]
            r = item["data"]
            cons = r.get("consensus", {})
            print(f"\n  {C.BOLD}• {ip}{C.RESET}")
            print(f"      Country: {cons.get('country', '?')} ({cons.get('country_code', '?')})")
            print(f"      City:    {cons.get('city', '?')}")
            print(f"      ISP:     {cons.get('isp', '?')}")
            print(f"      ASN:     {cons.get('asn', '?')}")

            flags = []
            if cons.get("is_proxy"):
                flags.append("🔴 PROXY/VPN")
            if cons.get("is_hosting"):
                flags.append("🟡 HOSTING")
            if cons.get("is_mobile"):
                flags.append("📱 MOBILE")
            if flags:
                print(f"      Flags:   {', '.join(flags)}")

        # Return primary result (for backwards compat) - strip circular refs
        primary = {k: v for k, v in results[0]["data"].items() if k not in ("_all_results", "_all_ips")} if results else {}
        return primary

    except Exception as e:
        print(f"  {C.RED}✗ IP OSINT failed: {e}{C.RESET}")
        return {}


# ============================================================
# 3. Port Scanner
# ============================================================

def step_ports(primary_ip, fast=False):
    section(3, 14, "🔍 Port Scanner")
    if not primary_ip:
        print(f"  {C.YELLOW}⏭ Skipped (no IP){C.RESET}")
        return {}

    try:
        from modules.network.port_scan import scan_port_range, get_ports
        preset = "top100" if fast else "common"
        ports = get_ports(preset)

        print(f"  {C.GRAY}Scanning {len(ports)} ports on {primary_ip}...{C.RESET}\n")

        def progress(done, total):
            pct = (done / total) * 100
            bar_len = 30
            filled = int(bar_len * done / total)
            bar = "█" * filled + "░" * (bar_len - filled)
            sys.stdout.write(f"\r  {C.CYAN}{bar}{C.RESET} {pct:5.1f}% ({done}/{total})")
            sys.stdout.flush()

        result = scan_port_range(
            primary_ip, ports,
            workers=100, grab_banner=True,
            progress_callback=progress,
        )
        print()

        open_ports = result.get("open_ports", [])
        print(f"  {C.GREEN}✓{C.RESET} Open ports:         {len(open_ports)}")
        print(f"  {C.GREEN}✓{C.RESET} Duration:           {result.get('scan_duration', 0):.1f}s")

        for p in open_ports[:15]:
            banner_txt = (p.get("banner") or "")[:45]
            print(f"      • {p['port']:<6} {p['service']:<15} {banner_txt}")

        vulns = [p for p in open_ports if p.get("vuln_hint")]
        if vulns:
            print(f"\n  {C.YELLOW}⚠ Vulnerability hints:{C.RESET}")
            for p in vulns[:5]:
                print(f"      ⚠ Port {p['port']}: {p['vuln_hint']}")

        return result
    except Exception as e:
        print(f"  {C.RED}✗ Port scan failed: {e}{C.RESET}")
        return {}


# ============================================================
# 4. DNS Deep
# ============================================================

def step_dns(target):
    section(4, 14, "🌐 DNS Deep Recon")
    try:
        from modules.network.dns_deep import run_dns_deep
        result = run_dns_deep(target)
        s = result.get("summary", {})

        print(f"  {C.GREEN}✓{C.RESET} Nameservers:        {s.get('nameservers', 0)}")
        for ns in result.get("nameservers", [])[:5]:
            print(f"      • {ns}")

        print(f"  {C.GREEN}✓{C.RESET} MX records:         {s.get('mx_records', 0)}")
        for mx in result.get("mx", [])[:5]:
            if isinstance(mx, dict):
                print(f"      • {mx['priority']:>3}  {mx['host']}")
            else:
                print(f"      • {str(mx)[:70]}")

        print(f"  {C.GREEN}✓{C.RESET} TXT records:        {s.get('txt_records', 0)}")

        spf_mark = f"{C.GREEN}✓{C.RESET}" if s.get("has_spf") else f"{C.RED}✗{C.RESET}"
        dmarc_mark = f"{C.GREEN}✓{C.RESET}" if s.get("has_dmarc") else f"{C.RED}✗{C.RESET}"
        print(f"  {spf_mark} SPF record:         {'present' if s.get('has_spf') else 'MISSING'}")
        print(f"  {dmarc_mark} DMARC record:       {'present' if s.get('has_dmarc') else 'MISSING'}")

        if result.get("zone_transfer"):
            print(f"\n  {C.RED}{C.BOLD}🔴 ZONE TRANSFER SUCCEEDED!{C.RESET}")
            print(f"      Nameserver: {result['zone_transfer']['nameserver']}")

        for level, reason in result.get("indicators", []):
            marker = "🔴" if level == "CRITICAL" else "🟡" if level == "MEDIUM" else "🔵"
            print(f"  {marker} [{level}] {reason}")

        return result
    except Exception as e:
        print(f"  {C.RED}✗ DNS Deep failed: {e}{C.RESET}")
        return {}


# ============================================================
# 5. Subdomain Enumeration
# ============================================================

def step_subdomains(target, deep=True):
    section(5, 14, "🌐 Subdomain Enumeration")
    if not deep:
        print(f"  {C.YELLOW}⏭ Skipped (fast mode){C.RESET}")
        return {}

    try:
        from modules.web.subdomain_enum import run_subdomain_enum
        print(f"  {C.GRAY}Running 7 passive sources + bruteforce...{C.RESET}")
        result = run_subdomain_enum(target)

        total = result.get("total_unique", 0)
        by_src = result.get("by_source", {})

        print(f"\n  {C.GREEN}✓{C.RESET} Total found:        {total}")
        for src, count in sorted(by_src.items()):
            marker = "✓" if count > 0 else "·"
            print(f"      {marker} {src:<20} {count}")
        if result.get("wildcard"):
            print(f"  {C.YELLOW}⚠ Wildcard DNS ({', '.join(result.get('wildcard_ips', [])[:3])}): "
                  f"brute-force hits on the wildcard IPs were dropped{C.RESET}")

        if result.get("subdomains"):
            print(f"\n  {C.BOLD}Top subdomains:{C.RESET}")
            for s in result["subdomains"][:15]:
                print(f"      → {s['hostname']:<45} {s['ip']}")

            # Which of them actually serve HTTP(S)? Names that never
            # resolved cannot answer, so they are not probed.
            resolved = [s["hostname"] for s in result["subdomains"]
                        if s.get("ip") or s.get("ipv6")]
            skipped = len(result["subdomains"]) - len(resolved)
            note = f" ({skipped} unresolved skipped)" if skipped else ""
            try:
                from modules.web.live_probe import probe_hosts
                print(f"\n  {C.GRAY}Probing HTTP(S) on {len(resolved)} resolved "
                      f"subdomains{note}...{C.RESET}")
                probe = probe_hosts(resolved, timeout=5)
                result["live"] = probe
                print(f"  {C.GREEN}✓{C.RESET} Live web hosts:    {probe['alive']} "
                      f"(of {probe['total']})")
                for entry in probe["results"]:
                    if entry.get("alive"):
                        print(f"      🌐 {entry['url']:<45} "
                              f"[{entry['status']}] {entry.get('title') or ''}"[:110])
            except Exception as e:
                print(f"  {C.YELLOW}⚠ Live host probe failed: {e}{C.RESET}")

        return result
    except Exception as e:
        print(f"  {C.RED}✗ Subdomain enum failed: {e}{C.RESET}")
        return {}


# ============================================================
# Optional Stage: Screenshots of live hosts
# ============================================================

def step_screenshots(target, subs, outdir=None):
    """Capture the live subdomains (or the target itself) after the scan."""
    print(f"\n{C.CYAN}{'═' * 70}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  📸 Screenshotting Live Hosts{C.RESET}")
    print(f"{C.CYAN}{'═' * 70}{C.RESET}\n")

    from modules.web.aquatone_clone import (
        backend_hint, is_screenshot_available, print_screenshot_report, run_screenshots,
    )

    live = [r["url"] for r in (subs.get("live") or {}).get("results", []) if r.get("alive")]
    if not live:
        print(f"  {C.GRAY}No live subdomains — capturing the target itself{C.RESET}")
        live = [target]

    if not is_screenshot_available():
        print(f"  {C.YELLOW}⚠ No screenshot backend — {backend_hint()}{C.RESET}")
        return {}

    print(f"  {C.GRAY}Capturing {len(live)} host(s)...{C.RESET}")
    result = run_screenshots(
        live,
        outdir=outdir or "outputs/screenshots",
        source=target,
        verbose=True,
    )
    print_screenshot_report(result)
    return result


# ============================================================
# 6. Web Fingerprint
# ============================================================

def step_fingerprint(target):
    section(6, 14, "🌍 Web Fingerprint")
    try:
        from modules.web.web_fingerprint import run_web_fingerprint
        result = run_web_fingerprint(target)

        if result.get("error"):
            print(f"  {C.YELLOW}⚠ {result['error']}{C.RESET}")
            return result

        print(f"  {C.GREEN}✓{C.RESET} Status:             {result.get('status', '?')}")
        print(f"  {C.GREEN}✓{C.RESET} Server:             {result.get('server', '?')}")
        print(f"  {C.GREEN}✓{C.RESET} Powered by:         {result.get('powered_by', '?')}")
        if result.get("title"):
            print(f"  {C.GREEN}✓{C.RESET} Title:              {result['title'][:70]}")

        techs = result.get("technologies", [])
        if techs:
            print(f"\n  {C.BOLD}Technologies ({len(techs)}):{C.RESET}")
            by_type = {}
            for t in techs:
                by_type.setdefault(t["type"], []).append(t["name"])
            for ttype, names in sorted(by_type.items()):
                print(f"      [{ttype}] {', '.join(names)}")

        headers = result.get("security_headers", {})
        if headers:
            print(f"\n  {C.BOLD}Security headers present ({len(headers)}):{C.RESET}")
            for h in headers:
                print(f"      ✓ {h}")

        missing = result.get("missing_headers", [])
        if missing:
            print(f"\n  {C.YELLOW}⚠ Missing headers ({len(missing)}):{C.RESET}")
            for h in missing[:10]:
                print(f"      ✗ {h}")

        return result
    except Exception as e:
        print(f"  {C.RED}✗ Web fingerprint failed: {e}{C.RESET}")
        return {}


# ============================================================
# 7. SSL/TLS (graceful failure)
# ============================================================

def step_ssl(target):
    section(7, 14, "🔐 SSL/TLS Analysis")
    try:
        from modules.network.ssl_analyzer import run_ssl_analyzer
        result = run_ssl_analyzer(target)

        # Graceful failure check
        if result.get("error"):
            print(f"  {C.YELLOW}⚠ SSL unavailable: {result['error']}{C.RESET}")
            print(f"  {C.GRAY}  (target may not support HTTPS on port 443){C.RESET}")
            return result

        # Guard: grade may be None
        grade = result.get("grade") or "?"
        if grade == "?":
            print(f"  {C.YELLOW}⚠ Could not determine grade{C.RESET}")
            return result

        grade_color = C.GREEN if grade.startswith("A") else C.YELLOW if grade.startswith("B") else C.RED
        print(f"  {grade_color}✓ Grade:              {grade}{C.RESET}")
        print(f"  {C.GREEN}✓{C.RESET} Protocol:           {result.get('protocol', '?')}")

        if result.get("cipher"):
            c = result["cipher"]
            print(f"  {C.GREEN}✓{C.RESET} Cipher:             {c['name']} ({c['bits']} bits)")

        cert = result.get("certificate", {})
        if cert:
            subj = cert.get("subject", {})
            iss = cert.get("issuer", {})
            print(f"  {C.GREEN}✓{C.RESET} CN:                 {subj.get('commonName', '?')}")
            print(f"  {C.GREEN}✓{C.RESET} Issuer:             {iss.get('organizationName', '?')}")

            if cert.get("days_until_expiry") is not None:
                days = cert["days_until_expiry"]
                day_color = C.GREEN if days > 60 else C.YELLOW if days > 14 else C.RED
                print(f"  {day_color}✓ Expires in:         {days} days{C.RESET}")

        san = result.get("san_domains", [])
        if san:
            print(f"  {C.GREEN}✓{C.RESET} SAN domains:        {len(san)}")
            for d in san[:5]:
                print(f"      • {d}")

        for level, issue in result.get("issues", []):
            marker = "🔴" if level == "HIGH" else "🟡" if level == "MEDIUM" else "🔵"
            print(f"  {marker} [{level}] {issue}")

        return result
    except Exception as e:
        print(f"  {C.RED}✗ SSL analysis failed: {e}{C.RESET}")
        return {"error": str(e)}


# ============================================================
# 8. Directory Buster
# ============================================================

def step_dirs(target, deep=True):
    section(8, 14, "📂 Directory Buster")
    if not deep:
        print(f"  {C.YELLOW}⏭ Skipped (fast mode){C.RESET}")
        return {}

    try:
        from modules.web.dir_buster import run_dir_bust
        base_url = f"https://{target}"
        print(f"  {C.GRAY}Scanning common paths on {base_url}...{C.RESET}")
        result = run_dir_bust(base_url)

        found = result.get("found", [])
        print(f"\n  {C.GREEN}✓{C.RESET} Paths checked:      {result.get('total_checked', 0)}")
        print(f"  {C.GREEN}✓{C.RESET} Found:              {len(found)}")

        if result.get("soft_404_baseline"):
            b = result["soft_404_baseline"]
            print(f"  {C.GRAY}Soft-404 baseline:  status={b['status']}, size={b['size']}{C.RESET}")

        if found:
            print(f"\n  {C.BOLD}Found paths:{C.RESET}")
            sensitive = [".env", ".git", "wp-config", "backup", "admin", "phpmyadmin", "config"]
            for item in found[:20]:
                is_sensitive = any(s in item["path"].lower() for s in sensitive)
                marker = f"{C.RED}🔴{C.RESET}" if is_sensitive else f"{C.CYAN}•{C.RESET}"
                print(f"      {marker} [{item['status']}] {item['path']:<40} {item['size']} B")

        return result
    except Exception as e:
        print(f"  {C.RED}✗ Directory buster failed: {e}{C.RESET}")
        return {}


# ============================================================
# Summary Builder
# ============================================================



# ============================================================
# 9. Login Finder
# ============================================================

def step_login(target):
    section(9, 14, "🔐 Login Finder")
    try:
        from modules.web.login_finder import run_login_finder
        result = run_login_finder(target)

        found = result.get("found", [])
        print(f"  {C.GREEN}✓{C.RESET} Login pages found: {len(found)}")

        for item in found[:10]:
            conf = item["confidence"]
            marker = "🟢" if conf >= 0.85 else "🟡" if conf >= 0.65 else "🔵"
            print(f"      {marker} [{item['status']}] {item['url']} ({conf:.2f})")

        return result
    except Exception as e:
        print(f"  {C.RED}✗ Login finder failed: {e}{C.RESET}")
        return {}


# ============================================================
# 10. Register Finder
# ============================================================

def step_register(target):
    section(10, 14, "📝 Register Finder")
    try:
        from modules.web.register_finder import run_register_finder
        result = run_register_finder(target)

        found = result.get("found", [])
        print(f"  {C.GREEN}✓{C.RESET} Register pages found: {len(found)}")

        for item in found[:10]:
            conf = item["confidence"]
            marker = "🟢" if conf >= 0.85 else "🟡" if conf >= 0.65 else "🔵"
            print(f"      {marker} [{item['status']}] {item['url']} ({conf:.2f})")

        return result
    except Exception as e:
        print(f"  {C.RED}✗ Register finder failed: {e}{C.RESET}")
        return {}


# ============================================================
# 11. WAF Detector
# ============================================================

def step_waf(target):
    section(11, 14, "🛡️  WAF Detector")
    try:
        from modules.web.waf_detector import run_waf_detector
        result = run_waf_detector(target)

        wafs = result.get("wafs_detected", [])
        if wafs:
            print(f"  {C.GREEN}✓{C.RESET} WAF detected: {len(wafs)}")
            for w in wafs[:3]:
                conf = w["confidence"]
                marker = "🟢" if conf >= 0.80 else "🟡" if conf >= 0.50 else "🔵"
                print(f"      {marker} {w['waf']} (confidence: {conf:.2f})")
        else:
            print(f"  {C.GRAY}•{C.RESET} No WAF detected")

        blocked = result.get("blocked_payloads", 0)
        if blocked > 0:
            print(f"  {C.YELLOW}⚠ {blocked} suspicious payloads blocked{C.RESET}")

        return result
    except Exception as e:
        print(f"  {C.RED}✗ WAF detector failed: {e}{C.RESET}")
        return {}


# ============================================================
# 12. Param Finder
# ============================================================

def step_params(target):
    section(12, 14, "🔗 Parameter Finder")
    try:
        from modules.web.param_finder import run_param_finder
        result = run_param_finder(target)

        accepted = result.get("accepted", [])
        print(f"  {C.GREEN}✓{C.RESET} Accepted parameters: {len(accepted)}")

        for item in accepted[:10]:
            conf = item["confidence"]
            marker = "🟢" if conf >= 0.80 else "🟡" if conf >= 0.60 else "🔵"
            reflected = " ⚠ reflected" if item.get("reflected") else ""
            print(f"      {marker} {item['param']} ({conf:.2f}){reflected}")

        return result
    except Exception as e:
        print(f"  {C.RED}✗ Param finder failed: {e}{C.RESET}")
        return {}




# ============================================================
# 14. DIRB Content Scan
# ============================================================

def step_dirb_engine(target, deep=True):
    section(14, 14, "🎯 DIRB Content Scan")
    if not deep:
        print(f"  {C.YELLOW}⏭ Skipped (fast mode){C.RESET}")
        return {}

    try:
        from modules.vuln.dirb_engine import (
            default_wordlist, is_dirb_available, run_dirb, run_dirb_threaded,
        )

        base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        wordlist = default_wordlist()

        if wordlist:
            # dirb is single-threaded and would pin the run at its timeout;
            # scan the same wordlist with the threaded in-process buster.
            print(f"  [*] Scanning {base_url} with the dirb wordlist "
                  f"({DIRB_WORKERS} threads, budget {DIRB_BUDGET}s)...")
            result = run_dirb_threaded(base_url, wordlist=wordlist,
                                       workers=DIRB_WORKERS, budget=DIRB_BUDGET)
        else:
            if not is_dirb_available():
                print(f"  {C.YELLOW}⚠ DIRB not installed (sudo apt install dirb){C.RESET}")
                return {"available": False, "error": "not_installed"}

            print(f"  [*] Running DIRB on {base_url} (timeout 180s)...")
            result = run_dirb(base_url, timeout=180, verbose=False)

        findings = result.get("findings", [])
        summary = result.get("summary", {})

        if result.get("error") and not findings:
            print(f"  {C.YELLOW}⚠ DIRB error: {result['error']}{C.RESET}")
            return result

        by_sev = summary.get("by_severity", {})
        print(f"  {C.GREEN}✓{C.RESET} Paths found:  {len(findings)}")
        if result.get("error"):
            print(f"  {C.YELLOW}⚠ {result['error']}{C.RESET}")
        if by_sev:
            icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
            parts = []
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in by_sev:
                    parts.append(f"{icons[sev]}{by_sev[sev]}")
            print(f"      {' '.join(parts)}")

        # Show top findings
        for f in findings[:10]:
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(
                f.get("severity", "info"), "⚪"
            )
            print(f"      {icon} [{f['status']}] {f['path']}")

        return result

    except Exception as e:
        print(f"  {C.RED}✗ DIRB failed: {e}{C.RESET}")
        return {}



def build_summary(target, steps):
    domain = steps.get("domain", {})
    ip = steps.get("ip", {})
    ports = steps.get("ports", {})
    dns = steps.get("dns", {})
    subs = steps.get("subdomains", {})
    fp = steps.get("fingerprint", {})
    ssl_r = steps.get("ssl", {})
    dirs = steps.get("dir_bust", {})
    login = steps.get("login", {})
    register = steps.get("register", {})
    waf = steps.get("waf", {})
    params = steps.get("params", {})
    dirb = steps.get("dirb", {})

    indicators = []

    # Port vulns
    for p in ports.get("open_ports", []):
        if p.get("vuln_hint"):
            indicators.append({
                "severity": "MEDIUM",
                "category": "port",
                "detail": f"Port {p['port']}: {p['vuln_hint']}",
            })

    # DNS
    if not dns.get("summary", {}).get("has_spf"):
        indicators.append({
            "severity": "MEDIUM",
            "category": "dns",
            "detail": "No SPF record (email spoofing risk)",
        })
    if not dns.get("summary", {}).get("has_dmarc"):
        indicators.append({
            "severity": "MEDIUM",
            "category": "dns",
            "detail": "No DMARC record (email spoofing risk)",
        })
    if dns.get("zone_transfer"):
        indicators.append({
            "severity": "CRITICAL",
            "category": "dns",
            "detail": f"Zone transfer succeeded via {dns['zone_transfer']['nameserver']}",
        })

    # SSL
    for level, issue in ssl_r.get("issues", []):
        indicators.append({
            "severity": level,
            "category": "ssl",
            "detail": issue,
        })

    # Missing headers
    missing = fp.get("missing_headers", [])
    if missing:
        indicators.append({
            "severity": "LOW",
            "category": "headers",
            "detail": f"Missing security headers: {', '.join(missing[:3])}",
        })

    # Sensitive exposed paths
    sensitive = [".env", ".git", "wp-config", "backup", "phpmyadmin", "config"]
    for d in dirs.get("found", []):
        path = d.get("path", "").lower()
        for sp in sensitive:
            if sp in path:
                indicators.append({
                    "severity": "HIGH",
                    "category": "exposed",
                    "detail": f"Exposed sensitive path: {d['path']}",
                })
                break

    # IP proxy
    cons = ip.get("consensus", {})
    if cons.get("is_proxy"):
        indicators.append({
            "severity": "MEDIUM",
            "category": "ip",
            "detail": "Target behind proxy/VPN",
        })

    # Login pages exposed
    login_found = login.get("found", [])
    for lg in login_found:
        if lg.get("confidence", 0) >= 0.85:
            indicators.append({
                "severity": "LOW",
                "category": "login",
                "detail": f"Login page found: {lg['url']}",
            })

    # Register pages exposed
    register_found = register.get("found", [])
    for rg in register_found:
        if rg.get("confidence", 0) >= 0.85:
            indicators.append({
                "severity": "LOW",
                "category": "register",
                "detail": f"Registration page found: {rg['url']}",
            })

    # WAF detected
    wafs = waf.get("wafs_detected", [])
    if wafs:
        top_waf = wafs[0]
        indicators.append({
            "severity": "INFO",
            "category": "waf",
            "detail": f"WAF detected: {top_waf['waf']} ({top_waf['confidence']:.2f})",
        })

    # Reflected parameters (potential XSS surface)
    reflected_params = [p for p in params.get("accepted", []) if p.get("reflected")]
    for rp in reflected_params[:5]:
        indicators.append({
            "severity": "MEDIUM",
            "category": "params",
            "detail": f"Reflected parameter: {rp['param']} (potential XSS)",
        })

    # DIRB findings
    dirb_sev_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
    for df in dirb.get("findings", []):
        sev = dirb_sev_map.get(df.get("severity"))
        if sev:
            indicators.append({
                "severity": sev,
                "category": "dirb",
                "detail": f"Exposed path: {df.get('path', '?')} ({df.get('description', '')})",
            })

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for ind in indicators:
        sev_counts[ind["severity"]] = sev_counts.get(ind["severity"], 0) + 1

    primary_ip = None
    ips = domain.get("ips", {}).get("A", [])
    if ips:
        primary_ip = ips[0]

    return {
        "target": target,
        "primary_ip": primary_ip,
        "domain": {
            "ips": len(ips),
            "subdomains_in_domain": len(domain.get("subdomains", [])),
            "registrar": domain.get("whois", {}).get("registrar"),
        },
        "ip": {
            "country": cons.get("country"),
            "city": cons.get("city"),
            "isp": cons.get("isp"),
            "asn": cons.get("asn"),
            "is_proxy": cons.get("is_proxy", False),
        },
        "ports": {
            "scanned": ports.get("total_ports", 0),
            "open": len(ports.get("open_ports", [])),
        },
        "dns": dns.get("summary", {}),
        "subdomains": {
            "total": subs.get("total_unique", 0),
            "by_source": subs.get("by_source", {}),
            "live": subs.get("live", {}).get("alive", 0),
        },
        "fingerprint": {
            "technologies": len(fp.get("technologies", [])),
            "missing_headers": len(missing),
        },
        "ssl": {
            "grade": ssl_r.get("grade"),
            "protocol": ssl_r.get("protocol"),
        },
        "directories": {
            "checked": dirs.get("total_checked", 0),
            "found": len(dirs.get("found", [])),
        },
        "web": {
            "login_pages": len(login.get("found", [])),
            "register_pages": len(register.get("found", [])),
            "waf": [w["waf"] for w in waf.get("wafs_detected", [])][:3],
            "accepted_params": len(params.get("accepted", [])),
            "reflected_params": len([p for p in params.get("accepted", []) if p.get("reflected")]),
        },
        "dirb": {
            "total": dirb.get("summary", {}).get("total", 0),
            "by_severity": dirb.get("summary", {}).get("by_severity", {}),
        },
        "risk": {
            "severity_counts": sev_counts,
            "indicators": indicators,
            "total": len(indicators),
        },
        "timed_out_steps": [name for name, value in steps.items()
                            if isinstance(value, dict) and value.get("timed_out")],
    }


def print_summary(summary):
    print(f"\n{C.CYAN}{'═' * 70}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  📊 FINAL SUMMARY — {summary['target']}{C.RESET}")
    print(f"{C.CYAN}{'═' * 70}{C.RESET}\n")

    print(f"  {C.BOLD}{C.MAGENTA}🌐 DOMAIN{C.RESET}")
    print(f"    IPs:             {summary['domain']['ips']}")
    print(f"    Subdomains:      {summary['domain']['subdomains_in_domain']}")
    print(f"    Registrar:       {summary['domain']['registrar'] or '?'}")

    print(f"\n  {C.BOLD}{C.MAGENTA}🌍 IP{C.RESET}")
    print(f"    Primary:         {summary['primary_ip'] or '?'}")
    print(f"    Country:         {summary['ip']['country'] or '?'}")
    print(f"    City:            {summary['ip']['city'] or '?'}")
    print(f"    ISP:             {summary['ip']['isp'] or '?'}")
    print(f"    ASN:             {summary['ip']['asn'] or '?'}")

    print(f"\n  {C.BOLD}{C.MAGENTA}🔍 PORTS{C.RESET}")
    print(f"    Scanned:         {summary['ports']['scanned']}")
    print(f"    Open:            {summary['ports']['open']}")

    print(f"\n  {C.BOLD}{C.MAGENTA}🌐 DNS{C.RESET}")
    dns = summary.get("dns", {})
    print(f"    Nameservers:     {dns.get('nameservers', 0)}")
    print(f"    MX records:      {dns.get('mx_records', 0)}")
    print(f"    SPF:             {'✓' if dns.get('has_spf') else '✗'}")
    print(f"    DMARC:           {'✓' if dns.get('has_dmarc') else '✗'}")
    if dns.get("zone_transfer"):
        print(f"    {C.RED}ZONE TRANSFER:   SUCCEEDED!{C.RESET}")

    print(f"\n  {C.BOLD}{C.MAGENTA}🌐 SUBDOMAINS{C.RESET}")
    print(f"    Total:           {summary['subdomains']['total']}")
    print(f"    Live (HTTP):     {summary['subdomains'].get('live', 0)}")
    for src, count in summary['subdomains'].get('by_source', {}).items():
        print(f"    {src:<17} {count}")

    print(f"\n  {C.BOLD}{C.MAGENTA}🌍 WEB FINGERPRINT{C.RESET}")
    print(f"    Technologies:    {summary['fingerprint']['technologies']}")
    print(f"    Missing headers: {summary['fingerprint']['missing_headers']}")

    print(f"\n  {C.BOLD}{C.MAGENTA}🔐 SSL/TLS{C.RESET}")
    print(f"    Grade:           {summary['ssl']['grade']}")
    print(f"    Protocol:        {summary['ssl']['protocol']}")

    print(f"\n  {C.BOLD}{C.MAGENTA}📂 DIRECTORIES{C.RESET}")
    print(f"    Checked:         {summary['directories']['checked']}")
    print(f"    Found:           {summary['directories']['found']}")

    # Web recon additions
    web = summary.get("web", {})
    if web:
        print(f"\n  {C.BOLD}{C.MAGENTA}🔐 WEB DISCOVERY{C.RESET}")
        print(f"    Login pages:     {web.get('login_pages', 0)}")
        print(f"    Register pages:  {web.get('register_pages', 0)}")
        print(f"    Accepted params: {web.get('accepted_params', 0)}")
        print(f"    Reflected params: {web.get('reflected_params', 0)}")
        wafs = web.get("waf", [])
        print(f"    WAF:             {', '.join(wafs) if wafs else 'none detected'}")

    # DIRB
    dirb = summary.get("dirb", {})
    if dirb.get("total", 0) > 0:
        print(f"\n  {C.BOLD}{C.MAGENTA}🎯 DIRB{C.RESET}")
        print(f"    Paths found:     {dirb.get('total', 0)}")
        by_sev = dirb.get("by_severity", {})
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_sev:
                icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
                print(f"    {icons[sev]} {sev.capitalize():<10} {by_sev[sev]}")

    timed_out = summary.get("timed_out_steps") or []
    if timed_out:
        print(f"\n  {C.BOLD}{C.YELLOW}⏱ TIMED OUT (not in this report){C.RESET}")
        print(f"    Steps:           {', '.join(timed_out)}")

    risk = summary["risk"]
    counts = risk["severity_counts"]
    print(f"\n  {C.BOLD}{C.MAGENTA}⚠ RISK SUMMARY{C.RESET}")
    print(f"    🔴 Critical:     {counts['CRITICAL']}")
    print(f"    🟠 High:         {counts['HIGH']}")
    print(f"    🟡 Medium:       {counts['MEDIUM']}")
    print(f"    🔵 Low:          {counts['LOW']}")
    print(f"    {C.BOLD}Total:           {risk['total']}{C.RESET}")

    if risk["indicators"]:
        print(f"\n  {C.BOLD}{C.MAGENTA}INDICATORS{C.RESET}")
        for ind in risk["indicators"][:15]:
            marker = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🔵",
            }.get(ind["severity"], "⚪")
            print(f"    {marker} [{ind['severity']:<8}] {ind['detail']}")

    print(f"\n{C.CYAN}{'═' * 70}{C.RESET}\n")


# ============================================================
# Parallel runner with real time limits
# ============================================================

def _run_parallel(tasks, step_timeout=STEP_TIMEOUT, deadline=RECON_DEADLINE,
                  step_timeouts=None, on_done=None, extra_workers=0):
    """Run {name: (fn, args, kwargs)} at once and collect the results.

    Each step must finish within its own timeout (step_timeouts[name], else
    step_timeout) and within the overall deadline, both counted from the
    start. A step that misses its limit is recorded as
    {"error": ..., "timed_out": True, "partial": True}; its thread cannot be
    killed, so it keeps running in the background and its result is dropped.
    on_done(name, result, submit) runs as each step ends (or times out) and
    may start a follow-up step with submit(name, fn, args, kwargs, timeout),
    which is bounded by its own timeout only. A timeout or deadline of 0 or
    None means no limit. Returns (results, timed_out_names).
    """
    step_timeouts = step_timeouts or {}
    start = time.monotonic()
    hard_stop = start + deadline if deadline else None
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks) + extra_workers)
    names, limits, started = {}, {}, {}
    pending = set()
    results = {}
    timed_out = []

    def submit(name, fn, args=(), kwargs=None, timeout=None, stop=None):
        now = time.monotonic()
        limit = now + timeout if timeout else None
        if stop is not None:
            limit = stop if limit is None else min(limit, stop)
        future = ex.submit(_safe_step, name, fn, *args, **(kwargs or {}))
        names[future] = name
        limits[future] = limit
        started[future] = now
        pending.add(future)

    def finish(name, value):
        results[name] = value
        if on_done:
            on_done(name, value, submit)

    for name, (fn, args, kwargs) in tasks.items():
        submit(name, fn, args, kwargs,
               timeout=step_timeouts.get(name, step_timeout), stop=hard_stop)

    try:
        while pending:
            due = [limits[f] for f in pending if limits[f] is not None]
            wait_for = max(0.0, min(due) - time.monotonic()) if due else None
            done, _ = concurrent.futures.wait(
                pending, timeout=wait_for,
                return_when=concurrent.futures.FIRST_COMPLETED)

            for future in done:
                pending.discard(future)
                name = names[future]
                try:
                    value = future.result()
                except Exception as e:
                    print(f"{C.RED}✗ [{name}] thread failed: {e}{C.RESET}")
                    value = {}
                finish(name, value)

            now = time.monotonic()
            for future in [f for f in pending
                           if limits[f] is not None and limits[f] <= now]:
                pending.discard(future)
                future.cancel()
                name = names[future]
                elapsed = int(now - started[future])
                print(f"\n  {C.YELLOW}⏱ [{name}] timed out after {elapsed}s — "
                      f"left out of the report{C.RESET}")
                timed_out.append(name)
                finish(name, {"error": f"timeout after {elapsed}s",
                              "timed_out": True, "partial": True})
    finally:
        ex.shutdown(wait=False)

    return results, timed_out


# ============================================================
# Main Recon Runner (PARALLEL)
# ============================================================

def run_recon(target, deep=True, save_json=False, output_file=None, max_ips=3,
              screenshots=False, step_timeout=None, deadline=RECON_DEADLINE):
    """Run full web recon with parallel execution.

    step_timeout: seconds each step may take (None = per-step defaults,
    0 = no limit). deadline: seconds for the whole parallel stage (0 or
    None = no limit). Steps that miss a limit are reported as timed out.
    """
    target = target.strip().lower()
    if target.startswith(("http://", "https://")):
        target = target.split("://", 1)[1].rstrip("/")
    target = target.split("/")[0]

    banner(target, deep=deep)

    start_time = datetime.now()
    steps = {}

    # The IP-based steps only need the A records; Domain OSINT runs in the pool.
    try:
        from modules.web.domain_osint import _resolve_all_ips
        target_ips = _resolve_all_ips(target)
    except Exception:
        target_ips = {"A": [], "AAAA": []}
    ips = target_ips["A"]
    primary_ip = ips[0] if ips else None

    # === Run every step in PARALLEL ===
    parallel_tasks = {
        "domain":      (step_domain, (target,), {"ips": target_ips}),
        "ip":          (step_ip_multi, (ips,), {"max_ips": max_ips}),
        "ports":       (step_ports, (primary_ip,), {"fast": not deep}),
        "dns":         (step_dns, (target,), {}),
        "subdomains":  (step_subdomains, (target,), {"deep": deep}),
        "fingerprint": (step_fingerprint, (target,), {}),
        "ssl":         (step_ssl, (target,), {}),
        "dir_bust":    (step_dirs, (target,), {"deep": deep}),
        "login":       (step_login, (target,), {}),
        "register":    (step_register, (target,), {}),
        "waf":         (step_waf, (target,), {}),
        "params":      (step_params, (target,), {}),
        "dirb":        (step_dirb_engine, (target,), {"deep": deep}),
    }

    if step_timeout is None:
        step_timeout, step_timeouts = STEP_TIMEOUT, STEP_TIMEOUTS
    else:
        step_timeouts = {}

    limits = []
    if step_timeout:
        limits.append(f"{step_timeout}s per step")
    if deadline:
        limits.append(f"{deadline}s overall")
    limit_note = f" ({', '.join(limits)})" if limits else ""

    print(f"\n{C.CYAN}{'═' * 70}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  ⚡ Running {len(parallel_tasks)} steps in PARALLEL"
          f"{limit_note}...{C.RESET}")
    print(f"{C.CYAN}{'═' * 70}{C.RESET}\n")

    # === Optional: screenshot the live hosts as soon as the probe is done ===
    def start_screenshots(name, value, submit):
        if screenshots and name == "subdomains":
            submit("screenshots", step_screenshots, (target, value), {},
                   timeout=SCREENSHOT_TIMEOUT)

    results, _ = _run_parallel(
        parallel_tasks, step_timeout=step_timeout, deadline=deadline,
        step_timeouts=step_timeouts, on_done=start_screenshots,
        extra_workers=1 if screenshots else 0)

    for name in parallel_tasks:
        steps[name] = results.get(name, {})
    if isinstance(steps["domain"], dict) and "ips" not in steps["domain"]:
        steps["domain"]["ips"] = target_ips
    if "screenshots" in results:
        steps["screenshots"] = results["screenshots"]

    # === Build final result ===
    result = {
        "timestamp": start_time.isoformat(),
        "target": target,
        "deep_mode": deep,
        "max_ips": max_ips,
        "duration_seconds": round((datetime.now() - start_time).total_seconds(), 1),
        "steps": steps,
        "summary": build_summary(target, steps),
    }

    print_summary(result["summary"])

    if save_json or output_file:
        out = Path(output_file) if output_file else Path("outputs") / f"recon_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False, default=str)
        print(f"{C.GREEN}✓ Report saved: {out}{C.RESET}\n")

    return result


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="ReconX - Comprehensive Web Recon v5.0 (parallel, multi-IP)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon.py example.com
  python recon.py example.com --fast
  python recon.py example.com --json
  python recon.py example.com --output report.json
  python recon.py example.com --max-ips 5
  python recon.py example.com --screenshots
  python recon.py example.com --budget 300
        """
    )
    parser.add_argument("target", help="Domain or URL to scan")
    parser.add_argument("--fast", action="store_true",
                        help="Skip subdomains + dirbuster (faster)")
    parser.add_argument("--json", action="store_true",
                        help="Save JSON report")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Output file path")
    parser.add_argument("--max-ips", type=int, default=3,
                        help="Max IPs to check in IP OSINT (default: 3)")
    parser.add_argument("--screenshots", action="store_true",
                        help="Screenshot live subdomains as soon as they are probed "
                             "(saved to outputs/screenshots — needs Playwright or Chrome)")
    parser.add_argument("--budget", type=int, default=RECON_DEADLINE,
                        help=f"Overall time limit in seconds for the scan steps; "
                             f"steps still running are reported as timed out "
                             f"(default: {RECON_DEADLINE}, 0 = no limit)")
    parser.add_argument("--step-timeout", type=int, default=None,
                        help=f"Time limit in seconds for each step (default: "
                             f"{STEP_TIMEOUT}, subdomains {STEP_TIMEOUTS['subdomains']}; "
                             f"0 = no limit)")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Quiet mode")
    parser.add_argument("--version", action="version", version="ReconX v5.0.0")

    args = parser.parse_args()

    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)

    try:
        run_recon(
            args.target,
            deep=not args.fast,
            save_json=args.json or bool(args.output),
            output_file=args.output,
            max_ips=args.max_ips,
            screenshots=args.screenshots,
            step_timeout=args.step_timeout,
            deadline=args.budget,
        )
        return 0
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}  [!] Interrupted{C.RESET}\n")
        return 130
    except Exception as e:
        print(f"\n{C.RED}  Fatal: {e}{C.RESET}\n")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
