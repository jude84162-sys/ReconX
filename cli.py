#!/usr/bin/env python3
"""ReconX - Interactive CLI (19 tools)"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))


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


def clear():
    os.system("clear" if os.name != "nt" else "cls")


def pause():
    input(f"\n{C.GRAY}  Press Enter to continue...{C.RESET}")


def prompt(msg, default=""):
    if default:
        r = input(f"{C.YELLOW}{msg} [{default}]: {C.RESET}").strip()
        return r if r else default
    return input(f"{C.YELLOW}{msg}: {C.RESET}").strip()


def confirm(msg):
    return input(f"{C.YELLOW}{msg} (y/n): {C.RESET}").strip().lower() in ("y", "yes")


def banner():
    print(f"""{C.CYAN}
╔══════════════════════════════════════════════════════════════════╗
║  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗             ║
║  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝             ║
║  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝              ║
║  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗              ║
║  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗             ║
║  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝             ║
║                                                                  ║
║              Comprehensive OSINT Toolkit  v1.0.0                 ║
║                        19 Tools Available                        ║
╚══════════════════════════════════════════════════════════════════╝{C.RESET}
""")


def section(title):
    print(f"\n{C.BOLD}{C.CYAN}  ═══ {title} ═══{C.RESET}\n")


def main_menu():
    while True:
        clear()
        banner()

        print(f"{C.BOLD}  ── Target OSINT ──{C.RESET}")
        print(f"  {C.CYAN}[1]{C.RESET}  📱 Phone OSINT")
        print(f"  {C.CYAN}[2]{C.RESET}  👤 Username OSINT (CB-UserHunter)")
        print(f"  {C.CYAN}[3]{C.RESET}  🌐 Domain OSINT")
        print(f"  {C.CYAN}[4]{C.RESET}  🌍 IP OSINT")
        print(f"  {C.CYAN}[5]{C.RESET}  📧 Email OSINT")
        print(f"  {C.CYAN}[6]{C.RESET}  🖼️  Image Metadata")
        print(f"  {C.CYAN}[7]{C.RESET}  🐙 GitHub Recon")
        print(f"  {C.CYAN}[8]{C.RESET}  🔓 Breach Checker")
        print(f"  {C.CYAN}[9]{C.RESET}  📱 Social Media Deep")
        print()
        print(f"{C.BOLD}  ── Network ──{C.RESET}")
        print(f"  {C.CYAN}[10]{C.RESET} 🔍 Port Scanner")
        print(f"  {C.CYAN}[11]{C.RESET} 🌐 DNS Deep Recon")
        print()
        print(f"{C.BOLD}  ── Web Recon ──{C.RESET}")
        print(f"  {C.CYAN}[12]{C.RESET} 📧 Email Harvester")
        print(f"  {C.CYAN}[13]{C.RESET} 🌐 Subdomain Enumerator")
        print(f"  {C.CYAN}[14]{C.RESET} 🌍 Web Fingerprint")
        print(f"  {C.CYAN}[15]{C.RESET} 🔐 SSL/TLS Analyzer")
        print(f"  {C.CYAN}[16]{C.RESET} 📂 Directory Buster")
        print()
        print(f"{C.BOLD}  ── Combined ──{C.RESET}")
        print(f"  {C.CYAN}[17]{C.RESET} 🎯 Job Scan (all-in-one)")
        print(f"  {C.CYAN}[18]{C.RESET} 👤 CB-UserHunter Direct")
        print(f"  {C.CYAN}[19]{C.RESET} 📊 Generate HTML Report")
        print()
        print(f"{C.BOLD}  ── Actions ──{C.RESET}")
        print(f"  {C.GREEN}[F]{C.RESET}  ⚡ Full Recon (auto)")
        print(f"  {C.GREEN}[i]{C.RESET}  ℹ️  Environment")
        print(f"  {C.GREEN}[h]{C.RESET}  ❓ Help")
        print(f"  {C.GREEN}[o]{C.RESET}  📁 Outputs")
        print(f"  {C.RED}[q]{C.RESET}  🚪 Quit")
        print()

        choice = input(f"{C.YELLOW}  → Choice: {C.RESET}").strip().lower()

        handlers = {
            "1": phone_menu, "2": username_menu, "3": domain_menu,
            "4": ip_menu, "5": email_menu, "6": metadata_menu,
            "7": github_menu, "8": breach_menu, "9": social_menu,
            "10": portscan_menu, "11": dns_menu,
            "12": email_harvest_menu, "13": subdomain_menu,
            "14": web_fingerprint_menu, "15": ssl_analyzer_menu,
            "16": dir_buster_menu, "17": job_scan_menu,
            "18": cb_userhunter_menu, "19": html_report_menu,
            "f": full_recon_menu, "i": show_env,
            "h": show_help, "o": show_outputs,
        }

        if choice == "q":
            print(f"\n{C.GREEN}  👋 Goodbye!{C.RESET}\n")
            return
        elif choice in handlers:
            handlers[choice]()
        else:
            print(f"{C.RED}  ✗ Invalid{C.RESET}")
            pause()


# ============ Menus ============

def phone_menu():
    clear(); banner(); section("📱 Phone OSINT")
    n = prompt("  Phone number (+963...)")
    if not n: return
    try:
        from modules.phone_osint import run_phone_osint, print_phone_report
        r = run_phone_osint(n)
        print_phone_report(r)
        if confirm("  Save?"): save_report({"phone": r}, "phone")
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def username_menu():
    clear(); banner(); section("👤 Username OSINT (CB-UserHunter)")
    u = prompt("  Username")
    if not u: return
    print(f"\n{C.BOLD}  Filter:{C.RESET}")
    print(f"  [1] All  [2] Social  [3] Dev  [4] Gaming  [5] Crypto  [6] Cyber")
    f = prompt("\n  Filter", default="1")
    fm = {"1": None, "2": "social", "3": "dev", "4": "gaming", "5": "crypto", "6": "cyber"}
    try:
        from modules.cb_userhunter_clone import search_username, print_report as p, save_report as s
        r = search_username(u, filter_type=fm.get(f))
        p(r)
        if confirm("  Save?"): s(r, str(BASE_DIR / "outputs"))
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def domain_menu():
    clear(); banner(); section("🌐 Domain OSINT")
    d = prompt("  Domain")
    if not d: return
    try:
        from modules.domain_osint import run_domain_osint, print_domain_report
        r = run_domain_osint(d)
        print_domain_report(r)
        if confirm("  Save?"): save_report({"domain": r}, "domain")
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def ip_menu():
    clear(); banner(); section("🌍 IP OSINT")
    ip = prompt("  IP")
    if not ip: return
    try:
        from modules.ip_osint import run_ip_osint, print_ip_report
        r = run_ip_osint(ip)
        print_ip_report(r)
        if confirm("  Save?"): save_report({"ip": r}, "ip")
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def email_menu():
    clear(); banner(); section("📧 Email OSINT")
    e = prompt("  Email")
    if not e: return
    try:
        from modules.email_osint import run_email_osint, print_email_report
        r = run_email_osint(e)
        print_email_report(r)
        if confirm("  Save?"): save_report({"email": r}, "email")
    except Exception as ex: print(f"{C.RED}  Error: {ex}{C.RESET}")
    pause()


def metadata_menu():
    clear(); banner(); section("🖼️ Image Metadata")
    f = prompt("  File path")
    if not f: return
    try:
        from modules.metadata_osint import run_metadata_osint, print_metadata_report
        r = run_metadata_osint(f)
        print_metadata_report(r)
        if confirm("  Save?"): save_report({"metadata": r}, "metadata")
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def github_menu():
    clear(); banner(); section("🐙 GitHub Recon")
    u = prompt("  GitHub username")
    if not u: return
    try:
        from modules.github_recon import run_github_recon, print_github_report
        r = run_github_recon(u)
        print_github_report(r)
        if confirm("  Save?"): save_report({"github": r}, "github")
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def breach_menu():
    clear(); banner(); section("🔓 Breach Checker")
    t = prompt("  Email/username/phone")
    if not t: return
    try:
        from modules.breach_checker import run_breach_check, print_breach_report
        r = run_breach_check(t)
        print_breach_report(r)
        if confirm("  Save?"): save_report({"breach": r}, "breach")
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def social_menu():
    clear(); banner(); section("📱 Social Media Deep")
    u = prompt("  Username")
    if not u: return
    try:
        from modules.social_deep import run_social_deep, print_social_deep_report
        r = run_social_deep(u)
        print_social_deep_report(r)
        if confirm("  Save?"): save_report({"social": r}, "social")
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def portscan_menu():
    clear(); banner(); section("🔍 Port Scanner")
    t = prompt("  Target")
    if not t: return
    print(f"\n  [1] common [2] top100 [3] web [4] db [5] windows [6] custom")
    c = prompt("  Preset", default="1")
    pm = {"1": "common", "2": "top100", "3": "web", "4": "db", "5": "windows"}
    spec = prompt("  Range", default="80-443") if c == "6" else pm.get(c, "common")
    try:
        from modules.port_open_scan import get_ports, scan_port_range, print_scan_report
        ports = get_ports(spec)
        print(f"\n{C.YELLOW}  Scanning {len(ports)} ports...{C.RESET}")
        r = scan_port_range(t, ports)
        print_scan_report(r)
        if confirm("  Save?"): save_report({"port_scan": r}, "portscan")
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def dns_menu():
    clear(); banner(); section("🌐 DNS Deep Recon")
    d = prompt("  Domain")
    if not d: return
    try:
        from modules.dns_deep import run_dns_deep, print_dns_deep_report
        r = run_dns_deep(d)
        print_dns_deep_report(r)
        if confirm("  Save?"): save_report({"dns_deep": r}, "dns_deep")
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def email_harvest_menu():
    clear(); banner(); section("📧 Email Harvester")
    d = prompt("  Domain")
    if not d: return
    try:
        from modules.email_harvester import run_email_harvest, print_email_harvest_report
        r = run_email_harvest(d)
        print_email_harvest_report(r)
        if confirm("  Save?"): save_report({"email_harvest": r}, "email_harvest")
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def subdomain_menu():
    clear(); banner(); section("🌐 Subdomain Enumerator")
    d = prompt("  Domain")
    if not d: return
    try:
        from modules.subdomain_enum import run_subdomain_enum, print_subdomain_report
        r = run_subdomain_enum(d)
        print_subdomain_report(r)
        if confirm("  Save?"): save_report({"subdomains": r}, "subdomains")
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def web_fingerprint_menu():
    clear(); banner(); section("🌍 Web Fingerprint")
    u = prompt("  URL")
    if not u: return
    try:
        from modules.web_fingerprint import run_web_fingerprint, print_fingerprint_report
        r = run_web_fingerprint(u)
        print_fingerprint_report(r)
        if confirm("  Save?"): save_report({"fingerprint": r}, "fingerprint")
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def ssl_analyzer_menu():
    clear(); banner(); section("🔐 SSL/TLS Analyzer")
    h = prompt("  Hostname")
    if not h: return
    try:
        from modules.ssl_analyzer import run_ssl_analyzer, print_ssl_report
        r = run_ssl_analyzer(h)
        print_ssl_report(r)
        if confirm("  Save?"): save_report({"ssl": r}, "ssl")
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def dir_buster_menu():
    clear(); banner(); section("📂 Directory Buster")
    u = prompt("  Base URL")
    if not u: return
    try:
        from modules.dir_buster import run_dir_bust, print_dir_bust_report
        r = run_dir_bust(u)
        print_dir_bust_report(r)
        if confirm("  Save?"): save_report({"dir_bust": r}, "dir_bust")
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def job_scan_menu():
    clear(); banner(); section("🎯 Job Scan (All-in-One)")
    t = prompt("  Domain")
    if not t: return
    print(f"\n{C.YELLOW}  ⚡ Starting job scan...{C.RESET}\n")
    try:
        from modules.domain_osint import run_domain_osint
        from modules.port_open_scan import scan_port_range, get_ports
        from modules.web_fingerprint import run_web_fingerprint
        from modules.ssl_analyzer import run_ssl_analyzer

        report = {"timestamp": datetime.now().isoformat(), "target": t, "results": {}}

        print(f"{C.CYAN}[1/4] Domain Recon...{C.RESET}")
        d = run_domain_osint(t, deep=False)
        report["results"]["domain"] = d
        ips = d.get("ips", {}).get("A", [])
        print(f"      IPs: {len(ips)}, Subdomains: {len(d.get('subdomains', []))}")

        if ips:
            print(f"\n{C.CYAN}[2/4] Port Scan...{C.RESET}")
            pr = scan_port_range(ips[0], get_ports("common"), workers=100, grab_banner=False)
            report["results"]["ports"] = pr
            print(f"      Open: {len(pr['open_ports'])}")

        print(f"\n{C.CYAN}[3/4] Fingerprint...{C.RESET}")
        fp = run_web_fingerprint(t)
        report["results"]["fingerprint"] = fp
        print(f"      Techs: {len(fp.get('technologies', []))}")

        print(f"\n{C.CYAN}[4/4] SSL...{C.RESET}")
        ssl_r = run_ssl_analyzer(t)
        report["results"]["ssl"] = ssl_r
        print(f"      Grade: {ssl_r.get('grade', '?')}")

        print(f"\n{C.GREEN}  ✓ Complete!{C.RESET}")

        if confirm("  Save + HTML?"):
            save_report({"job_scan": report}, "job_scan")
            try:
                from modules.html_report import save_html_report
                out = save_html_report(report, "job_scan")
                print(f"{C.GREEN}  ✓ HTML: {out}{C.RESET}")
            except Exception as e:
                print(f"{C.YELLOW}  HTML: {e}{C.RESET}")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def cb_userhunter_menu():
    clear(); banner(); section("👤 CB-UserHunter Direct")
    u = prompt("  Username")
    if not u: return
    try:
        from modules.cb_userhunter_clone import search_username, print_report as p, save_report as s
        r = search_username(u)
        p(r)
        if confirm("  Save?"): s(r, str(BASE_DIR / "outputs"))
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def html_report_menu():
    clear(); banner(); section("📊 Generate HTML Report")
    print(f"  {C.GRAY}Combines multiple tools into one HTML report{C.RESET}\n")
    t = prompt("  Target (domain/username/ip/phone)")
    if not t: return

    report = {}

    try:
        # Auto-detect and run
        if "@" in t:
            from modules.email_osint import run_email_osint
            report["email"] = run_email_osint(t)
        elif t.startswith("+") or t.replace("-", "").isdigit():
            from modules.phone_osint import run_phone_osint
            report["phone"] = run_phone_osint(t)
        elif t.count(".") == 3 and all(p.isdigit() for p in t.split(".")):
            from modules.ip_osint import run_ip_osint
            report["ip"] = run_ip_osint(t)
        elif "." in t:
            from modules.domain_osint import run_domain_osint
            from modules.ssl_analyzer import run_ssl_analyzer
            from modules.web_fingerprint import run_web_fingerprint
            report["domain"] = run_domain_osint(t)
            report["ssl"] = run_ssl_analyzer(t)
            report["fingerprint"] = run_web_fingerprint(t)
        else:
            from modules.cb_userhunter_clone import search_username
            report["username"] = search_username(t)

        from modules.html_report import save_html_report
        out = save_html_report(report, "reconx_report")
        print(f"\n{C.GREEN}  ✓ HTML: {out}{C.RESET}")
        print(f"  {C.CYAN}Open: termux-open {out}{C.RESET}")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def full_recon_menu():
    clear(); banner(); section("⚡ Full Recon")
    t = prompt("  Target")
    if not t: return
    try:
        if "@" in t:
            from modules.email_osint import run_email_osint, print_email_report
            r = run_email_osint(t); print_email_report(r)
        elif t.startswith("+") or t.replace("-", "").isdigit():
            from modules.phone_osint import run_phone_osint, print_phone_report
            r = run_phone_osint(t); print_phone_report(r)
        elif t.count(".") == 3 and all(p.isdigit() for p in t.split(".")):
            from modules.ip_osint import run_ip_osint, print_ip_report
            r = run_ip_osint(t); print_ip_report(r)
        elif "." in t:
            from modules.domain_osint import run_domain_osint, print_domain_report
            r = run_domain_osint(t); print_domain_report(r)
        else:
            from modules.cb_userhunter_clone import search_username, print_report as p
            r = search_username(t); p(r)
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def show_env():
    clear(); banner(); section("ℹ️ Environment")
    try:
        from modules.env_detect import get_environment, get_env_label
        env = get_environment()
        print(f"  Environment: {get_env_label(env)}")
        print(f"  Python:      {env.get('python')}")
        print(f"  Platform:    {env.get('platform')}")
        print(f"\n  Modules:")
        mods = ["phone_osint", "cb_userhunter_clone", "domain_osint", "ip_osint",
                "email_osint", "metadata_osint", "github_recon", "breach_checker",
                "social_deep", "port_open_scan", "dns_deep", "email_harvester",
                "subfinder_clone", "subdomain_enum", "web_fingerprint",
                "ssl_analyzer", "dir_buster", "html_report"]
        for m in mods:
            try:
                __import__(f"modules.{m}")
                print(f"    {C.GREEN}✓{C.RESET} {m}")
            except ImportError:
                print(f"    {C.RED}✗{C.RESET} {m}")
    except Exception as e: print(f"{C.RED}  Error: {e}{C.RESET}")
    pause()


def show_help():
    clear(); banner(); section("❓ Help")
    print(f"  ReconX v1.0.0 — 19 OSINT tools")
    print(f"  Zero external tools needed")
    print(f"\n  Reports: ~/ReconX/outputs/")
    print(f"  GitHub:  https://github.com/jude84162-sys/ReconX")
    pause()


def show_outputs():
    clear(); banner(); section("📁 Outputs")
    outputs = BASE_DIR / "outputs"
    if not outputs.exists():
        print(f"  {C.YELLOW}No outputs{C.RESET}"); pause(); return
    files = sorted(outputs.glob("*"), reverse=True)
    if not files:
        print(f"  {C.YELLOW}Empty{C.RESET}"); pause(); return
    for f in files[:20]:
        size = f.stat().st_size
        mt = datetime.fromtimestamp(f.stat().st_mtime).strftime("%m-%d %H:%M")
        print(f"  {C.CYAN}•{C.RESET} {f.name:<45} {size:>8} B  {mt}")
    pause()


def save_report(data, prefix="report"):
    outputs = BASE_DIR / "outputs"
    outputs.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fp = outputs / f"{prefix}_{ts}.json"
    data["_saved_at"] = datetime.now().isoformat()
    data["_tool"] = "ReconX v1.0.0"
    try:
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n{C.GREEN}  ✓ Saved: {fp}{C.RESET}")
        return fp
    except Exception as e:
        print(f"\n{C.RED}  ✗ {e}{C.RESET}")
        return None


def main():
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{C.GREEN}  Bye!{C.RESET}\n")
    except Exception as e:
        print(f"\n{C.RED}  Fatal: {e}{C.RESET}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
