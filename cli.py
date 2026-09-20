#!/usr/bin/env python3
"""
ReconX - Interactive CLI
Beautiful menu-driven interface for all OSINT modules.
"""

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
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"


def clear():
    os.system("clear" if os.name != "nt" else "cls")


def pause():
    input(f"\n{C.GRAY}  Press Enter to continue...{C.RESET}")


def prompt(msg, default=""):
    if default:
        result = input(f"{C.YELLOW}{msg} [{default}]: {C.RESET}").strip()
        return result if result else default
    return input(f"{C.YELLOW}{msg}: {C.RESET}").strip()


def confirm(msg):
    response = input(f"{C.YELLOW}{msg} (y/n): {C.RESET}").strip().lower()
    return response in ("y", "yes")


def print_banner():
    print(f"""{C.CYAN}
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║      ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗        ║
║      ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝        ║
║      ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝         ║
║      ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗         ║
║      ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗        ║
║      ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝        ║
║                                                                  ║
║                  Comprehensive OSINT Toolkit                     ║
║                          v1.0.0                                  ║
╚══════════════════════════════════════════════════════════════════╝{C.RESET}
""")


def print_section(title):
    print(f"\n{C.BOLD}{C.WHITE}{'═' * 66}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  {title}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}{'═' * 66}{C.RESET}\n")


# ============================================================
# Main Menu
# ============================================================

def main_menu():
    while True:
        clear()
        print_banner()

        print(f"{C.BOLD}{C.WHITE}  ═══ MAIN MENU ═══{C.RESET}\n")

        print(f"{C.BOLD}{C.MAGENTA}  ── Target OSINT ──{C.RESET}")
        print(f"  {C.CYAN}[1]{C.RESET}  📱 Phone OSINT")
        print(f"  {C.CYAN}[2]{C.RESET}  👤 Username OSINT (CB-UserHunter)")
        print(f"  {C.CYAN}[3]{C.RESET}  🌐 Domain OSINT")
        print(f"  {C.CYAN}[4]{C.RESET}  🌍 IP OSINT")
        print(f"  {C.CYAN}[5]{C.RESET}  📧 Email OSINT")
        print(f"  {C.CYAN}[6]{C.RESET}  🖼️  Image Metadata")
        print()
        print(f"{C.BOLD}{C.MAGENTA}  ── Network ──{C.RESET}")
        print(f"  {C.CYAN}[7]{C.RESET}  🔍 Port Scanner")
        print()
        print(f"{C.BOLD}{C.MAGENTA}  ── Web Recon ──{C.RESET}")
        print(f"  {C.CYAN}[8]{C.RESET}  📧 Email Harvester")
        print(f"  {C.CYAN}[9]{C.RESET}  🌐 Subdomain Enumerator (Subfinder Clone)")
        print(f"  {C.CYAN}[10]{C.RESET} 🌍 Web Fingerprint")
        print(f"  {C.CYAN}[11]{C.RESET} 🔐 SSL/TLS Analyzer")
        print(f"  {C.CYAN}[12]{C.RESET} 📂 Directory Buster")
        print()
        print(f"{C.BOLD}{C.MAGENTA}  ── Combined ──{C.RESET}")
        print(f"  {C.CYAN}[13]{C.RESET} 🎯 Job Scan (all-in-one)")
        print(f"  {C.CYAN}[14]{C.RESET} 👤 CB-UserHunter Direct (100+ platforms)")
        print()
        print(f"{C.BOLD}{C.MAGENTA}  ── Actions ──{C.RESET}")
        print(f"  {C.GREEN}[F]{C.RESET}  ⚡ Full Recon (auto-detect)")
        print(f"  {C.GREEN}[i]{C.RESET}  ℹ️  Environment")
        print(f"  {C.GREEN}[h]{C.RESET}  ❓ Help")
        print(f"  {C.GREEN}[o]{C.RESET}  📁 View Outputs")
        print(f"  {C.RED}[q]{C.RESET}  🚪 Quit")
        print()

        choice = input(f"{C.YELLOW}  → Choice: {C.RESET}").strip().lower()

        if choice == "1":
            phone_menu()
        elif choice == "2":
            username_menu()
        elif choice == "3":
            domain_menu()
        elif choice == "4":
            ip_menu()
        elif choice == "5":
            email_menu()
        elif choice == "6":
            metadata_menu()
        elif choice == "7":
            portscan_menu()
        elif choice == "8":
            email_harvest_menu()
        elif choice == "9":
            subdomain_menu()
        elif choice == "10":
            web_fingerprint_menu()
        elif choice == "11":
            ssl_analyzer_menu()
        elif choice == "12":
            dir_buster_menu()
        elif choice == "13":
            job_scan_menu()
        elif choice == "14":
            cb_userhunter_menu()
        elif choice == "f":
            full_recon_menu()
        elif choice == "i":
            show_env()
        elif choice == "h":
            show_help()
        elif choice == "o":
            show_outputs()
        elif choice == "q":
            print(f"\n{C.GREEN}  👋 Goodbye!{C.RESET}\n")
            return
        else:
            print(f"{C.RED}  ✗ Invalid choice{C.RESET}")
            pause()


# ============================================================
# Target OSINT Handlers
# ============================================================

def phone_menu():
    clear()
    print_banner()
    print_section("📱 Phone Number OSINT")

    print(f"{C.GRAY}  Example: +963912345678, +19005551234{C.RESET}\n")
    number = prompt("  Phone number")

    if not number:
        return

    try:
        from modules.phone_osint import run_phone_osint, print_phone_report
        result = run_phone_osint(number)
        print_phone_report(result)

        if confirm("  Save report?"):
            save_report({"phone": result}, "phone")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def username_menu():
    clear()
    print_banner()
    print_section("👤 Username OSINT (CB-UserHunter Clone)")

    print(f"{C.GRAY}  Searches username across 100+ platforms{C.RESET}")
    print(f"{C.GRAY}  Includes Google Dorks automatically{C.RESET}\n")

    username = prompt("  Username")

    if not username:
        return

    print(f"\n{C.BOLD}  Filter by type:{C.RESET}")
    print(f"  {C.CYAN}[1]{C.RESET}  All platforms (100+)")
    print(f"  {C.CYAN}[2]{C.RESET}  Social only")
    print(f"  {C.CYAN}[3]{C.RESET}  Dev only")
    print(f"  {C.CYAN}[4]{C.RESET}  Gaming only")
    print(f"  {C.CYAN}[5]{C.RESET}  Crypto only")
    print(f"  {C.CYAN}[6]{C.RESET}  Cybersecurity only")

    filter_choice = prompt("\n  Filter", default="1")
    filter_map = {
        "1": None,
        "2": "social",
        "3": "dev",
        "4": "gaming",
        "5": "crypto",
        "6": "cyber",
    }
    filter_type = filter_map.get(filter_choice)

    try:
        from modules.cb_userhunter_clone import (
            search_username,
            print_report as print_cb_report,
            save_report as save_cb_report,
        )

        results = search_username(username, filter_type=filter_type)
        print_cb_report(results)

        if confirm("  Save report?"):
            save_cb_report(results, str(BASE_DIR / "outputs"))
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()

    pause()


def domain_menu():
    clear()
    print_banner()
    print_section("🌐 Domain OSINT")

    print(f"{C.GRAY}  Example: example.com{C.RESET}\n")
    domain = prompt("  Domain")

    if not domain:
        return

    try:
        from modules.domain_osint import run_domain_osint, print_domain_report
        result = run_domain_osint(domain, deep=False)
        print_domain_report(result)

        if confirm("  Save report?"):
            save_report({"domain": result}, "domain")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def ip_menu():
    clear()
    print_banner()
    print_section("🌍 IP OSINT")

    print(f"{C.GRAY}  Example: 8.8.8.8, 1.1.1.1{C.RESET}\n")
    ip = prompt("  IP address")

    if not ip:
        return

    try:
        from modules.ip_osint import run_ip_osint, print_ip_report
        result = run_ip_osint(ip)
        print_ip_report(result)

        if confirm("  Save report?"):
            save_report({"ip": result}, "ip")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def email_menu():
    clear()
    print_banner()
    print_section("📧 Email OSINT")

    print(f"{C.GRAY}  Example: user@example.com{C.RESET}\n")
    email = prompt("  Email")

    if not email:
        return

    try:
        from modules.email_osint import run_email_osint, print_email_report
        result = run_email_osint(email)
        print_email_report(result)

        if confirm("  Save report?"):
            save_report({"email": result}, "email")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def metadata_menu():
    clear()
    print_banner()
    print_section("🖼️  Image Metadata (EXIF)")

    print(f"{C.GRAY}  Example: ~/photo.jpg{C.RESET}\n")
    filepath = prompt("  Image file")

    if not filepath:
        return

    try:
        from modules.metadata_osint import run_metadata_osint, print_metadata_report
        result = run_metadata_osint(filepath)
        print_metadata_report(result)

        if confirm("  Save report?"):
            save_report({"metadata": result}, "metadata")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


# ============================================================
# Network Handlers
# ============================================================

def portscan_menu():
    clear()
    print_banner()
    print_section("🔍 Port Scanner")

    target = prompt("  Target (IP or domain)")

    if not target:
        return

    print(f"\n{C.BOLD}  Port presets:{C.RESET}")
    print(f"  {C.CYAN}[1]{C.RESET}  common   - 22 common ports")
    print(f"  {C.CYAN}[2]{C.RESET}  top100   - Top 100 ports")
    print(f"  {C.CYAN}[3]{C.RESET}  web      - Web ports")
    print(f"  {C.CYAN}[4]{C.RESET}  db       - Database ports")
    print(f"  {C.CYAN}[5]{C.RESET}  windows  - Windows ports")
    print(f"  {C.CYAN}[6]{C.RESET}  Custom   - Range or list")

    preset_choice = prompt("\n  Preset", default="1")

    presets = {
        "1": "common", "2": "top100", "3": "web",
        "4": "db", "5": "windows",
    }

    if preset_choice == "6":
        port_spec = prompt("  Range (e.g., 80-443 or 80,443,8080)")
        if not port_spec:
            return
    else:
        port_spec = presets.get(preset_choice, "common")

    try:
        from modules.port_open_scan import (
            get_ports, scan_port_range, print_scan_report
        )

        ports = get_ports(port_spec)
        print(f"\n{C.YELLOW}  Scanning {len(ports)} ports on {target}...{C.RESET}\n")

        def progress(done, total):
            pct = (done / total) * 100
            bar_len = 30
            filled = int(bar_len * done / total)
            bar = "█" * filled + "░" * (bar_len - filled)
            sys.stdout.write(f"\r  {C.CYAN}{bar}{C.RESET} {pct:5.1f}% ({done}/{total})")
            sys.stdout.flush()

        result = scan_port_range(target, ports, progress_callback=progress)
        print()
        print_scan_report(result)

        if confirm("  Save report?"):
            save_report({"port_scan": result}, "portscan")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


# ============================================================
# Web Recon Handlers
# ============================================================

def email_harvest_menu():
    clear()
    print_banner()
    print_section("📧 Email Harvester")

    print(f"{C.GRAY}  Example: example.com{C.RESET}\n")
    domain = prompt("  Domain")

    if not domain:
        return

    try:
        from modules.email_harvester import run_email_harvest, print_email_harvest_report
        result = run_email_harvest(domain)
        print_email_harvest_report(result)

        if confirm("  Save report?"):
            save_report({"email_harvest": result}, "email_harvest")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def subdomain_menu():
    clear()
    print_banner()
    print_section("🌐 Subdomain Enumerator (Subfinder Clone)")

    print(f"{C.GRAY}  7 passive sources + 90-word bruteforce{C.RESET}")
    print(f"{C.GRAY}  No external tools needed{C.RESET}")
    print(f"{C.GRAY}  Example: example.com{C.RESET}\n")
    domain = prompt("  Domain")

    if not domain:
        return

    try:
        from modules.subdomain_enum import run_subdomain_enum, print_subdomain_report
        result = run_subdomain_enum(domain)
        print_subdomain_report(result)

        if confirm("  Save report?"):
            save_report({"subdomains": result}, "subdomains")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()

    pause()


def web_fingerprint_menu():
    clear()
    print_banner()
    print_section("🌍 Web Fingerprint")

    print(f"{C.GRAY}  Detects 60+ technologies{C.RESET}")
    print(f"{C.GRAY}  Example: example.com{C.RESET}\n")
    url = prompt("  URL")

    if not url:
        return

    try:
        from modules.web_fingerprint import run_web_fingerprint, print_fingerprint_report
        result = run_web_fingerprint(url)
        print_fingerprint_report(result)

        if confirm("  Save report?"):
            save_report({"fingerprint": result}, "fingerprint")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def ssl_analyzer_menu():
    clear()
    print_banner()
    print_section("🔐 SSL/TLS Analyzer")

    print(f"{C.GRAY}  Example: example.com{C.RESET}\n")
    hostname = prompt("  Hostname")

    if not hostname:
        return

    try:
        from modules.ssl_analyzer import run_ssl_analyzer, print_ssl_report
        result = run_ssl_analyzer(hostname)
        print_ssl_report(result)

        if confirm("  Save report?"):
            save_report({"ssl": result}, "ssl")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def dir_buster_menu():
    clear()
    print_banner()
    print_section("📂 Directory Buster")

    print(f"{C.GRAY}  Example: https://example.com{C.RESET}\n")
    url = prompt("  Base URL")

    if not url:
        return

    try:
        from modules.dir_buster import run_dir_bust, print_dir_bust_report, COMMON_PATHS
        print(f"\n{C.YELLOW}  Busting {len(COMMON_PATHS)} paths...{C.RESET}\n")
        result = run_dir_bust(url)
        print_dir_bust_report(result)

        if confirm("  Save report?"):
            save_report({"dir_bust": result}, "dir_bust")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


# ============================================================
# CB-UserHunter Direct
# ============================================================

def cb_userhunter_menu():
    clear()
    print_banner()
    print_section("👤 CB-UserHunter Direct (100+ platforms)")

    print(f"  {C.GRAY}Full search — no filtering{C.RESET}\n")

    username = prompt("  Username")

    if not username:
        return

    try:
        from modules.cb_userhunter_clone import (
            search_username,
            print_report as print_cb_report,
            save_report as save_cb_report,
        )
        results = search_username(username, workers=30)
        print_cb_report(results)

        if confirm("  Save report?"):
            save_cb_report(results, str(BASE_DIR / "outputs"))
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()

    pause()


# ============================================================
# Job Scan (Combined)
# ============================================================

def job_scan_menu():
    clear()
    print_banner()
    print_section("🎯 Job Scan (Combined Recon)")

    print(f"  {C.GRAY}Combines: domain + subdomains + ports + ssl + fingerprint{C.RESET}\n")

    target = prompt("  Target domain")

    if not target:
        return

    print(f"\n{C.YELLOW}  ⚡ Starting job scan on {target}...{C.RESET}\n")

    try:
        from modules.domain_osint import run_domain_osint
        from modules.port_open_scan import scan_port_range, get_ports
        from modules.web_fingerprint import run_web_fingerprint
        from modules.ssl_analyzer import run_ssl_analyzer

        report = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "results": {}
        }

        # 1. Domain
        print(f"{C.CYAN}[1/4] Domain Recon...{C.RESET}")
        domain_result = run_domain_osint(target, deep=False)
        report["results"]["domain"] = domain_result

        ips = domain_result.get("ips", {}).get("A", [])
        subdomains = domain_result.get("subdomains", [])

        print(f"      IPs: {len(ips)}")
        if ips:
            print(f"      Primary IP: {ips[0]}")
        print(f"      Subdomains: {len(subdomains)}")

        # 2. Ports
        if ips:
            print(f"\n{C.CYAN}[2/4] Port Scan on {ips[0]}...{C.RESET}")
            ports = get_ports("common")
            port_result = scan_port_range(ips[0], ports, workers=100, grab_banner=False)
            report["results"]["ports"] = port_result

            print(f"      Open ports: {len(port_result['open_ports'])}")
            for p in port_result['open_ports'][:5]:
                print(f"        • {p['port']}/{p['service']}")
        else:
            print(f"\n{C.YELLOW}[2/4] Port Scan: skipped (no IPs){C.RESET}")

        # 3. Web fingerprint
        print(f"\n{C.CYAN}[3/4] Web Fingerprint...{C.RESET}")
        fp_result = run_web_fingerprint(target)
        report["results"]["fingerprint"] = fp_result

        techs = fp_result.get("technologies", [])
        print(f"      Technologies: {len(techs)}")
        for t in techs[:5]:
            print(f"        • {t['name']}")

        # 4. SSL
        print(f"\n{C.CYAN}[4/4] SSL/TLS...{C.RESET}")
        try:
            ssl_result = run_ssl_analyzer(target)
            report["results"]["ssl"] = ssl_result
            print(f"      Grade: {ssl_result.get('grade', '?')}")
            print(f"      Protocol: {ssl_result.get('protocol', '?')}")
        except Exception as e:
            print(f"      [!] SSL: {e}")

        # Summary
        print(f"\n{C.GREEN}  ✓ Job scan complete!{C.RESET}")
        print(f"\n  {C.BOLD}Summary:{C.RESET}")
        print(f"    IPs:          {len(ips)}")
        print(f"    Subdomains:   {len(subdomains)}")
        print(f"    Open ports:   {len(report['results'].get('ports', {}).get('open_ports', []))}")
        print(f"    Technologies: {len(techs)}")
        if report['results'].get('ssl'):
            print(f"    SSL Grade:    {report['results']['ssl'].get('grade', '?')}")

        if confirm("\n  Save report?"):
            save_report({"job_scan": report}, "job_scan")

    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()

    pause()


# ============================================================
# Full Recon
# ============================================================

def full_recon_menu():
    clear()
    print_banner()
    print_section("⚡ Full Recon (Auto-detect)")

    print(f"  {C.GRAY}Target type is auto-detected from input{C.RESET}\n")

    target = prompt("  Target")

    if not target:
        return

    try:
        if "@" in target:
            kind = "email"
        elif target.startswith("+") or (
            target.replace("-", "").replace(" ", "").isdigit() and len(target) > 6
        ):
            kind = "phone"
        elif all(p.isdigit() and 0 <= int(p) <= 255 for p in target.split(".")) and target.count(".") == 3:
            kind = "ip"
        elif "." in target:
            kind = "domain"
        else:
            kind = "username"

        print(f"\n{C.GREEN}  → Detected: {kind}{C.RESET}\n")

        result = None

        if kind == "phone":
            from modules.phone_osint import run_phone_osint, print_phone_report
            result = run_phone_osint(target)
            print_phone_report(result)
        elif kind == "email":
            from modules.email_osint import run_email_osint, print_email_report
            result = run_email_osint(target)
            print_email_report(result)
        elif kind == "ip":
            from modules.ip_osint import run_ip_osint, print_ip_report
            result = run_ip_osint(target)
            print_ip_report(result)
        elif kind == "domain":
            from modules.domain_osint import run_domain_osint, print_domain_report
            result = run_domain_osint(target)
            print_domain_report(result)
        else:
            # Username — use CB-UserHunter
            from modules.cb_userhunter_clone import (
                search_username, print_report as print_cb_report,
            )
            result = search_username(target)
            print_cb_report(result)

        if result and confirm("  Save report?"):
            save_report({"full_recon": result}, f"full_{kind}")

    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


# ============================================================
# Info
# ============================================================

def show_env():
    clear()
    print_banner()
    print_section("ℹ️  Environment")

    try:
        from modules.env_detect import get_environment, get_env_label
        env = get_environment()
        label = get_env_label(env)

        print(f"  {C.CYAN}Environment:{C.RESET}  {label}")
        print(f"  {C.CYAN}Python:     {C.RESET}  {env.get('python', '?')}")
        print(f"  {C.CYAN}Platform:   {C.RESET}  {env.get('platform', '?')}")

        print(f"\n  {C.BOLD}Available Modules:{C.RESET}")
        modules = [
            ("phone_osint", "📱"),
            ("cb_userhunter_clone", "👤"),
            ("domain_osint", "🌐"),
            ("ip_osint", "🌍"),
            ("email_osint", "📧"),
            ("metadata_osint", "🖼️ "),
            ("port_open_scan", "🔍"),
            ("email_harvester", "📧"),
            ("subfinder_clone", "🌐"),
            ("subdomain_enum", "🌐"),
            ("web_fingerprint", "🌍"),
            ("ssl_analyzer", "🔐"),
            ("dir_buster", "📂"),
        ]

        for mod, icon in modules:
            try:
                __import__(f"modules.{mod}")
                print(f"    {C.GREEN}✓{C.RESET} {icon} {mod}")
            except ImportError:
                print(f"    {C.RED}✗{C.RESET} {icon} {mod}")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def show_help():
    clear()
    print_banner()
    print_section("❓ Help")

    print(f"{C.BOLD}  ReconX v1.0.0:{C.RESET}")
    print(f"  Comprehensive OSINT toolkit for Termux, Kali, WSL.")
    print(f"  No external tools needed.")
    print()
    print(f"{C.BOLD}  14 Tools:{C.RESET}")
    print(f"  {C.CYAN}1{C.RESET}  📱 Phone OSINT")
    print(f"  {C.CYAN}2{C.RESET}  👤 Username (CB-UserHunter Clone)")
    print(f"  {C.CYAN}3{C.RESET}  🌐 Domain OSINT")
    print(f"  {C.CYAN}4{C.RESET}  🌍 IP OSINT")
    print(f"  {C.CYAN}5{C.RESET}  📧 Email OSINT")
    print(f"  {C.CYAN}6{C.RESET}  🖼️  Image Metadata")
    print(f"  {C.CYAN}7{C.RESET}  🔍 Port Scanner")
    print(f"  {C.CYAN}8{C.RESET}  📧 Email Harvester")
    print(f"  {C.CYAN}9{C.RESET}  🌐 Subdomain Enumerator")
    print(f"  {C.CYAN}10{C.RESET} 🌍 Web Fingerprint")
    print(f"  {C.CYAN}11{C.RESET} 🔐 SSL/TLS Analyzer")
    print(f"  {C.CYAN}12{C.RESET} 📂 Directory Buster")
    print(f"  {C.CYAN}13{C.RESET} 🎯 Job Scan (all-in-one)")
    print(f"  {C.CYAN}14{C.RESET} 👤 CB-UserHunter Direct")
    print()
    print(f"{C.BOLD}  Reports:{C.RESET} ~/ReconX/outputs/")

    pause()


def show_outputs():
    clear()
    print_banner()
    print_section("📁 Outputs")

    outputs_dir = BASE_DIR / "outputs"
    if not outputs_dir.exists():
        print(f"{C.YELLOW}  No outputs yet.{C.RESET}")
        pause()
        return

    files = sorted(outputs_dir.glob("*.json"), reverse=True)
    if not files:
        print(f"{C.YELLOW}  No reports found.{C.RESET}")
        pause()
        return

    print(f"  {C.GRAY}{len(files)} reports found:{C.RESET}\n")
    for f in files[:20]:
        size = f.stat().st_size
        mtime = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        print(f"  {C.CYAN}•{C.RESET} {f.name:<50} {size:>8} B  {mtime}")

    if len(files) > 20:
        print(f"  ... and {len(files) - 20} more")

    pause()


# ============================================================
# Save
# ============================================================

def save_report(data, prefix="report"):
    outputs = BASE_DIR / "outputs"
    outputs.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{timestamp}.json"
    filepath = outputs / filename

    data["_saved_at"] = datetime.now().isoformat()
    data["_tool"] = "ReconX v1.0.0"

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n{C.GREEN}  ✓ Saved: {filepath}{C.RESET}")
        return filepath
    except Exception as e:
        print(f"\n{C.RED}  ✗ Save failed: {e}{C.RESET}")
        return None


# ============================================================
# Main
# ============================================================

def main():
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{C.GREEN}  👋 Interrupted. Goodbye!{C.RESET}\n")
    except Exception as e:
        print(f"\n{C.RED}  Fatal error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
