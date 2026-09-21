#!/usr/bin/env python3
"""ReconX - Interactive CLI v4 (Web Recon — 15 tools)"""

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
║              Comprehensive Web Recon  v4.1.1.0                     ║
║                        18 Tools Available                        ║
╚══════════════════════════════════════════════════════════════════╝{C.RESET}
""")


def section(title):
    print(f"\n{C.BOLD}{C.CYAN}  ═══ {title} ═══{C.RESET}\n")


# ============================================================
# Main Menu
# ============================================================

def main_menu():
    while True:
        clear()
        banner()

        print(f"{C.BOLD}{C.MAGENTA}  ── Recon Modules ──{C.RESET}")
        print(f"  {C.CYAN}[1]{C.RESET}  🌐 Domain OSINT")
        print(f"  {C.CYAN}[2]{C.RESET}  🌍 IP OSINT (multi-source)")
        print(f"  {C.CYAN}[3]{C.RESET}  🔍 Port Scanner")
        print(f"  {C.CYAN}[4]{C.RESET}  🌐 DNS Deep Recon")
        print(f"  {C.CYAN}[5]{C.RESET}  🌐 Subdomain Enumerator")
        print()
        print(f"{C.BOLD}{C.MAGENTA}  ── Web Discovery ──{C.RESET}")
        print(f"  {C.CYAN}[6]{C.RESET}  🌍 Web Fingerprint")
        print(f"  {C.CYAN}[7]{C.RESET}  📂 Directory Buster")
        print(f"  {C.CYAN}[8]{C.RESET}  🔐 Login Finder")
        print(f"  {C.CYAN}[9]{C.RESET}  📝 Register Finder")
        print(f"  {C.CYAN}[10]{C.RESET} 🔗 Parameter Finder")
        print()
        print(f"{C.BOLD}{C.MAGENTA}  ── Security & Monitoring ──{C.RESET}")
        print(f"  {C.CYAN}[11]{C.RESET} 🛡️  WAF Detector")
        print(f"  {C.CYAN}[12]{C.RESET} 👁️  Web Monitor")
        print(f"  {C.CYAN}[13]{C.RESET} 🔐 SSL/TLS Analyzer")
        print()
        print(f"{C.BOLD}{C.RED}  ── Web Vuln Scanners (active) ──{C.RESET}")
        print(f"  {C.RED}[14]{C.RESET} 💉 SQL Injection")
        print(f"  {C.RED}[15]{C.RESET} 🎯 XSS")
        print(f"  {C.RED}[16]{C.RESET} 🌐 SSRF")
        print(f"  {C.RED}[17]{C.RESET} 📐 SSTI")
        print(f"  {C.RED}[18]{C.RESET} 💻 Command Injection")
        print(f"  {C.RED}[19]{C.RESET} 🔑 JWT Attacks")
        print(f"  {C.RED}[20]{C.RESET} 🚀 ALL Web Vuln Scanners")
        print()
        print(f"{C.BOLD}{C.RED}  ── Bug Bounty & Content ──{C.RESET}")
        print(f"  {C.RED}[21]{C.RESET} 🎯 DIRB Content Scan")
        print(f"  {C.RED}[22]{C.RESET} 🐛 Bug Bounty Checks")
        print(f"  {C.RED}[23]{C.RESET} 💰 Bug Bounty Nikto (multi-target)")
        print()
        print(f"{C.BOLD}{C.GREEN}  ── Full Recon (recommended) ──{C.RESET}")
        print(f"  {C.GREEN}[24]{C.RESET} 🎯 Full Web Recon   (parallel, 14 tools)")
        print(f"  {C.GREEN}[25]{C.RESET} ⚡ Fast Web Recon   (skip subs/dirs)")
        print()
        print(f"{C.BOLD}{C.MAGENTA}  ── Actions ──{C.RESET}")
        print(f"  {C.GREEN}[i]{C.RESET}  ℹ️  Environment")
        print(f"  {C.GREEN}[h]{C.RESET}  ❓ Help")
        print(f"  {C.GREEN}[o]{C.RESET}  📁 View Outputs")
        print(f"  {C.RED}[q]{C.RESET}  🚪 Quit")
        print()

        choice = input(f"{C.YELLOW}  → Choice: {C.RESET}").strip().lower()

        handlers = {
            "1": domain_menu,
            "2": ip_menu,
            "3": portscan_menu,
            "4": dns_menu,
            "5": subdomain_menu,
            "6": web_fingerprint_menu,
            "7": dir_buster_menu,
            "8": login_finder_menu,
            "9": register_finder_menu,
            "10": param_finder_menu,
            "11": waf_detector_menu,
            "12": web_monitor_menu,
            "13": ssl_analyzer_menu,
            "14": sqli_menu,
            "15": xss_menu,
            "16": ssrf_menu,
            "17": ssti_menu,
            "18": cmdi_menu,
            "19": jwt_menu,
            "20": all_vuln_menu,
            "21": dirb_menu,
            "22": bounty_checks_menu,
            "23": bugbounty_nikto_menu,
            "24": full_web_recon_menu,
            "25": fast_web_recon_menu,
            "i": show_env,
            "h": show_help,
            "o": show_outputs,
        }

        if choice == "q":
            print(f"\n{C.GREEN}  👋 Goodbye!{C.RESET}\n")
            return
        elif choice in handlers:
            handlers[choice]()
        else:
            print(f"{C.RED}  ✗ Invalid choice{C.RESET}")
            pause()


# ============================================================
# Recon Modules (1-5)
# ============================================================

def domain_menu():
    clear()
    banner()
    section("🌐 Domain OSINT")

    d = prompt("  Domain")
    if not d:
        return

    try:
        from modules.web.domain_osint import run_domain_osint, print_domain_report
        r = run_domain_osint(d)
        print_domain_report(r)
        if confirm("  Save?"):
            save_report({"domain": r}, "domain")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()

    pause()


def ip_menu():
    clear()
    banner()
    section("🌍 IP OSINT")

    ip = prompt("  IP address")
    if not ip:
        return

    try:
        import sys
        sys.path.insert(0, str(BASE_DIR / "_archive"))
        from modules.network.ip_osint import run_ip_osint, print_ip_report
        r = run_ip_osint(ip)
        print_ip_report(r)
        if confirm("  Save?"):
            save_report({"ip": r}, "ip")
    except ImportError:
        print(f"{C.YELLOW}  ⚠ IP OSINT module not available{C.RESET}")
        print(f"{C.GRAY}  (was moved to archive){C.RESET}")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def portscan_menu():
    clear()
    banner()
    section("🔍 Port Scanner")

    t = prompt("  Target (domain or IP)")
    if not t:
        return

    print(f"\n  {C.BOLD}Presets:{C.RESET}")
    print(f"  [1] common   [2] top100   [3] web    [4] db")
    print(f"  [5] windows  [6] all      [7] custom")
    c = prompt("  Preset", default="1")

    pm = {"1": "common", "2": "top100", "3": "web", "4": "db", "5": "windows", "6": "all"}

    if c == "7":
        spec = prompt("  Range (e.g. 80-443 or 80,443,8080)", default="80-443")
    else:
        spec = pm.get(c, "common")

    try:
        from modules.network.port_scan import get_ports, scan_port_range, print_scan_report
        ports = get_ports(spec)
        print(f"\n{C.YELLOW}  Scanning {len(ports)} ports on {t}...{C.RESET}\n")

        def progress(done, total):
            pct = (done / total) * 100
            bar_len = 30
            filled = int(bar_len * done / total)
            bar = "█" * filled + "░" * (bar_len - filled)
            sys.stdout.write(f"\r  {C.CYAN}{bar}{C.RESET} {pct:5.1f}% ({done}/{total})")
            sys.stdout.flush()

        r = scan_port_range(t, ports, progress_callback=progress)
        print()
        print_scan_report(r)
        if confirm("  Save?"):
            save_report({"port_scan": r}, "portscan")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()

    pause()


def dns_menu():
    clear()
    banner()
    section("🌐 DNS Deep Recon")

    d = prompt("  Domain")
    if not d:
        return

    try:
        from modules.network.dns_deep import run_dns_deep, print_dns_deep_report
        r = run_dns_deep(d)
        print_dns_deep_report(r)
        if confirm("  Save?"):
            save_report({"dns_deep": r}, "dns_deep")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def subdomain_menu():
    clear()
    banner()
    section("🌐 Subdomain Enumerator")

    print(f"  {C.GRAY}7 passive sources + bruteforce{C.RESET}\n")

    d = prompt("  Domain")
    if not d:
        return

    try:
        from modules.web.subdomain_enum import run_subdomain_enum, print_subdomain_report
        r = run_subdomain_enum(d)
        print_subdomain_report(r)
        if confirm("  Save?"):
            save_report({"subdomains": r}, "subdomains")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()

    pause()


# ============================================================
# Web Discovery (6-10)
# ============================================================

def web_fingerprint_menu():
    clear()
    banner()
    section("🌍 Web Fingerprint")

    u = prompt("  URL or domain")
    if not u:
        return

    try:
        from modules.web.web_fingerprint import run_web_fingerprint, print_fingerprint_report
        r = run_web_fingerprint(u)
        print_fingerprint_report(r)
        if confirm("  Save?"):
            save_report({"fingerprint": r}, "fingerprint")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def dir_buster_menu():
    clear()
    banner()
    section("📂 Directory Buster")

    u = prompt("  Base URL (e.g. https://example.com)")
    if not u:
        return

    try:
        from modules.web.dir_buster import run_dir_bust, print_dir_bust_report
        r = run_dir_bust(u)
        print_dir_bust_report(r)
        if confirm("  Save?"):
            save_report({"dir_bust": r}, "dir_bust")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def login_finder_menu():
    clear()
    banner()
    section("🔐 Login Finder")

    print(f"  {C.GRAY}Search 60+ login/admin paths (recon only){C.RESET}\n")

    u = prompt("  URL or domain")
    if not u:
        return

    try:
        from modules.web.login_finder import run_login_finder, print_login_finder_report
        r = run_login_finder(u)
        print_login_finder_report(r)
        if confirm("  Save?"):
            save_report({"login_finder": r}, "login_finder")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def register_finder_menu():
    clear()
    banner()
    section("📝 Register Finder")

    print(f"  {C.GRAY}Search 55+ register/signup paths (recon only){C.RESET}\n")

    u = prompt("  URL or domain")
    if not u:
        return

    try:
        from modules.web.register_finder import run_register_finder, print_register_finder_report
        r = run_register_finder(u)
        print_register_finder_report(r)
        if confirm("  Save?"):
            save_report({"register_finder": r}, "register_finder")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def param_finder_menu():
    clear()
    banner()
    section("🔗 Parameter Finder")

    print(f"  {C.GRAY}Test 101 parameters (recon only){C.RESET}\n")

    u = prompt("  URL with params (e.g. https://example.com/?id=1)")
    if not u:
        return

    try:
        from modules.web.param_finder import run_param_finder, print_param_finder_report
        r = run_param_finder(u)
        print_param_finder_report(r)
        if confirm("  Save?"):
            save_report({"param_finder": r}, "param_finder")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


# ============================================================
# Security & Monitoring (11-13)
# ============================================================

def waf_detector_menu():
    clear()
    banner()
    section("🛡️  WAF Detector")

    print(f"  {C.GRAY}Detect 17 WAFs (Cloudflare, Akamai, Sucuri, etc.){C.RESET}\n")

    u = prompt("  URL or domain")
    if not u:
        return

    try:
        from modules.web.waf_detector import run_waf_detector, print_waf_report
        r = run_waf_detector(u)
        print_waf_report(r)
        if confirm("  Save?"):
            save_report({"waf_detector": r}, "waf_detector")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def web_monitor_menu():
    clear()
    banner()
    section("👁️  Web Monitor")

    print(f"  {C.GRAY}Detect changes over time (run twice){C.RESET}")
    print(f"  {C.GRAY}Baselines saved to ~/.reconx/monitor/{C.RESET}\n")

    u = prompt("  URL")
    if not u:
        return

    try:
        from modules.web.web_monitor import run_web_monitor, print_web_monitor_report
        r = run_web_monitor(u)
        print_web_monitor_report(r)
        if confirm("  Save?"):
            save_report({"web_monitor": r}, "web_monitor")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def ssl_analyzer_menu():
    clear()
    banner()
    section("🔐 SSL/TLS Analyzer")

    h = prompt("  Hostname")
    if not h:
        return

    try:
        from modules.network.ssl_analyzer import run_ssl_analyzer, print_ssl_report
        r = run_ssl_analyzer(h)
        print_ssl_report(r)
        if confirm("  Save?"):
            save_report({"ssl": r}, "ssl")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


# ============================================================
# Full Recon (14-15)
# ============================================================



def dirb_menu():
    clear()
    banner()
    section("🎯 DIRB Content Scan")

    print(f"  {C.RED}⚠ Active scan — use only on authorized targets{C.RESET}\n")

    u = prompt("  URL (e.g. https://example.com)")
    if not u:
        return

    try:
        from modules.vuln.dirb_engine import (
            run_dirb, print_dirb_report, get_wordlists, is_dirb_available,
        )

        if not is_dirb_available():
            print(f"{C.RED}  ✗ dirb not installed{C.RESET}")
            print(f"{C.GRAY}  Install: sudo apt install dirb{C.RESET}")
            pause()
            return

        # Optional wordlist
        wordlists = get_wordlists()
        if wordlists:
            print(f"\n  {C.BOLD}Available wordlists:{C.RESET}")
            names = list(wordlists.keys())
            for i, name in enumerate(names[:10], 1):
                print(f"  {C.CYAN}[{i}]{C.RESET} {name}")

            choice = prompt("\n  Wordlist [default: common.txt]", default="")
            wl = None
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(names):
                    wl = wordlists[names[idx]]
            elif choice:
                wl = wordlists.get(choice)

            timeout = prompt("  Timeout (seconds)", default="300")
            try:
                timeout = int(timeout)
            except ValueError:
                timeout = 300
        else:
            wl = None
            timeout = 300

        print(f"\n{C.YELLOW}  ⚡ Running DIRB on {u}...{C.RESET}\n")
        r = run_dirb(u, wordlist=wl, timeout=timeout, verbose=True)
        print_dirb_report(r)

        if confirm("  Save JSON report?"):
            from modules.vuln.dirb_engine import save_dirb_report
            out = save_dirb_report(r, "outputs")
            print(f"{C.GREEN}  ✓ Saved: {out}{C.RESET}")

    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()

    pause()




def bounty_checks_menu():
    clear()
    banner()
    section("🐛 Bug Bounty Checks")

    print(f"  {C.RED}⚠ Active checks — use only on authorized targets{C.RESET}\n")
    print(f"  {C.GRAY}Checks: VCS, API docs, CORS, Open redirect, GraphQL, JWT{C.RESET}\n")

    u = prompt("  URL (e.g. https://example.com)")
    if not u:
        return

    try:
        from modules.vuln.bounty_checks import run_bounty_checks, print_bounty_report
        r = run_bounty_checks(u)
        print_bounty_report(r)

        if confirm("  Save JSON report?"):
            import json
            from pathlib import Path
            from datetime import datetime

            outputs = BASE_DIR / "outputs"
            outputs.mkdir(exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fp = outputs / f"bounty_checks_{ts}.json"
            with open(fp, "w", encoding="utf-8") as fh:
                json.dump(r, fh, indent=2, ensure_ascii=False, default=str)
            print(f"{C.GREEN}  ✓ Saved: {fp}{C.RESET}")

    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()

    pause()


def bugbounty_nikto_menu():
    clear()
    banner()
    section("💰 Bug Bounty Nikto")

    print(f"  {C.RED}⚠ Active scan — use only on authorized bug bounty programs{C.RESET}\n")
    print(f"  {C.GRAY}Multi-target parallel + WAF-aware + payout estimation{C.RESET}\n")

    mode = prompt("  Target (single URL or -f targets.txt)", default="")
    if not mode:
        return

    if mode.startswith("-f "):
        target_file = mode[3:].strip()
        try:
            with open(target_file) as fh:
                targets = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except Exception as e:
            print(f"{C.RED}  ✗ Can't read file: {e}{C.RESET}")
            pause()
            return
    else:
        targets = [mode]

    waf_skip = confirm("  Skip targets with WAF?")
    workers = prompt("  Workers", default="3")
    try:
        workers = int(workers)
    except ValueError:
        workers = 3

    try:
        from modules.vuln.bugbounty_nikto import (
            scan_targets, print_bounty_nikto_report, save_bounty_report,
        )
        from modules.vuln.nikto_engine import is_nikto_available

        if not is_nikto_available():
            print(f"{C.RED}  ✗ Nikto not installed{C.RESET}")
            print(f"{C.GRAY}  Install: sudo apt install nikto{C.RESET}")
            pause()
            return

        print(f"\n{C.YELLOW}  ⚡ Scanning {len(targets)} target(s)...{C.RESET}\n")

        r = scan_targets(targets, workers=workers, waf_skip=waf_skip, verbose=True)
        print_bounty_nikto_report(r)

        if confirm("  Save JSON report?"):
            out = save_bounty_report(r)
            print(f"{C.GREEN}  ✓ Saved: {out}{C.RESET}")

    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()

    pause()




# ============================================================
# Web Vulnerability Scanners (20-26)
# ============================================================

def _run_vuln_scanner(scanner_key, title, extra_tip=None):
    """Generic vuln scanner runner."""
    clear()
    banner()
    section(title)

    print(f"  {C.RED}⚠ Active scan — use only on authorized targets{C.RESET}")
    if extra_tip:
        print(f"  {C.GRAY}{extra_tip}{C.RESET}")
    print()

    u = prompt("  URL (with params if possible)")
    if not u:
        return

    try:
        from modules.vuln.scanner_manager import run_scanner, print_all_report
        from modules.vuln.scanner_manager import SCANNERS

        print(f"\n{C.YELLOW}  ⚡ Running {SCANNERS[scanner_key]['name']} scan...{C.RESET}\n")

        r = run_scanner(scanner_key, u, timeout=300, verbose=True)

        # Print using scanner's own report if available
        try:
            mod = __import__(SCANNERS[scanner_key]["module"], fromlist=["print_report"])
            print_fn = getattr(mod, "print_report")
            print_fn(r)
        except Exception:
            # Fallback
            from modules.vuln.scanner_manager import print_all_report
            print_all_report({
                "target": u,
                "scanners_run": [scanner_key],
                "scanners_failed": [],
                "findings": r.get("findings", []),
                "total_findings": len(r.get("findings", [])),
            })

        if confirm("  Save JSON report?"):
            save_report({f"vuln_{scanner_key}": r}, f"vuln_{scanner_key}")

    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()

    pause()


def sqli_menu():
    _run_vuln_scanner("sqli", "💉 SQL Injection Scanner",
                      "Needs: sqlmap (sudo apt install sqlmap)")


def xss_menu():
    _run_vuln_scanner("xss", "🎯 XSS Scanner",
                      "Optional: dalfox (for better detection)")


def ssrf_menu():
    _run_vuln_scanner("ssrf", "🌐 SSRF Scanner",
                      "Detects AWS/GCP metadata, file:// leaks")


def ssti_menu():
    _run_vuln_scanner("ssti", "📐 SSTI Scanner",
                      "Tests 16 template engines (Jinja2, Twig, Freemarker...)")


def cmdi_menu():
    _run_vuln_scanner("cmdi", "💻 Command Injection Scanner",
                      "Time-based + output-based detection")


def jwt_menu():
    _run_vuln_scanner("jwt", "🔑 JWT Scanner",
                      "Tests alg:none bypass + weak secrets")


def all_vuln_menu():
    clear()
    banner()
    section("🚀 ALL Web Vulnerability Scanners")

    print(f"  {C.RED}⚠ Active scan — use only on authorized targets{C.RESET}\n")
    print(f"  {C.GRAY}Runs: SQLi, XSS, SSRF, SSTI, CMDi, JWT (parallel){C.RESET}\n")

    u = prompt("  URL (with params)")
    if not u:
        return

    workers = prompt("  Workers", default="3")
    try:
        workers = int(workers)
    except ValueError:
        workers = 3

    print(f"\n{C.YELLOW}  ⚡ Running ALL vuln scanners on {u}...{C.RESET}")

    try:
        from modules.vuln.scanner_manager import run_all, print_all_report

        r = run_all(u, workers=workers, verbose=True)
        print_all_report(r)

        if confirm("  Save JSON report?"):
            save_report({"vuln_all": r}, "vuln_all")

    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()

    pause()


def full_web_recon_menu():
    clear()
    banner()
    section("🎯 Full Web Recon")

    print(f"  {C.GRAY}12 tools in parallel + auto HTML/TXT/JSON{C.RESET}\n")

    t = prompt("  Domain")
    if not t:
        return

    max_ips = prompt("  Max IPs to check", default="3")
    try:
        max_ips = int(max_ips)
    except ValueError:
        max_ips = 3

    print(f"\n{C.YELLOW}  ⚡ Starting FULL web recon on {t}...{C.RESET}\n")

    try:
        from recon import run_recon
        run_recon(t, deep=True, save_json_flag=True,
                  save_html_report=True, save_txt_report=True, max_ips=max_ips)
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()

    pause()


def fast_web_recon_menu():
    clear()
    banner()
    section("⚡ Fast Web Recon")

    print(f"  {C.GRAY}Skip subdomains + dirbuster{C.RESET}\n")

    t = prompt("  Domain")
    if not t:
        return

    print(f"\n{C.YELLOW}  ⚡ Starting FAST web recon on {t}...{C.RESET}\n")

    try:
        from recon import run_recon
        run_recon(t, deep=False, save_json_flag=True,
                  save_html_report=True, save_txt_report=True, max_ips=2)
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")
        import traceback
        traceback.print_exc()

    pause()


# ============================================================
# Info
# ============================================================

def show_env():
    clear()
    banner()
    section("ℹ️ Environment")

    try:
        from modules.utils.env_detect import get_environment, get_env_label
        env = get_environment()

        print(f"  {C.CYAN}Environment:{C.RESET}  {get_env_label(env)}")
        print(f"  {C.CYAN}Python:     {C.RESET}  {env.get('python')}")
        print(f"  {C.CYAN}Platform:   {C.RESET}  {env.get('platform')}")
        print(f"  {C.CYAN}Root:       {C.RESET}  {'YES' if env.get('is_root') else 'no'}")

        print(f"\n  {C.BOLD}Core Engines:{C.RESET}")
        for engine in ["cli.py", "recon.py"]:
            path = BASE_DIR / engine
            if path.exists():
                print(f"    {C.GREEN}✓{C.RESET} {engine}")
            else:
                print(f"    {C.RED}✗{C.RESET} {engine}")

        print(f"\n  {C.BOLD}Web Recon Modules:{C.RESET}")
        mods = [
            ("network.port_scan", "🔍"),
            ("network.dns_deep", "🌐"),
            ("network.ssl_analyzer", "🔐"),
            ("web.domain_osint", "🌐"),
            ("web.subdomain_enum", "🌐"),
            ("web.subfinder_clone", "🌐"),
            ("web.web_fingerprint", "🌍"),
            ("web.dir_buster", "📂"),
            ("web.login_finder", "🔐"),
            ("web.register_finder", "📝"),
            ("web.param_finder", "🔗"),
            ("web.waf_detector", "🛡️ "),
            ("web.web_monitor", "👁️ "),
            ("report.html_report", "📊"),
            ("utils.env_detect", "ℹ️ "),
        ]

        working = 0
        for m, icon in mods:
            try:
                __import__(f"modules.{m}")
                print(f"    {C.GREEN}✓{C.RESET} {icon} {m}")
                working += 1
            except ImportError:
                print(f"    {C.RED}✗{C.RESET} {icon} {m}")

        print(f"\n  {C.BOLD}Working: {working}/{len(mods)}{C.RESET}")
    except Exception as e:
        print(f"{C.RED}  Error: {e}{C.RESET}")

    pause()


def show_help():
    clear()
    banner()
    section("❓ Help")

    print(f"{C.BOLD}  ReconX v4.1.0 — Web Recon Toolkit (15 tools){C.RESET}")
    print(f"  Zero external tools needed. Termux, Kali, WSL.")
    print()
    print(f"{C.BOLD}  Recon Modules:{C.RESET}")
    print(f"  {C.CYAN}1{C.RESET}  Domain OSINT")
    print(f"  {C.CYAN}2{C.RESET}  IP OSINT")
    print(f"  {C.CYAN}3{C.RESET}  Port Scanner")
    print(f"  {C.CYAN}4{C.RESET}  DNS Deep")
    print(f"  {C.CYAN}5{C.RESET}  Subdomain Enumerator")
    print()
    print(f"{C.BOLD}  Web Discovery:{C.RESET}")
    print(f"  {C.CYAN}6{C.RESET}  Web Fingerprint")
    print(f"  {C.CYAN}7{C.RESET}  Directory Buster")
    print(f"  {C.CYAN}8{C.RESET}  Login Finder")
    print(f"  {C.CYAN}9{C.RESET}  Register Finder")
    print(f"  {C.CYAN}10{C.RESET} Parameter Finder")
    print()
    print(f"{C.BOLD}  Security & Monitoring:{C.RESET}")
    print(f"  {C.CYAN}11{C.RESET} WAF Detector")
    print(f"  {C.CYAN}12{C.RESET} Web Monitor")
    print(f"  {C.CYAN}13{C.RESET} SSL/TLS Analyzer")
    print()
    print(f"{C.BOLD}{C.RED}  Vulnerability Scan (active):{C.RESET}")
    print(f"  {C.RED}14{C.RESET} DIRB Content Scan")
    print(f"  {C.RED}15{C.RESET} Bug Bounty Checks")
    print(f"  {C.RED}16{C.RESET} Bug Bounty Nikto")
    print()
    print(f"{C.BOLD}{C.GREEN}  Full Recon:{C.RESET}")
    print(f"  {C.GREEN}17{C.RESET} Full Web Recon (parallel, 14 tools)")
    print(f"  {C.GREEN}18{C.RESET} Fast Web Recon")
    print()
    print(f"{C.BOLD}  CLI usage:{C.RESET}")
    print(f"  python recon.py example.com")
    print(f"  python recon.py example.com --fast")
    print()
    print(f"{C.BOLD}  Reports: {C.RESET}~/ReconX/outputs/")

    pause()


def show_outputs():
    clear()
    banner()
    section("📁 Outputs")

    outputs = BASE_DIR / "outputs"
    if not outputs.exists():
        print(f"  {C.YELLOW}No outputs yet.{C.RESET}")
        pause()
        return

    files = sorted(outputs.glob("*"), key=lambda f: f.stat().st_mtime, reverse=True)
    if not files:
        print(f"  {C.YELLOW}Empty.{C.RESET}")
        pause()
        return

    print(f"  {C.GRAY}{len(files)} files:{C.RESET}\n")
    for f in files[:20]:
        size = f.stat().st_size
        mt = datetime.fromtimestamp(f.stat().st_mtime).strftime("%m-%d %H:%M")
        color = C.CYAN
        if f.suffix == ".html":
            color = C.GREEN
        elif f.suffix == ".json":
            color = C.YELLOW
        print(f"  {color}•{C.RESET} {f.name:<50} {size:>8} B  {mt}")

    if len(files) > 20:
        print(f"  ... and {len(files) - 20} more")

    pause()


# ============================================================
# Save Helper
# ============================================================

def save_report(data, prefix="report"):
    outputs = BASE_DIR / "outputs"
    outputs.mkdir(exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fp = outputs / f"{prefix}_{ts}.json"

    data["_saved_at"] = datetime.now().isoformat()
    data["_tool"] = "ReconX v4.1.0"

    try:
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n{C.GREEN}  ✓ Saved: {fp}{C.RESET}")
        return fp
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
