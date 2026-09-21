#!/usr/bin/env python3
"""
ReconX - Full Test Suite
=========================
Tests ALL 25 tools with safe, legal targets.
Uses example.com + testphp.vulnweb.com (legal test targets).

Usage:
    python3 test_all_tools.py
    python3 test_all_tools.py --quick      # Skip slow tools
    python3 test_all_tools.py --target X   # Custom target
"""

import sys
import time
import argparse
import importlib
from pathlib import Path
from datetime import datetime

# Safe, legal test targets
SAFE_TARGET = "https://example.com"
SAFE_TARGET_WITH_PARAMS = "https://example.com/?id=1"
LEGAL_VULN_TARGET = "http://testphp.vulnweb.com"  # Public test site

# Colors
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


# ============================================================
# Test Definitions
# ============================================================

TESTS = [
    # (id, name, module_path, function, args, timeout)
    ("1",  "🌐 Domain OSINT",       "modules.web.domain_osint",
     "run_domain_osint", ("example.com",), 30),
    ("2",  "🌍 IP OSINT",           "modules.network.ip_osint",
     "run_ip_osint", ("8.8.8.8",), 20),
    ("3",  "🔍 Port Scanner",       "modules.network.port_scan",
     "get_ports", ("common",), 5),
    ("4",  "🌐 DNS Deep",           "modules.network.dns_deep",
     "run_dns_deep", ("example.com",), 30),
    ("5",  "🌐 Subdomain Enum",     "modules.web.subfinder_clone",
     "run_subfinder_clone", ("example.com",), 45),
    ("6",  "🌍 Web Fingerprint",    "modules.web.web_fingerprint",
     "run_web_fingerprint", (SAFE_TARGET,), 20),
    ("7",  "📂 Dir Buster",         "modules.web.dir_buster",
     "run_dir_bust", (SAFE_TARGET,), 30),
    ("8",  "🔐 Login Finder",       "modules.web.login_finder",
     "run_login_finder", (SAFE_TARGET,), 30),
    ("9",  "📝 Register Finder",    "modules.web.register_finder",
     "run_register_finder", (SAFE_TARGET,), 30),
    ("10", "🔗 Param Finder",       "modules.web.param_finder",
     "run_param_finder", (SAFE_TARGET_WITH_PARAMS,), 30),
    ("11", "🛡️  WAF Detector",      "modules.web.waf_detector",
     "run_waf_detector", (SAFE_TARGET,), 20),
    ("12", "👁️  Web Monitor",       "modules.web.web_monitor",
     "run_web_monitor", (SAFE_TARGET,), 20),
    ("13", "🔐 SSL/TLS",            "modules.network.ssl_analyzer",
     "run_ssl_analyzer", ("example.com",), 15),
    ("14", "💉 SQLi Scanner",       "modules.vuln.web.sqli_scanner",
     "is_available", (), 5),
    ("15", "🎯 XSS Scanner",        "modules.vuln.web.xss_scanner",
     "reflection_test", (SAFE_TARGET_WITH_PARAMS,), 30),
    ("16", "🌐 SSRF Scanner",       "modules.vuln.web.ssrf_scanner",
     "scan", (SAFE_TARGET_WITH_PARAMS,), 60),
    ("17", "📐 SSTI Scanner",       "modules.vuln.web.ssti_scanner",
     "scan", (SAFE_TARGET_WITH_PARAMS,), 60),
    ("18", "💻 CMDi Scanner",       "modules.vuln.web.cmdi_scanner",
     "scan", (SAFE_TARGET_WITH_PARAMS,), 90),
    ("19", "🔑 JWT Scanner",        "modules.vuln.web.jwt_scanner",
     "extract_jwts", (SAFE_TARGET,), 15),
    ("20", "🚀 Vuln Manager",       "modules.vuln.scanner_manager",
     "list_scanners", (), 5),
    ("21", "🎯 DIRB Engine",        "modules.vuln.dirb_engine",
     "is_dirb_available", (), 5),
    ("22", "🐛 Bounty Checks",      "modules.vuln.bounty_checks",
     "check_vcs_exposed", (SAFE_TARGET,), 20),
    ("23", "💰 Bounty Nikto",       "modules.vuln.bugbounty_nikto",
     "quick_waf_check", (SAFE_TARGET,), 15),
    ("24", "ℹ️  Env Detect",         "modules.utils.env_detect",
     "get_environment", (), 5),
    ("25", "📊 HTML Report",        "modules.report.html_report",
     "generate_report", ({}, str(Path.home() / "test_report.html")), 5),
]


# ============================================================
# Test Runner
# ============================================================

def run_test(test_id, name, module_path, func_name, args, timeout):
    """Run a single test."""
    start = time.time()

    try:
        # Import module
        mod = importlib.import_module(module_path)

        # Get function
        fn = getattr(mod, func_name, None)
        if not fn:
            return {
                "id": test_id,
                "name": name,
                "status": "FAIL",
                "error": f"Function '{func_name}' not found",
                "duration": time.time() - start,
            }

        # Run function
        result = fn(*args)

        duration = time.time() - start

        return {
            "id": test_id,
            "name": name,
            "status": "OK",
            "duration": duration,
            "result_type": type(result).__name__,
        }

    except Exception as e:
        return {
            "id": test_id,
            "name": name,
            "status": "FAIL",
            "error": f"{type(e).__name__}: {str(e)[:100]}",
            "duration": time.time() - start,
        }


def main():
    parser = argparse.ArgumentParser(description="ReconX Full Test Suite")
    parser.add_argument("--quick", action="store_true", help="Skip slow tests")
    parser.add_argument("--target", help="Custom target URL")
    parser.add_argument("--only", help="Test only specific ID")
    args = parser.parse_args()

    print(f"""{C.CYAN}
╔══════════════════════════════════════════════════════════════════╗
║  ReconX - Full Test Suite                                        ║
║  Testing ALL 25 tools                                             ║
╚══════════════════════════════════════════════════════════════════╝{C.RESET}
""")

    # Filter tests
    tests_to_run = TESTS
    if args.only:
        tests_to_run = [t for t in TESTS if t[0] == args.only]
    elif args.quick:
        # Skip slow ones
        skip = {"5", "8", "9", "10", "16", "17", "18", "21"}
        tests_to_run = [t for t in TESTS if t[0] not in skip]

    print(f"{C.GRAY}Running {len(tests_to_run)} tests...{C.RESET}\n")

    results = []
    overall_start = time.time()

    for test_id, name, module_path, func_name, t_args, timeout in tests_to_run:
        print(f"  [{test_id:>2}/25] {name:<28}", end=" ", flush=True)

        r = run_test(test_id, name, module_path, func_name, t_args, timeout)
        results.append(r)

        status = r["status"]
        duration = r["duration"]

        if status == "OK":
            print(f"{C.GREEN}✓{C.RESET} ({duration:.1f}s)")
        else:
            print(f"{C.RED}✗{C.RESET} ({duration:.1f}s)")
            print(f"        {C.RED}{r.get('error', '?')}{C.RESET}")

    # Summary
    total_time = time.time() - overall_start
    passed = sum(1 for r in results if r["status"] == "OK")
    failed = sum(1 for r in results if r["status"] == "FAIL")

    print(f"\n{C.CYAN}{'═' * 70}{C.RESET}")
    print(f"{C.BOLD}  TEST SUMMARY{C.RESET}")
    print(f"{C.CYAN}{'═' * 70}{C.RESET}\n")

    print(f"  Total:     {len(results)}")
    print(f"  {C.GREEN}Passed:    {passed}{C.RESET}")
    if failed:
        print(f"  {C.RED}Failed:    {failed}{C.RESET}")
    else:
        print(f"  Failed:    0")
    print(f"  Duration:  {total_time:.1f}s")
    print(f"  Score:     {(passed / len(results) * 100):.0f}%")

    if failed:
        print(f"\n  {C.BOLD}Failed tests:{C.RESET}")
        for r in results:
            if r["status"] == "FAIL":
                print(f"    ✗ [{r['id']}] {r['name']}")
                print(f"      {r.get('error', '?')}")

    print(f"\n{C.CYAN}{'═' * 70}{C.RESET}\n")

    # Exit code
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
