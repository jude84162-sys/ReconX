#!/usr/bin/env python3
"""
ReconX - Comprehensive OSINT Toolkit
Platforms: Termux, Kali Linux, WSL.
"""

import sys
import argparse
import json
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from modules.env_detect import get_environment, get_env_label, print_env_info
from modules.phone_osint import run_phone_osint, print_phone_report
from modules.username_osint import run_username_osint, print_username_report
from modules.domain_osint import run_domain_osint, print_domain_report
from modules.ip_osint import run_ip_osint, print_ip_report
from modules.email_osint import run_email_osint, print_email_report
from modules.metadata_osint import run_metadata_osint, print_metadata_report

VERSION = "1.0.0"
OUTPUT_DIR = BASE_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)


def banner():
    print("=" * 75)
    print("       🔍 ReconX - Comprehensive OSINT Toolkit")
    print(f"       v{VERSION}")
    print("=" * 75)


def detect_target_type(target):
    """Auto-detect target type."""
    if "@" in target:
        return "email"
    if target.startswith("+") or (target.replace("-", "").replace(" ", "").isdigit() and len(target) > 6):
        return "phone"
    # IP?
    parts = target.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return "ip"
    # Domain?
    if "." in target and not target.startswith("."):
        return "domain"
    return "username"


def save_report(data, filename="reconx_report.json"):
    output = OUTPUT_DIR / filename
    with open(output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n[✓] Saved: {output}")


def run_full(target, target_type="auto"):
    """Run full recon."""
    banner()

    env = get_environment()
    print(f"\n[*] Environment: {get_env_label(env)}")

    if target_type == "auto":
        target_type = detect_target_type(target)

    print(f"[*] Target:      {target}")
    print(f"[*] Type:        {target_type}")

    report = {
        "timestamp": datetime.now().isoformat(),
        "version": VERSION,
        "target": target,
        "type": target_type,
        "environment": get_env_label(env),
        "results": {}
    }

    if target_type == "phone":
        report["results"]["phone"] = run_phone_osint(target)
        print_phone_report(report["results"]["phone"])

    elif target_type == "email":
        report["results"]["email"] = run_email_osint(target)
        print_email_report(report["results"]["email"])

    elif target_type == "ip":
        report["results"]["ip"] = run_ip_osint(target)
        print_ip_report(report["results"]["ip"])

    elif target_type == "domain":
        report["results"]["domain"] = run_domain_osint(target)
        print_domain_report(report["results"]["domain"])

    elif target_type == "username":
        report["results"]["username"] = run_username_osint(target)
        print_username_report(report["results"]["username"])

    save_report(report)
    return report


def main():
    parser = argparse.ArgumentParser(
        description="ReconX - Comprehensive OSINT Toolkit (Termux/Kali/WSL)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("target", nargs="?", help="Target to investigate")

    parser.add_argument("--phone", metavar="NUMBER", help="Phone OSINT")
    parser.add_argument("--username", metavar="NAME", help="Username OSINT")
    parser.add_argument("--domain", metavar="DOMAIN", help="Domain OSINT")
    parser.add_argument("--ip", metavar="IP", help="IP OSINT")
    parser.add_argument("--email", metavar="EMAIL", help="Email OSINT")
    parser.add_argument("--metadata", metavar="FILE", help="Image metadata")

    parser.add_argument("--env", action="store_true", help="Show environment")
    parser.add_argument("--output", default="reconx_report.json")
    parser.add_argument("--quiet", "-q", action="store_true")
    parser.add_argument("--version", action="version", version=f"ReconX {VERSION}")

    args = parser.parse_args()

    # Environment
    if args.env:
        banner()
        print_env_info(get_environment())
        return

    # Specific modules
    if args.phone:
        banner()
        r = run_phone_osint(args.phone)
        print_phone_report(r)
        save_report({"phone": r}, args.output)
        return

    if args.username:
        banner()
        r = run_username_osint(args.username)
        print_username_report(r)
        save_report({"username": r}, args.output)
        return

    if args.domain:
        banner()
        r = run_domain_osint(args.domain)
        print_domain_report(r)
        save_report({"domain": r}, args.output)
        return

    if args.ip:
        banner()
        r = run_ip_osint(args.ip)
        print_ip_report(r)
        save_report({"ip": r}, args.output)
        return

    if args.email:
        banner()
        r = run_email_osint(args.email)
        print_email_report(r)
        save_report({"email": r}, args.output)
        return

    if args.metadata:
        banner()
        r = run_metadata_osint(args.metadata)
        print_metadata_report(r)
        save_report({"metadata": r}, args.output)
        return

    # Auto-detect
    if args.target:
        run_full(args.target)
        return

    # Help
    banner()
    parser.print_help()
    print()
    print("Examples:")
    print("  python reconx.py +963912345678       # Phone")
    print("  python reconx.py user@example.com    # Email")
    print("  python reconx.py 8.8.8.8             # IP")
    print("  python reconx.py example.com         # Domain")
    print("  python reconx.py johndoe             # Username")
    print()
    print("  python reconx.py --phone +963912345678")
    print("  python reconx.py --username johndoe")
    print("  python reconx.py --domain example.com")
    print("  python reconx.py --ip 8.8.8.8")
    print("  python reconx.py --email test@example.com")
    print("  python reconx.py --metadata ~/photo.jpg")
    print()


if __name__ == "__main__":
    main()
