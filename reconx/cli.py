"""ReconX CLI - All-in-One OSINT Suite

Usage:
    python -m reconx -u <username>       Username search across 100+ platforms
    python -m reconx -e <email>          Email reconnaissance
    python -m reconx -d <domain>         Domain intelligence
    python -m reconx -i <ip>             IP geolocation & profiling
    python -m reconx -u <user> -o json   Export results as JSON
    python -m reconx --list              List available modules
"""

import argparse
import json
import os
import sys
import time

from rich.console import Console

from reconx import __version__
from reconx.utils.output import print_banner, print_info, print_error, print_warning


console = Console()


def create_parser():
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX - All-in-One OSINT Suite",
        epilog="Example: python -m reconx -u johndoe -t 15 -w 30",
    )
    parser.add_argument("-v", "--version", action="version", version=f"ReconX v{__version__}")

    # Target type arguments
    target_group = parser.add_argument_group("Target Options")
    target_group.add_argument("-u", "--username", help="Search for a username across platforms")
    target_group.add_argument("-e", "--email", help="Email address reconnaissance")
    target_group.add_argument("-d", "--domain", help="Domain intelligence gathering")
    target_group.add_argument("-i", "--ip", help="IP geolocation and profiling")

    # Configuration
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    config_group.add_argument("-w", "--workers", type=int, default=20, help="Number of concurrent threads (default: 20)")
    config_group.add_argument("--verbose", action="store_true", help="Enable verbose output")

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-o", "--output", choices=["json", "csv", "txt"], help="Export results to file")
    output_group.add_argument("-f", "--file", help="Output filename (default: reconx_results.<ext>)")
    output_group.add_argument(
        "--no-banner",
        "--quiet",
        dest="no_banner",
        action="store_true",
        help="Skip the banner display",
    )

    # Info
    parser.add_argument("--list", action="store_true", help="List all available modules")

    return parser


def list_modules():
    from reconx.core.engine import Engine
    from reconx.modules.username import UsernameRecon
    from reconx.modules.email import EmailRecon
    from reconx.modules.domain import DomainRecon
    from reconx.modules.ip import IPRecon

    engine = Engine()
    engine.register(UsernameRecon)
    engine.register(EmailRecon)
    engine.register(DomainRecon)
    engine.register(IPRecon)

    from rich.table import Table
    table = Table(title="[bold cyan]Available Modules[/bold cyan]", box=None)
    table.add_column("Module", style="bold cyan")
    table.add_column("Description", style="white")
    table.add_column("Flag", style="yellow")

    modules_info = [
        ("username", "Search username across 100+ platforms", "-u <username>"),
        ("email", "Email breach checks, domain info, Gravatar", "-e <email>"),
        ("domain", "DNS, WHOIS, subdomain enumeration, tech detect", "-d <domain>"),
        ("ip", "Geolocation, ASN, reverse DNS, port scan", "-i <ip>"),
    ]
    for name, desc, flag in modules_info:
        table.add_row(name, desc, flag)
    console.print(table)


def export_results(results, format_type, filename):
    """Export results to a file."""
    if not filename:
        filename = f"reconx_results.{format_type}"
    else:
        parent = os.path.dirname(os.path.abspath(filename))
        if parent:
            os.makedirs(parent, exist_ok=True)

    if format_type == "json":
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"[bold green]Results saved to {filename}[/bold green]")

    elif format_type == "csv":
        import csv
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Platform", "URL", "Status", "Extra"])
            for r in results:
                extra = json.dumps(r.get("extra", {}), ensure_ascii=False) if r.get("extra") else ""
                writer.writerow([r.get("platform", ""), r.get("url", ""), r.get("status", ""), extra])
        console.print(f"[bold green]Results saved to {filename}[/bold green]")

    elif format_type == "txt":
        with open(filename, "w", encoding="utf-8") as f:
            for r in results:
                status_icon = "+" if r.get("status") == "found" else "-"
                f.write(f"[{status_icon}] {r.get('platform', '')}: {r.get('url', '')}\n")
                if r.get("extra"):
                    f.write(f"    Extra: {json.dumps(r['extra'], ensure_ascii=False)}\n")
        console.print(f"[bold green]Results saved to {filename}[/bold green]")


def main():
    parser = create_parser()
    args = parser.parse_args()

    if args.quiet:
        args.no_banner = True
        from reconx.utils.output import set_quiet
        set_quiet(True)
        global console
        from rich.console import Console as _C
        console = _C(quiet=True)
    elif not args.no_banner:
        print_banner()

    if args.list:
        list_modules()
        return

    # Determine target and module
    target = None
    module_name = None

    if args.username:
        target = args.username
        module_name = "username"
    elif args.email:
        target = args.email
        module_name = "email"
    elif args.domain:
        target = args.domain
        module_name = "domain"
    elif args.ip:
        target = args.ip
        module_name = "ip"
    else:
        parser.print_help()
        sys.exit(1)

    # Import and run the appropriate module
    start_time = time.time()

    try:
        if module_name == "username":
            from reconx.modules.username import UsernameRecon
            module = UsernameRecon(verbose=args.verbose, timeout=args.timeout)
            module.run(target, workers=args.workers)

        elif module_name == "email":
            from reconx.modules.email import EmailRecon
            module = EmailRecon(verbose=args.verbose, timeout=args.timeout)
            module.run(target)

        elif module_name == "domain":
            from reconx.modules.domain import DomainRecon
            module = DomainRecon(verbose=args.verbose, timeout=args.timeout)
            module.run(target)

        elif module_name == "ip":
            from reconx.modules.ip import IPRecon
            module = IPRecon(verbose=args.verbose, timeout=args.timeout)
            module.run(target)

    except KeyboardInterrupt:
        print_warning("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print_error(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    if not args.quiet:
        elapsed = time.time() - start_time
        console.print(f"\n[bold cyan]Completed in {elapsed:.2f} seconds[/bold cyan]")

    # Export results if requested
    if args.output and module:
        export_results(module.get_results(), args.output, args.file)


if __name__ == "__main__":
    main()
