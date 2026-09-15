"""ReconX CLI - All-in-One OSINT Suite

Usage:
    python -m reconx -u <username>       Username search across hundreds of platforms
    python -m reconx -d <domain>         Domain intelligence
    python -m reconx -i <ip>             IP geolocation & profiling
    python -m reconx username <username> Username search across platforms
    python -m reconx domain <domain>     Domain intelligence
    python -m reconx ip <ip>             IP geolocation & profiling
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


def _add_common_arguments(parser):
    """Add options shared by legacy and subcommand parsers."""
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument(
        "-t", "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)"
    )
    config_group.add_argument(
        "-w", "--workers", type=int, default=20, help="Number of concurrent threads (default: 20)"
    )
    config_group.add_argument("--verbose", action="store_true", help="Enable verbose output")

    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-o", "--output", choices=["json", "csv", "txt"], help="Export results to file")
    output_group.add_argument("-f", "--file", help="Output filename (default: reconx_results.<ext>)")
    output_group.add_argument("--no-banner", action="store_true", help="Skip the banner display")
    output_group.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress banner and non-essential output (for scripting)",
    )
    output_group.add_argument("--list", action="store_true", help="List all available modules")


def create_parser():
    """Create the backward-compatible flag-based parser."""
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX - All-in-One OSINT Suite",
        epilog="Example: python -m reconx -u johndoe -t 15 -w 30",
    )
    parser.add_argument("-v", "--version", action="version", version=f"ReconX v{__version__}")

    # Target type arguments
    target_group = parser.add_argument_group("Target Options")
    target_group.add_argument("-u", "--username", help="Search for a username across platforms")
    target_group.add_argument("-d", "--domain", help="Domain intelligence gathering")
    target_group.add_argument("-i", "--ip", help="IP geolocation and profiling")
    target_group.add_argument("--fedifinder", metavar="TARGET", help="Find Fediverse accounts")
    target_group.add_argument("--fediverse-observer", metavar="INSTANCE", help="Inspect a Fediverse instance")
    target_group.add_argument("--fediverse-osint", metavar="USERNAME", help="Search Fediverse instances")
    target_group.add_argument("--masto", metavar="HANDLE", help="Look up a Mastodon account")
    target_group.add_argument("--inflact", metavar="USERNAME", help="Fetch a public Inflact profile")
    target_group.add_argument("--osintgram", metavar="USERNAME", help="Run an Osintgram command")

    _add_common_arguments(parser)

    return parser


def create_subcommand_parser():
    """Create the modern subcommand-based parser."""
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX - All-in-One OSINT Suite",
        epilog="Example: reconx username johndoe -t 15 -w 30",
    )
    parser.add_argument("-v", "--version", action="version", version=f"ReconX v{__version__}")
    parser.add_argument("--list", action="store_true", help="List all available modules")
    subparsers = parser.add_subparsers(dest="command", required=True, title="Commands")

    for command, help_text in (
        ("username", "Search for a username across platforms"),
        ("domain", "Domain intelligence gathering"),
        ("ip", "IP geolocation and profiling"),
        ("fedifinder", "Find Fediverse accounts"),
        ("fediverse-observer", "Inspect a Fediverse instance"),
        ("fediverse-osint", "Search Fediverse instances"),
        ("masto", "Look up a Mastodon account"),
        ("inflact", "Fetch a public Inflact profile"),
        ("osintgram", "Run an external Osintgram command"),
    ):
        command_parser = subparsers.add_parser(command, help=help_text, description=help_text)
        command_parser.add_argument("target", help=f"{command} target")
        _add_common_arguments(command_parser)

    list_parser = subparsers.add_parser("list", help="List all available modules")
    _add_common_arguments(list_parser)
    list_parser.set_defaults(list=True)

    return parser


def list_modules():
    """Display the available ReconX modules."""
    from reconx.core.engine import Engine
    from reconx.modules.username import SITES, UsernameRecon
    from reconx.modules.domain import DomainRecon
    from reconx.modules.ip import IPRecon

    engine = Engine()
    engine.register(UsernameRecon)
    engine.register(DomainRecon)
    engine.register(IPRecon)

    from rich.table import Table
    table = Table(title="[bold cyan]Available Modules[/bold cyan]", box=None)
    table.add_column("Module", style="bold cyan")
    table.add_column("Description", style="white")
    table.add_column("Flag", style="yellow")

    modules_info = [
        ("username", f"Search username across {len(SITES)} platforms", "-u <username>"),
        ("domain", "DNS, WHOIS, subdomain enumeration, tech detect", "-d <domain>"),
        ("ip", "Geolocation, ASN, reverse DNS, port scan", "-i <ip>"),
        ("fedifinder", "Find Fediverse accounts", "--fedifinder <target>"),
        ("fediverse-observer", "Inspect a Fediverse instance", "--fediverse-observer <instance>"),
        ("fediverse-osint", "Search Fediverse instances", "--fediverse-osint <username>"),
        ("masto", "Look up a Mastodon account", "--masto <handle>"),
        ("inflact", "Fetch a public Inflact profile", "--inflact <username>"),
        ("osintgram", "Run an Osintgram command", "--osintgram <username>"),
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


def main(argv=None):
    """Run ReconX using legacy flags or modern subcommands."""
    argv = sys.argv[1:] if argv is None else argv
    subcommand_mode = bool(argv and not argv[0].startswith("-"))
    parser = create_subcommand_parser() if subcommand_mode else create_parser()
    args = parser.parse_args(argv)

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

    if subcommand_mode:
        target = args.target
        module_name = args.command
    else:
        target = None
        module_name = None

        if getattr(args, "fedifinder", None):
            target = args.fedifinder
            module_name = "fedifinder"
        elif getattr(args, "fediverse_observer", None):
            target = args.fediverse_observer
            module_name = "fediverse-observer"
        elif getattr(args, "fediverse_osint", None):
            target = args.fediverse_osint
            module_name = "fediverse-osint"
        elif getattr(args, "masto", None):
            target = args.masto
            module_name = "masto"
        elif getattr(args, "inflact", None):
            target = args.inflact
            module_name = "inflact"
        elif getattr(args, "osintgram", None):
            target = args.osintgram
            module_name = "osintgram"
        elif args.username:
            target = args.username
            module_name = "username"
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
    module = None

    try:
        if module_name == "username":
            from reconx.modules.username import UsernameRecon
            module = UsernameRecon(verbose=args.verbose, timeout=args.timeout)
            module.run(target, workers=args.workers)

        elif module_name == "domain":
            from reconx.modules.domain import DomainRecon
            module = DomainRecon(verbose=args.verbose, timeout=args.timeout)
            module.run(target)

        elif module_name == "ip":
            from reconx.modules.ip import IPRecon
            module = IPRecon(verbose=args.verbose, timeout=args.timeout)
            module.run(target)
        elif module_name == "fedifinder":
            from reconx.modules.fedifinder import FedifinderModule
            module = FedifinderModule()
            results = module.run(target, timeout=args.timeout)
        elif module_name == "fediverse-observer":
            from reconx.modules.fediverse_observer import FediverseObserverModule
            module = FediverseObserverModule()
            results = module.run(target, timeout=args.timeout)
        elif module_name == "fediverse-osint":
            from reconx.modules.fediverse_osint import FediverseOsintModule
            module = FediverseOsintModule()
            results = module.run(target, timeout=args.timeout)
        elif module_name == "masto":
            from reconx.modules.masto import MastoModule
            module = MastoModule()
            results = module.run(target, timeout=30)
        elif module_name == "inflact":
            from reconx.modules.inflact import InflactModule
            module = InflactModule()
            results = module.run(target, timeout=15)
        elif module_name == "osintgram":
            from reconx.modules.osintgram import OsintgramModule
            module = OsintgramModule()
            results = module.run(target, timeout=120)

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
        export_results(module.get_results() if hasattr(module, "get_results") else results, args.output, args.file)


if __name__ == "__main__":
    main()
