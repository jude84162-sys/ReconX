from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def print_banner():
    """Print the ReconX banner."""
    banner = r"""
[bold cyan]
    ██████╗ ██████╗ ██████╗ ███████╗
   ██╔════╝██╔═══██╗██╔══██╗██╔════╝
   ██║     ██║   ██║██████╔╝█████╗
   ██║     ██║   ██║██╔══██╗██╔══╝
   ╚██████╗╚██████╔╝██║  ██║███████╗
    ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝[/bold cyan]
    [bold yellow]All-in-One OSINT Suite v1.0.0[/bold yellow]
    [dim]By jude84162-sys | github.com/jude84162-sys[/dim]
"""
    console.print(banner)


def print_success(msg):
    console.print(f"[bold green][+][/bold green] {msg}")


def print_error(msg):
    console.print(f"[bold red][-][/bold red] {msg}")


def print_info(msg):
    console.print(f"[bold blue][*][/bold blue] {msg}")


def print_warning(msg):
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def print_found(msg):
    console.print(f"[bold magenta][FOUND][/bold magenta] {msg}")


def print_not_found(msg):
    console.print(f"[dim][-] {msg}[/dim]")


def create_results_table(title, columns, rows):
    """Create a Rich table with results."""
    table = Table(title=f"[bold cyan]{title}[/bold cyan]", box=box.ROUNDED, show_lines=True)
    for col in columns:
        table.add_column(col["name"], style=col.get("style", "white"), header_style=col.get("header_style", "bold cyan"))
    for row in rows:
        table.add_row(*[str(cell) for cell in row])
    return table


def print_module_header(module_name, description, target):
    panel = Panel(
        f"[bold]Target:[/bold] {target}\n[bold]Module:[/bold] {module_name}\n[bold]Description:[/bold] {description}",
        title=f"[bold cyan]ReconX Module[/bold cyan]",
        border_style="cyan",
    )
    console.print(panel)


def print_summary(found, not_found, errors):
    """Print a summary of the scan."""
    console.print()
    panel = Panel(
        f"[bold green]Found:     {found}[/bold green]\n"
        f"[dim]Not Found: {not_found}[/dim]\n"
        f"[bold red]Errors:    {errors}[/bold red]",
        title="[bold yellow]Scan Summary[/bold yellow]",
        border_style="yellow",
    )
    console.print(panel)
