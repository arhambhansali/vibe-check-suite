import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Confirm
from rich import box
from rich.table import Table
from scanner.core_spider import CoreSpider
from scanner.jwt_crack import JWTCracker
from scanner.abuse_test import AbuseTester
from scanner.headers_audit import HeadersAuditor
from scanner.secret_scan import SecretScanner

console = Console()

ASCII_ART = r"""
 __   _____ ___  ___  ___ _  _ ___ ___ _  __
 \ \ / /_ _| _ )| __|/ __| || | __/ __| |/ /
  \ V / | || _ \| _|| (__| __ | _| (__| ' < 
   \_/ |___|___/|___|\__|_||_|___|\___|_|\_\
"""

MODULES = {
    "1": ("core_spider",   "Endpoint & Form Mapper"),
    "2": ("jwt_crack",     "JWT Signature Auditor"),
    "3": ("abuse_test",    "Rate-Limit & Error-Leak Prober"),
    "4": ("headers_audit", "Security Headers & Path Exposure"),
    "5": ("secret_scan",   "Secret & API Key Scanner"),
}


def print_banner() -> None:
    console.print(f"[bold cyan]{ASCII_ART}[/bold cyan]")
    console.print(
        Panel(
            "[bold cyan]VIBECHECK[/bold cyan]"
            "[dim white]  //  [/dim white]"
            "[bold white]QA & Security Posture Auditor[/bold white]",
            subtitle="[dim]Static & Dynamic Configuration Audit Suite[/dim]",
            border_style="cyan",
            padding=(0, 4),
        )
    )


def print_module_table() -> None:
    table = Table(
        box=box.SIMPLE_HEAVY,
        border_style="cyan",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("#",       width=4,  style="bold cyan")
    table.add_column("Module",  width=16, style="bold white")
    table.add_column("Description")

    for num, (mod, desc) in MODULES.items():
        table.add_row(num, mod, desc)

    console.print(table)


def select_modules() -> list[str]:
    """Prompt the user to select which modules to run."""
    console.print("\n[bold cyan]Available Modules:[/bold cyan]")
    print_module_table()

    console.print(
        "  [dim]Enter module numbers separated by commas, "
        "or press Enter to run [bold]all[/bold]:[/dim]"
    )
    raw = input("  > ").strip()

    if not raw:
        console.print("  [dim]Running all modules.[/dim]\n")
        return list(MODULES.keys())

    selected = []
    for part in raw.split(","):
        key = part.strip()
        if key in MODULES:
            selected.append(key)
        else:
            console.print(f"  [yellow]  ⚠ Unknown module '{key}' — skipped[/yellow]")

    if not selected:
        console.print("  [yellow]  No valid modules selected — running all.[/yellow]\n")
        return list(MODULES.keys())

    console.print(
        f"  [dim]Selected: "
        f"{', '.join(MODULES[k][0] for k in selected)}[/dim]\n"
    )
    return selected


@click.group()
def main() -> None:
    """VibeCheck — Audit configuration, error-handling, and cryptographic
    standards in modern web applications."""
    pass


@main.command()
@click.option(
    "--url", "-u",
    required=True,
    metavar="URL",
    help="Target URL of the web application to audit.",
)
@click.option(
    "--all", "run_all",
    is_flag=True,
    default=False,
    help="Skip module selection and run all modules automatically.",
)
@click.option(
    "--routes", "-r",
    default="",
    metavar="ROUTES",
    help="Comma-separated extra routes for abuse testing (e.g. /dashboard,/api/user).",
)
def scan(url: str, run_all: bool, routes: str) -> None:
    """Run a full audit against a target URL."""
    print_banner()

    console.print(
        f"\n[bold green]>[/bold green] Starting VibeCheck Audit Engine...\n"
    )
    console.print(f"  [dim]Target :[/dim]  [bold yellow]{url}[/bold yellow]")

    # ── Module selection ──────────────────────────────────────────────────────
    if run_all:
        selected = list(MODULES.keys())
        console.print(f"  [dim]Modules :[/dim]  [bold cyan]All (--all flag)[/bold cyan]\n")
    else:
        selected = select_modules()

    extra_routes = [r.strip() for r in routes.split(",") if r.strip()]

    # ── Shared state ──────────────────────────────────────────────────────────
    crawl_result = None

    # ── Phase 2: Core Spider ──────────────────────────────────────────────────
    if "1" in selected:
        spider = CoreSpider(url)
        crawl_result = spider.run()

    pages = crawl_result.pages_visited if crawl_result else [url]

    # ── Phase 3: JWT Auditor ──────────────────────────────────────────────────
    if "2" in selected:
        jwt_auditor = JWTCracker(url, pages=pages)
        jwt_auditor.run()

    # ── Phase 4: Abuse Tester ─────────────────────────────────────────────────
    if "3" in selected:
        abuse = AbuseTester(url, extra_routes=extra_routes or ["/dashboard"])
        abuse.run()

    # ── Phase 5: Headers Auditor ──────────────────────────────────────────────
    if "4" in selected:
        headers = HeadersAuditor(url)
        headers.run()

    # ── Phase 6: Secret Scanner ───────────────────────────────────────────────
    if "5" in selected:
        secrets = SecretScanner(url, pages=pages)
        secrets.run()

    console.print(
        "\n[bold green]✓[/bold green] [bold]VibeCheck audit complete.[/bold]\n"
    )


if __name__ == "__main__":
    main()