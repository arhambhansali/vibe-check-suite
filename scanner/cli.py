import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from scanner.core_spider import CoreSpider
from scanner.jwt_crack import JWTCracker
from scanner.abuse_test import AbuseTester
from scanner.headers_audit import HeadersAuditor

console = Console()


def print_banner() -> None:
    """Renders the VibeCheck startup banner to the terminal."""
    banner_text = Text()
    banner_text.append("VIBECHECK", style="bold cyan")
    banner_text.append("  //  ", style="dim white")
    banner_text.append("QA & Security Posture Auditor", style="bold white")

    console.print(
        Panel(
            banner_text,
            subtitle="[dim]Static & Dynamic Configuration Audit Suite[/dim]",
            border_style="cyan",
            padding=(1, 4),
        )
    )


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
    help="Target URL of the web application to audit (e.g. https://example.com).",
)
def scan(url: str) -> None:
    """Run a full audit against a target URL."""
    print_banner()

    console.print(
        f"\n[bold green]>[/bold green] Starting VibeCheck Audit Engine...\n"
    )
    console.print(f"  [dim]Target :[/dim]  [bold yellow]{url}[/bold yellow]")
    console.print(f"  [dim]Status  :[/dim]  [bold cyan]Initializing modules...[/bold cyan]\n")

    # ── Phase 2: Core Spider ─────────────────────────────────────────────────
    spider = CoreSpider(url)
    result = spider.run()

    # ── Phase 3: JWT Auditor ─────────────────────────────────────────────────
    jwt_auditor = JWTCracker(url, pages=result.pages_visited)
    jwt_auditor.run()

    # ── Phase 4: Abuse Tester ────────────────────────────────────────────────
    abuse = AbuseTester(url, extra_routes=["/dashboard"])
    abuse.run()

    # ── Phase 5: Headers Auditor ─────────────────────────────────────────────
    headers = HeadersAuditor(url)
    headers.run()


if __name__ == "__main__":
    main()