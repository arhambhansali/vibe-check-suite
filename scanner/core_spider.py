from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser

import requests
from requests.exceptions import RequestException
from rich.console import Console
from rich.table import Table
from rich import box

SKIP_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map",
    ".pdf", ".zip", ".gz", ".exe", ".dmg",
}

console = Console()


# ── Data containers ────────────────────────────────────────────────────────────

@dataclass
class FormField:
    tag: str
    name: str
    field_type: str
    action: str
    method: str


@dataclass
class CrawlResult:
    base_url: str
    pages_visited: list[str]          = field(default_factory=list)
    forms: list[FormField]            = field(default_factory=list)
    external_links: list[str]         = field(default_factory=list)
    errors: list[tuple[str, str]]     = field(default_factory=list)


# ── Spider ─────────────────────────────────────────────────────────────────────

class CoreSpider:
    """
    Polite, single-origin web crawler.
    Stays within the target origin, respects robots.txt, enforces a
    configurable page-cap and per-request delay, and never issues
    write-method requests — read-only audit only.
    """

    DEFAULT_HEADERS: dict[str, str] = {
        "User-Agent": "vibecheck-auditor/0.1 (security audit; read-only)",
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    }

    def __init__(
        self,
        target_url: str,
        max_pages: int = 40,
        delay: float = 0.3,
        timeout: int = 10,
        respect_robots: bool = True,
    ) -> None:
        self.target_url = target_url.rstrip("/")
        self.max_pages = max_pages
        self.delay = delay
        self.timeout = timeout
        self.respect_robots = respect_robots

        parsed = urlparse(self.target_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid target URL: {self.target_url!r}")

        self._origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        self._session = requests.Session()
        self._session.headers.update(self.DEFAULT_HEADERS)

        self._visited: set[str] = set()
        self._queue: list[str] = [self.target_url]
        self._robot_parser: RobotFileParser | None = None

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self) -> CrawlResult:
        result = CrawlResult(base_url=self.target_url)

        console.print(
            f"\n  [bold cyan][[/bold cyan]core_spider[bold cyan]][/bold cyan]"
            f"  Crawling [bold yellow]{self.target_url}[/bold yellow]"
            f"  [dim](max {self.max_pages} pages)[/dim]\n"
        )

        if self.respect_robots:
            self._load_robots()

        while self._queue and len(self._visited) < self.max_pages:
            url = self._queue.pop(0)
            url = self._normalise(url)

            if url in self._visited:
                continue
            if not self._same_origin(url):
                result.external_links.append(url)
                continue
            if self.respect_robots and not self._robots_allowed(url):
                console.print(f"  [dim]  robots.txt disallows  {url}[/dim]")
                continue

            self._visited.add(url)
            page_links, page_forms, error = self._fetch_and_parse(url)

            if error:
                result.errors.append((url, error))
                console.print(f"  [red]  ✗[/red] [dim]{url}[/dim]  [red]{error}[/red]")
            else:
                result.pages_visited.append(url)
                result.forms.extend(page_forms)
                console.print(
                    f"  [green]  ✓[/green] [dim]{url}[/dim]"
                    f"  [dim]({len(page_forms)} form field(s))[/dim]"
                )
                for link in page_links:
                    if link not in self._visited and link not in self._queue:
                        self._queue.append(link)

            time.sleep(self.delay)

        self._print_summary(result)
        return result

    # ── Robots.txt ─────────────────────────────────────────────────────────────

    def _load_robots(self) -> None:
        robots_url = f"{self._origin}/robots.txt"
        self._robot_parser = RobotFileParser()
        self._robot_parser.set_url(robots_url)
        try:
            self._robot_parser.read()
            console.print(f"  [dim]  robots.txt loaded from {robots_url}[/dim]")
        except Exception:
            console.print(f"  [dim]  robots.txt not found or unreadable — skipping[/dim]")
            self._robot_parser = None

    def _robots_allowed(self, url: str) -> bool:
        if self._robot_parser is None:
            return True
        return self._robot_parser.can_fetch(self.DEFAULT_HEADERS["User-Agent"], url)

    # ── Fetch & parse ──────────────────────────────────────────────────────────

    def _fetch_and_parse(
        self, url: str
    ) -> tuple[list[str], list[FormField], str | None]:
        try:
            response = self._session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                stream=False,
            )
            content_type = response.headers.get("Content-Type", "")
            if "html" not in content_type:
                return [], [], None

            response.raise_for_status()

        except RequestException as exc:
            return [], [], str(exc)

        links = self._extract_links(response.text, url)
        forms = self._extract_forms(response.text, url)
        return links, forms, None

    # ── Link extractor ─────────────────────────────────────────────────────────

    def _extract_links(self, html: str, base: str) -> list[str]:
        links: list[str] = []
        for match in re.finditer(r'href=["\']([^"\'#][^"\']*)["\']', html, re.IGNORECASE):
            href = match.group(1).strip()
            if href.startswith(("mailto:", "tel:", "javascript:")):
                continue
            absolute = urljoin(base, href)
            clean = urlunparse(urlparse(absolute)._replace(query="", fragment=""))

            # Skip static asset extensions
            if Path(urlparse(clean).path).suffix.lower() in SKIP_EXTENSIONS:
                continue

            links.append(clean)
        return links

    # ── Form extractor ─────────────────────────────────────────────────────────

    def _extract_forms(self, html: str, page_url: str) -> list[FormField]:
        fields: list[FormField] = []

        form_pattern = re.compile(
            r'<form([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL
        )
        field_pattern = re.compile(
            r'<(input|textarea|select)([^>]*?)(?:/>|>)', re.IGNORECASE | re.DOTALL
        )

        def attr(tag_attrs: str, key: str):
            return re.search(rf'{key}=["\']([^"\']*)["\']', tag_attrs, re.IGNORECASE)

        for form_match in form_pattern.finditer(html):
            form_attrs = form_match.group(1)
            form_body  = form_match.group(2)

            raw_action_m = attr(form_attrs, "action")
            raw_action   = raw_action_m.group(1) if raw_action_m else ""
            action       = urljoin(page_url, raw_action) if raw_action else page_url
            method_m     = attr(form_attrs, "method")
            method       = method_m.group(1).upper() if method_m else "GET"

            for field_match in field_pattern.finditer(form_body):
                tag       = field_match.group(1).lower()
                tag_attrs = field_match.group(2)
                name_m    = attr(tag_attrs, "name")
                type_m    = attr(tag_attrs, "type")
                name      = name_m.group(1) if name_m else "(unnamed)"
                ftype     = type_m.group(1).lower() if type_m else "text"

                if ftype in ("submit", "button", "image", "reset"):
                    continue

                fields.append(FormField(
                    tag=tag,
                    name=name,
                    field_type=ftype,
                    action=action,
                    method=method,
                ))

        return fields

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _same_origin(self, url: str) -> bool:
        parsed = urlparse(url)
        candidate_origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        return candidate_origin == self._origin

    def _normalise(self, url: str) -> str:
        p = urlparse(url)
        return urlunparse(p._replace(fragment=""))

    # ── Rich output ────────────────────────────────────────────────────────────

    def _print_summary(self, result: CrawlResult) -> None:
        console.print()

        page_table = Table(
            title="Pages Crawled",
            box=box.SIMPLE_HEAVY,
            border_style="cyan",
            show_lines=False,
        )
        page_table.add_column("#",   style="dim",         width=4)
        page_table.add_column("URL", style="bold yellow", no_wrap=False)

        for idx, page in enumerate(result.pages_visited, 1):
            page_table.add_row(str(idx), page)

        console.print(page_table)

        if result.forms:
            form_table = Table(
                title="Form Entry Points Discovered",
                box=box.SIMPLE_HEAVY,
                border_style="magenta",
                show_lines=True,
            )
            form_table.add_column("Field Name",  style="bold white")
            form_table.add_column("Type",        style="cyan")
            form_table.add_column("Tag",         style="dim")
            form_table.add_column("Method",      style="green")
            form_table.add_column("Action URL",  style="yellow", no_wrap=False)

            for f in result.forms:
                form_table.add_row(f.name, f.field_type, f.tag, f.method, f.action)

            console.print(form_table)
        else:
            console.print("  [dim]  No form entry points discovered.[/dim]")

        if result.errors:
            console.print(
                f"\n  [bold red]Crawl errors ({len(result.errors)}):[/bold red]"
            )
            for err_url, reason in result.errors:
                console.print(f"  [red]  ✗[/red] {err_url}  [dim]{reason}[/dim]")

        console.print(
            f"\n  [bold green]✓[/bold green] Spider complete —"
            f"  [bold]{len(result.pages_visited)}[/bold] pages,"
            f"  [bold]{len(result.forms)}[/bold] form fields,"
            f"  [bold]{len(result.external_links)}[/bold] external links,"
            f"  [bold]{len(result.errors)}[/bold] error(s)\n"
        )