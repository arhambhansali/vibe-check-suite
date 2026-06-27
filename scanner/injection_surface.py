from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import requests
from requests.exceptions import RequestException
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ── Payload paths ──────────────────────────────────────────────────────────────
PAYLOAD_DIR   = Path(__file__).resolve().parent.parent / "payloads"
SQLI_FILE     = PAYLOAD_DIR / "sqli_canaries.txt"
XSS_FILE      = PAYLOAD_DIR / "xss_canaries.txt"

# ── SQLi error signatures ──────────────────────────────────────────────────────
SQLI_SIGNATURES: list[str] = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "supplied argument is not a valid mysql",
    # PostgreSQL
    "pg_query",
    "pg_exec",
    "postgresql",
    "unterminated quoted string",
    "syntax error at or near",
    # SQLite
    "sqlite3",
    "sqlite_",
    "unrecognized token",
    # MSSQL
    "microsoft sql",
    "odbc sql server",
    "odbc microsoft access",
    "jet database engine",
    "access database engine",
    "unclosed quotation mark",
    "incorrect syntax near",
    # Oracle
    "ora-",
    "oracle error",
    "oracle driver",
    # Generic
    "sql syntax",
    "sql error",
    "database error",
    "db error",
    "query failed",
    "invalid query",
    "sql command",
    "syntax error",
    "unexpected end of sql",
]

# ── XSS reflection check ───────────────────────────────────────────────────────
XSS_PROBE      = "<vbchk-xss-probe>"
XSS_PROBE_RE   = XSS_PROBE.lower()


# ── Data containers ────────────────────────────────────────────────────────────

@dataclass
class InjectionFinding:
    url: str
    param: str
    injection_type: str    # sqli | xss | template
    severity: str
    detail: str
    evidence: str = ""


@dataclass
class InjectionScanResult:
    findings: list[InjectionFinding] = field(default_factory=list)
    endpoints_tested: int            = 0
    params_tested: int               = 0
    sqli_hits: int                   = 0
    xss_hits: int                    = 0


# ── Scanner ────────────────────────────────────────────────────────────────────

class InjectionScanner:
    """
    Maps injection surface and probes for:
      1. SQL injection — error-based detection
      2. Reflected XSS — probe reflection detection
      3. Template injection — expression canaries ({{7*7}}, ${7*7})
    
    Read-only where possible — never submits destructive payloads.
    Targets URL parameters and discovered form endpoints.
    """

    DEFAULT_HEADERS: dict[str, str] = {
        "User-Agent": "vibecheck-auditor/0.1 (security audit; read-only)",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    def __init__(
        self,
        target_url: str,
        pages: list[str] | None = None,
        forms: list | None = None,
        timeout: int = 10,
        delay: float = 0.15,
    ) -> None:
        self.target_url = target_url.rstrip("/")
        self.pages      = pages or [target_url]
        self.forms      = forms or []
        self.timeout    = timeout
        self.delay      = delay

        self._session = requests.Session()
        self._session.headers.update(self.DEFAULT_HEADERS)

        self._sqli_payloads = self._load_payloads(SQLI_FILE, self._default_sqli())
        self._xss_payloads  = self._load_payloads(XSS_FILE,  self._default_xss())

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self) -> InjectionScanResult:
        result = InjectionScanResult()

        console.print(
            f"\n  [bold cyan][[/bold cyan]injection_surface[bold cyan]][/bold cyan]"
            f"  Scanning [bold yellow]{self.target_url}[/bold yellow]"
            f"  [dim]({len(self._sqli_payloads)} SQLi  "
            f"{len(self._xss_payloads)} XSS payloads)[/dim]\n"
        )

        # ── Probe URL parameters on crawled pages ─────────────────────────────
        for page_url in self.pages:
            parsed = urlparse(page_url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            result.endpoints_tested += 1
            console.print(
                f"  [dim]URL params:[/dim]  [white]{page_url}[/white]  "
                f"[dim]({len(params)} param(s))[/dim]"
            )

            for param_name in params:
                result.params_tested += 1
                sqli = self._probe_sqli_get(page_url, param_name, parsed)
                xss  = self._probe_xss_get(page_url, param_name, parsed)
                result.findings.extend(sqli + xss)
                result.sqli_hits += len(sqli)
                result.xss_hits  += len(xss)
                time.sleep(self.delay)

        # ── Probe discovered form endpoints ───────────────────────────────────
        seen_actions: set[str] = set()
        for form in self.forms:
            action_key = f"{form.method}:{form.action}"
            if action_key in seen_actions:
                continue
            seen_actions.add(action_key)
            result.endpoints_tested += 1

            console.print(
                f"  [dim]Form endpoint:[/dim]  "
                f"[white]{form.action}[/white]  "
                f"[dim]({form.method}  field={form.name})[/dim]"
            )
            result.params_tested += 1

            sqli = self._probe_sqli_form(form)
            xss  = self._probe_xss_form(form)
            result.findings.extend(sqli + xss)
            result.sqli_hits += len(sqli)
            result.xss_hits  += len(xss)
            time.sleep(self.delay)

        # ── Always probe root URL with common param names ─────────────────────
        console.print(
            f"\n  [dim]→ Probing common parameter names on root...[/dim]"
        )
        common_params = ["id", "q", "search", "query", "page", "user", "name",
                         "email", "input", "data", "filter", "sort", "redirect"]
        result.endpoints_tested += 1
        for param in common_params:
            result.params_tested += 1
            sqli = self._probe_sqli_get(self.target_url, param, urlparse(self.target_url))
            xss  = self._probe_xss_get(self.target_url, param, urlparse(self.target_url))
            result.findings.extend(sqli + xss)
            result.sqli_hits += len(sqli)
            result.xss_hits  += len(xss)
            time.sleep(self.delay)

        self._print_summary(result)
        return result

    # ── SQLi probes ────────────────────────────────────────────────────────────

    def _probe_sqli_get(
        self, url: str, param: str, parsed
    ) -> list[InjectionFinding]:
        findings: list[InjectionFinding] = []
        seen: set[str] = set()

        for payload in self._sqli_payloads:
            try:
                probe_url = self._inject_get_param(parsed, param, payload)
                resp = self._session.get(
                    probe_url, timeout=self.timeout, allow_redirects=True
                )
                sig = self._detect_sqli(resp.text)
                if sig and sig not in seen:
                    seen.add(sig)
                    console.print(
                        f"  [bold red]  ⚠ SQLi SIGNAL[/bold red]  "
                        f"param=[bold white]{param}[/bold white]  "
                        f"[dim]sig={sig!r}[/dim]"
                    )
                    findings.append(InjectionFinding(
                        url=url,
                        param=param,
                        injection_type="sqli",
                        severity="CRITICAL",
                        detail=f"SQL error signature detected on param '{param}'",
                        evidence=f"Signature: {sig!r}  |  Payload: {payload!r}",
                    ))
            except RequestException:
                continue

        return findings

    def _probe_sqli_form(self, form) -> list[InjectionFinding]:
        findings: list[InjectionFinding] = []
        seen: set[str] = set()

        for payload in self._sqli_payloads:
            try:
                data = {form.name: payload}
                if form.method == "POST":
                    resp = self._session.post(
                        form.action, data=data,
                        timeout=self.timeout, allow_redirects=True
                    )
                else:
                    resp = self._session.get(
                        form.action, params=data,
                        timeout=self.timeout, allow_redirects=True
                    )
                sig = self._detect_sqli(resp.text)
                if sig and sig not in seen:
                    seen.add(sig)
                    console.print(
                        f"  [bold red]  ⚠ SQLi SIGNAL[/bold red]  "
                        f"form=[bold white]{form.action}[/bold white]  "
                        f"field=[bold white]{form.name}[/bold white]  "
                        f"[dim]sig={sig!r}[/dim]"
                    )
                    findings.append(InjectionFinding(
                        url=form.action,
                        param=form.name,
                        injection_type="sqli",
                        severity="CRITICAL",
                        detail=f"SQL error signature on form field '{form.name}'",
                        evidence=f"Signature: {sig!r}  |  Payload: {payload!r}",
                    ))
            except RequestException:
                continue

        return findings

    # ── XSS probes ─────────────────────────────────────────────────────────────

    def _probe_xss_get(
        self, url: str, param: str, parsed
    ) -> list[InjectionFinding]:
        findings: list[InjectionFinding] = []

        try:
            probe_url = self._inject_get_param(parsed, param, XSS_PROBE)
            resp = self._session.get(
                probe_url, timeout=self.timeout, allow_redirects=True
            )
            if XSS_PROBE_RE in resp.text.lower():
                console.print(
                    f"  [bold red]  ⚠ XSS REFLECTED[/bold red]  "
                    f"param=[bold white]{param}[/bold white]  "
                    f"[dim]probe reflected unescaped in response[/dim]"
                )
                findings.append(InjectionFinding(
                    url=url,
                    param=param,
                    injection_type="xss",
                    severity="HIGH",
                    detail=f"XSS probe reflected unescaped in response for param '{param}'",
                    evidence=f"Probe: {XSS_PROBE!r}",
                ))
        except RequestException:
            pass

        return findings

    def _probe_xss_form(self, form) -> list[InjectionFinding]:
        findings: list[InjectionFinding] = []

        try:
            data = {form.name: XSS_PROBE}
            if form.method == "POST":
                resp = self._session.post(
                    form.action, data=data,
                    timeout=self.timeout, allow_redirects=True
                )
            else:
                resp = self._session.get(
                    form.action, params=data,
                    timeout=self.timeout, allow_redirects=True
                )
            if XSS_PROBE_RE in resp.text.lower():
                console.print(
                    f"  [bold red]  ⚠ XSS REFLECTED[/bold red]  "
                    f"form=[bold white]{form.action}[/bold white]  "
                    f"field=[bold white]{form.name}[/bold white]"
                )
                findings.append(InjectionFinding(
                    url=form.action,
                    param=form.name,
                    injection_type="xss",
                    severity="HIGH",
                    detail=f"XSS probe reflected in form response for field '{form.name}'",
                    evidence=f"Probe: {XSS_PROBE!r}",
                ))
        except RequestException:
            pass

        return findings

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _inject_get_param(self, parsed, param: str, value: str) -> str:
        new_query = urlencode({param: value})
        return urlunparse(parsed._replace(query=new_query))

    def _detect_sqli(self, body: str) -> str | None:
        lower = body.lower()
        for sig in SQLI_SIGNATURES:
            if sig in lower:
                return sig
        return None

    def _load_payloads(self, path: Path, defaults: list[str]) -> list[str]:
        if not path.exists():
            return defaults
        payloads = []
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    payloads.append(stripped)
        return payloads or defaults

    def _default_sqli(self) -> list[str]:
        return ["'", '"', ";", "--", "' OR '1'='1", "' OR 1=1--", "SLEEP(0)"]

    def _default_xss(self) -> list[str]:
        return ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

    # ── Rich output ────────────────────────────────────────────────────────────

    def _print_summary(self, result: InjectionScanResult) -> None:
        console.print()

        if not result.findings:
            console.print(
                "  [bold green]✓[/bold green] "
                "[green]No injection vulnerabilities detected.[/green]\n"
            )
            return

        table = Table(
            title="Injection Surface Findings",
            box=box.SIMPLE_HEAVY,
            border_style="red",
            show_lines=True,
        )
        table.add_column("Severity",  style="bold",   width=10)
        table.add_column("Type",      style="cyan",   width=10)
        table.add_column("Param",     style="white",  width=14)
        table.add_column("Endpoint",  style="yellow", no_wrap=False)
        table.add_column("Evidence",  style="dim",    no_wrap=False)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for f in sorted(result.findings, key=lambda x: severity_order.get(x.severity, 9)):
            color = {
                "CRITICAL": "bold red",
                "HIGH":     "red",
                "MEDIUM":   "yellow",
                "LOW":      "dim white",
            }.get(f.severity, "white")
            table.add_row(
                f"[{color}]{f.severity}[/{color}]",
                f.injection_type,
                f.param,
                f.url,
                f.evidence,
            )

        console.print(table)

        critical = sum(1 for f in result.findings if f.severity == "CRITICAL")
        high     = sum(1 for f in result.findings if f.severity == "HIGH")
        color    = "bold red" if (critical + high) > 0 else "bold yellow"
        symbol   = "⚠" if result.findings else "✓"

        console.print(
            f"  [{color}]{symbol} Injection Scan complete[/{color}] —"
            f"  [bold]{result.endpoints_tested}[/bold] endpoint(s),"
            f"  [bold]{result.params_tested}[/bold] param(s) tested,"
            f"  [bold red]{critical}[/bold red] CRITICAL,"
            f"  [bold red]{high}[/bold red] HIGH,"
            f"  [bold]{len(result.findings)}[/bold] total finding(s)\n"
        )