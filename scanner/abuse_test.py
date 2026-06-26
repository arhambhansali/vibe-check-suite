from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ── Payload path ───────────────────────────────────────────────────────────────
PAYLOAD_DIR = Path(__file__).resolve().parent.parent / "payloads"
ERROR_TRIGGERS = PAYLOAD_DIR / "error_triggers.txt"

# ── Signatures that indicate stack trace / framework leakage ──────────────────
LEAK_SIGNATURES: list[str] = [
    # Generic
    "traceback",
    "stack trace",
    "exception",
    "error:",
    "syntax error",
    "at object.",
    "at module.",
    # Node / Express
    "express",
    "node_modules",
    "cannot read propert",
    "typeerror:",
    "referenceerror:",
    "syntaxerror:",
    # Python
    "django",
    "flask",
    "fastapi",
    "wsgi",
    "asgi",
    "file \"/",
    "line \\d",
    "most recent call last",
    # PHP
    "fatal error",
    "warning: ",
    "notice: ",
    "parse error",
    "on line",
    # SQL
    "sql syntax",
    "mysql_fetch",
    "pg_query",
    "sqlite3",
    "unclosed quotation",
    "unterminated string",
    "odbc_exec",
    # Next.js / Vercel
    "at getserversideprops",
    "at getstaticprops",
    "unhandled runtime error",
    "chunk failed",
    # Generic server errors worth flagging
    "internal server error",
    "application error",
    "something went wrong",
    "unexpected token",
    "cannot set headers",
]


# ── Data containers ────────────────────────────────────────────────────────────

@dataclass
class AbuseResult:
    endpoint: str
    test_type: str          # rate_limit | error_leak | stack_trace
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW | INFO
    detail: str
    evidence: str = ""


@dataclass
class AbuseTestResult:
    findings: list[AbuseResult]     = field(default_factory=list)
    endpoints_tested: int           = 0
    rate_limit_missing: int         = 0
    error_leaks_found: int          = 0


# ── Tester ─────────────────────────────────────────────────────────────────────

class AbuseTester:
    """
    Probes endpoints for:
      1. Missing rate limiting on auth endpoints
      2. Stack trace / framework info leakage on malformed input
      3. Verbose error messages that expose internals
    """

    DEFAULT_HEADERS: dict[str, str] = {
        "User-Agent": "vibecheck-auditor/0.1 (security audit; read-only)",
        "Content-Type": "application/json",
    }

    def __init__(
        self,
        target_url: str,
        extra_routes: list[str] | None = None,
        timeout: int = 10,
        rate_limit_attempts: int = 15,
        delay: float = 0.1,
    ) -> None:
        self.target_url   = target_url.rstrip("/")
        self.timeout      = timeout
        self.rate_limit_attempts = rate_limit_attempts
        self.delay        = delay

        # Always test login; add any extra routes passed in
        default_routes = ["/login", "/signin", "/api/login", "/api/auth/login",
                          "/api/signin", "/auth/login"]
        extra = extra_routes or []
        seen: set[str] = set()
        self.endpoints: list[str] = []
        for r in default_routes + extra:
            norm = "/" + r.strip("/")
            if norm not in seen:
                seen.add(norm)
                self.endpoints.append(urljoin(self.target_url, norm))

        self._session = requests.Session()
        self._session.headers.update(self.DEFAULT_HEADERS)
        self._payloads: list[str] = self._load_payloads()

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self) -> AbuseTestResult:
        result = AbuseTestResult()

        console.print(
            f"\n  [bold cyan][[/bold cyan]abuse_test[bold cyan]][/bold cyan]"
            f"  Probing [bold yellow]{self.target_url}[/bold yellow]"
            f"  [dim]({len(self.endpoints)} endpoint(s))[/dim]\n"
        )

        for endpoint in self.endpoints:
            console.print(f"  [dim]Testing:[/dim]  [bold white]{endpoint}[/bold white]")
            result.endpoints_tested += 1

            # ── Test 1: Rate limiting ─────────────────────────────────────────
            rl_finding = self._test_rate_limiting(endpoint)
            if rl_finding:
                result.findings.append(rl_finding)
                result.rate_limit_missing += 1

            # ── Test 2: Error / stack trace leakage ───────────────────────────
            leak_findings = self._test_error_leakage(endpoint)
            result.findings.extend(leak_findings)
            result.error_leaks_found += len(leak_findings)

            console.print()

        self._print_summary(result)
        return result

    # ── Rate limit test ────────────────────────────────────────────────────────

    def _test_rate_limiting(self, endpoint: str) -> AbuseResult | None:
        """
        Fire `rate_limit_attempts` rapid POST requests with dummy credentials.
        If none return 429 / 403 the endpoint is missing rate limiting.
        """
        console.print(
            f"    [dim]→ Rate limit probe  "
            f"({self.rate_limit_attempts} requests)[/dim]"
        )

        status_codes: list[int] = []
        blocked = False

        for i in range(self.rate_limit_attempts):
            try:
                resp = self._session.post(
                    endpoint,
                    json={"email": f"probe{i}@vibecheck.test", "password": "VibeCheck!probe"},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                status_codes.append(resp.status_code)
                if resp.status_code in (429, 403):
                    blocked = True
                    console.print(
                        f"    [green]  ✓[/green] Rate limit triggered at "
                        f"request {i + 1}  [dim](HTTP {resp.status_code})[/dim]"
                    )
                    break
            except RequestException:
                break
            time.sleep(self.delay)

        if blocked:
            return None

        unique = set(status_codes)
        console.print(
            f"    [bold red]  ⚠ No rate limit detected[/bold red]  "
            f"[dim]{self.rate_limit_attempts} requests — "
            f"status codes seen: {sorted(unique)}[/dim]"
        )
        return AbuseResult(
            endpoint=endpoint,
            test_type="rate_limit",
            severity="HIGH",
            detail=f"No 429/403 after {self.rate_limit_attempts} rapid login attempts.",
            evidence=f"Status codes returned: {sorted(unique)}",
        )

    # ── Error leakage test ─────────────────────────────────────────────────────

    def _test_error_leakage(self, endpoint: str) -> list[AbuseResult]:
        """
        Send malformed payloads and scan responses for stack traces /
        framework signatures.
        """
        console.print(
            f"    [dim]→ Error leak probe  "
            f"({len(self._payloads)} payloads)[/dim]"
        )
        findings: list[AbuseResult] = []
        seen_signatures: set[str] = set()

        for payload in self._payloads:
            try:
                # Try as JSON body first
                resp = self._session.post(
                    endpoint,
                    json={"email": payload, "password": payload},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            except RequestException:
                continue

            if resp.status_code == 500:
                leak = self._scan_for_leaks(resp.text)
                sig  = leak or "HTTP 500"
                if sig not in seen_signatures:
                    seen_signatures.add(sig)
                    severity = "CRITICAL" if leak else "HIGH"
                    leak_label = "STACK TRACE" if leak else "HTTP 500"
                    console.print(
                        f"    [bold red]  ⚠ {leak_label} "
                        f"leaked[/bold red]  [dim]payload={payload!r}[/dim]"
                    )
                    findings.append(AbuseResult(
                        endpoint=endpoint,
                        test_type="stack_trace" if leak else "error_leak",
                        severity=severity,
                        detail=f"Server returned HTTP 500 on malformed input.",
                        evidence=f"Payload: {payload!r}  |  Signature: {sig}  |  "
                                 f"Response snippet: {resp.text[:200]}",
                    ))

            elif resp.status_code not in (400, 401, 403, 404, 422):
                leak = self._scan_for_leaks(resp.text)
                if leak and leak not in seen_signatures:
                    seen_signatures.add(leak)
                    console.print(
                        f"    [bold red]  ⚠ Info leak[/bold red]  "
                        f"[dim]signature={leak!r}  payload={payload!r}[/dim]"
                    )
                    findings.append(AbuseResult(
                        endpoint=endpoint,
                        test_type="error_leak",
                        severity="MEDIUM",
                        detail=f"Framework/server signature detected in response body.",
                        evidence=f"Signature: {leak!r}  |  "
                                 f"Response snippet: {resp.text[:200]}",
                    ))

        if not findings:
            console.print(f"    [green]  ✓[/green] No error leakage detected")

        return findings

    # ── Leak scanner ───────────────────────────────────────────────────────────

    def _scan_for_leaks(self, body: str) -> str | None:
        """Return the first matching leak signature found in the response body."""
        lower = body.lower()
        for sig in LEAK_SIGNATURES:
            if sig in lower:
                return sig
        return None

    # ── Payload loader ─────────────────────────────────────────────────────────

    def _load_payloads(self) -> list[str]:
        if not ERROR_TRIGGERS.exists():
            console.print(
                f"  [yellow]  ⚠[/yellow] Payload file not found at "
                f"[dim]{ERROR_TRIGGERS}[/dim] — using built-in defaults"
            )
            return ["'", '"', "<script>", "null", "../", "%00"]

        payloads = []
        with ERROR_TRIGGERS.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    payloads.append(stripped)
        return payloads

    # ── Rich output ────────────────────────────────────────────────────────────

    def _print_summary(self, result: AbuseTestResult) -> None:
        console.print()

        if not result.findings:
            console.print(
                "  [bold green]✓[/bold green] [green]No abuse vulnerabilities detected.[/green]\n"
            )
            return

        table = Table(
            title="Abuse Test Findings",
            box=box.SIMPLE_HEAVY,
            border_style="red",
            show_lines=True,
        )
        table.add_column("Severity",  style="bold red",    width=10)
        table.add_column("Type",      style="cyan",        width=14)
        table.add_column("Endpoint",  style="yellow",      no_wrap=False)
        table.add_column("Detail",    style="white",       no_wrap=False)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            result.findings, key=lambda f: severity_order.get(f.severity, 9)
        )

        for f in sorted_findings:
            color = {"CRITICAL": "bold red", "HIGH": "red",
                     "MEDIUM": "yellow", "LOW": "dim"}.get(f.severity, "white")
            table.add_row(
                f"[{color}]{f.severity}[/{color}]",
                f.test_type,
                f.endpoint,
                f.detail,
            )

        console.print(table)

        critical = sum(1 for f in result.findings if f.severity == "CRITICAL")
        high     = sum(1 for f in result.findings if f.severity == "HIGH")

        console.print(
            f"  [bold red]⚠ Abuse Test complete[/bold red] —"
            f"  [bold]{result.endpoints_tested}[/bold] endpoint(s) tested,"
            f"  [bold red]{critical}[/bold red] CRITICAL,"
            f"  [bold red]{high}[/bold red] HIGH,"
            f"  [bold]{len(result.findings)}[/bold] total finding(s)\n"
        )