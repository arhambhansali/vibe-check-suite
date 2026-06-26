from __future__ import annotations

import re
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
PAYLOAD_DIR   = Path(__file__).resolve().parent.parent / "payloads"
EXPOSED_PATHS = PAYLOAD_DIR / "exposed_paths.txt"

# ── API key patterns (regex) ───────────────────────────────────────────────────
API_KEY_PATTERNS: dict[str, re.Pattern] = {
    "AWS Access Key":      re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key":      re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    "Stripe Secret Key":   re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "Stripe Public Key":   re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
    "OpenAI API Key":      re.compile(r"sk-[a-zA-Z0-9]{32,}"),
    "GitHub Token":        re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "Google API Key":      re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Twilio Auth Token":   re.compile(r"SK[0-9a-fA-F]{32}"),
    "SendGrid API Key":    re.compile(r"SG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{43,}"),
    "JWT Secret Hint":     re.compile(r"(?i)(jwt|token|secret|signing)[_\-\s]*(key|secret)['\"\s]*[:=]['\"\s]*[a-zA-Z0-9_\-]{8,}"),
    "Generic Secret":      re.compile(r"(?i)(secret|password|passwd|api_key|apikey|auth_token)['\"\s]*[:=]['\"\s]*[a-zA-Z0-9_\-!@#$%]{8,}"),
}

# ── Required security headers ──────────────────────────────────────────────────
REQUIRED_HEADERS: list[dict] = [
    {
        "name":        "Strict-Transport-Security",
        "severity":    "HIGH",
        "description": "Missing HSTS — site can be downgraded to HTTP.",
        "recommend":   "max-age=31536000; includeSubDomains",
    },
    {
        "name":        "Content-Security-Policy",
        "severity":    "HIGH",
        "description": "Missing CSP — XSS attacks have no browser-level mitigation.",
        "recommend":   "default-src 'self'",
    },
    {
        "name":        "X-Frame-Options",
        "severity":    "MEDIUM",
        "description": "Missing X-Frame-Options — site may be embeddable in iframes (clickjacking).",
        "recommend":   "DENY or SAMEORIGIN",
    },
    {
        "name":        "X-Content-Type-Options",
        "severity":    "MEDIUM",
        "description": "Missing X-Content-Type-Options — MIME sniffing attacks possible.",
        "recommend":   "nosniff",
    },
    {
        "name":        "Referrer-Policy",
        "severity":    "LOW",
        "description": "Missing Referrer-Policy — sensitive URLs may leak via Referer header.",
        "recommend":   "strict-origin-when-cross-origin",
    },
    {
        "name":        "Permissions-Policy",
        "severity":    "LOW",
        "description": "Missing Permissions-Policy — browser features not explicitly restricted.",
        "recommend":   "camera=(), microphone=(), geolocation=()",
    },
    {
        "name":        "Cross-Origin-Opener-Policy",
        "severity":    "LOW",
        "description": "Missing COOP — cross-origin window attacks not mitigated.",
        "recommend":   "same-origin",
    },
]

# ── Headers that should NOT be present (info leakage) ─────────────────────────
LEAKY_HEADERS: list[dict] = [
    {
        "name":        "X-Powered-By",
        "severity":    "LOW",
        "description": "Exposes backend framework (e.g. Express, PHP).",
    },
    {
        "name":        "Server",
        "severity":    "LOW",
        "description": "Exposes web server software and version.",
    },
    {
        "name":        "X-AspNet-Version",
        "severity":    "MEDIUM",
        "description": "Exposes ASP.NET version number.",
    },
    {
        "name":        "X-AspNetMvc-Version",
        "severity":    "MEDIUM",
        "description": "Exposes ASP.NET MVC version number.",
    },
]


# ── Data containers ────────────────────────────────────────────────────────────

@dataclass
class HeaderFinding:
    test_type: str       # missing_header | leaky_header | cors | exposed_path | secret_leak
    severity: str
    detail: str
    evidence: str = ""


@dataclass
class HeadersAuditResult:
    findings: list[HeaderFinding] = field(default_factory=list)
    headers_checked: int          = 0
    paths_checked: int            = 0
    exposed_paths: list[str]      = field(default_factory=list)
    secrets_found: list[str]      = field(default_factory=list)


# ── Auditor ────────────────────────────────────────────────────────────────────

class HeadersAuditor:
    """
    Audits a target for:
      1. Missing security headers
      2. Leaky informational headers
      3. CORS misconfiguration
      4. Exposed sensitive paths (.env, config files, etc.)
      5. API key / secret leakage in exposed files
    """

    DEFAULT_HEADERS: dict[str, str] = {
        "User-Agent": "vibecheck-auditor/0.1 (security audit; read-only)",
    }

    def __init__(
        self,
        target_url: str,
        timeout: int = 10,
    ) -> None:
        self.target_url = target_url.rstrip("/")
        self.timeout    = timeout

        self._session = requests.Session()
        self._session.headers.update(self.DEFAULT_HEADERS)
        self._exposed_paths = self._load_paths()

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self) -> HeadersAuditResult:
        result = HeadersAuditResult()

        console.print(
            f"\n  [bold cyan][[/bold cyan]headers_audit[bold cyan]][/bold cyan]"
            f"  Auditing [bold yellow]{self.target_url}[/bold yellow]\n"
        )

        # ── Fetch root response ───────────────────────────────────────────────
        try:
            resp = self._session.get(
                self.target_url,
                timeout=self.timeout,
                allow_redirects=True,
            )
        except RequestException as exc:
            console.print(f"  [red]  ✗ Could not reach target: {exc}[/red]")
            return result

        # ── Run all checks ────────────────────────────────────────────────────
        self._check_security_headers(resp, result)
        self._check_leaky_headers(resp, result)
        self._check_cors(resp, result)
        self._check_exposed_paths(result)

        self._print_summary(result)
        return result

    # ── Check 1: Missing security headers ─────────────────────────────────────

    def _check_security_headers(
        self, resp: requests.Response, result: HeadersAuditResult
    ) -> None:
        console.print("  [dim]→ Checking security headers...[/dim]")
        present_headers = {k.lower(): v for k, v in resp.headers.items()}

        for rule in REQUIRED_HEADERS:
            result.headers_checked += 1
            if rule["name"].lower() not in present_headers:
                console.print(
                    f"  [bold red]  ⚠[/bold red] Missing  "
                    f"[bold white]{rule['name']}[/bold white]  "
                    f"[dim]{rule['description']}[/dim]"
                )
                result.findings.append(HeaderFinding(
                    test_type="missing_header",
                    severity=rule["severity"],
                    detail=f"Missing {rule['name']} — {rule['description']}",
                    evidence=f"Recommended: {rule['recommend']}",
                ))
            else:
                console.print(
                    f"  [green]  ✓[/green] [dim]{rule['name']}[/dim]"
                )

    # ── Check 2: Leaky headers ─────────────────────────────────────────────────

    def _check_leaky_headers(
        self, resp: requests.Response, result: HeadersAuditResult
    ) -> None:
        console.print("\n  [dim]→ Checking for leaky headers...[/dim]")
        present_headers = {k.lower(): v for k, v in resp.headers.items()}

        for rule in LEAKY_HEADERS:
            if rule["name"].lower() in present_headers:
                value = present_headers[rule["name"].lower()]
                console.print(
                    f"  [bold yellow]  ⚠[/bold yellow] Leaky header  "
                    f"[bold white]{rule['name']}[/bold white]: "
                    f"[yellow]{value}[/yellow]"
                )
                result.findings.append(HeaderFinding(
                    test_type="leaky_header",
                    severity=rule["severity"],
                    detail=f"{rule['name']} header present — {rule['description']}",
                    evidence=f"Value: {value}",
                ))
            else:
                console.print(
                    f"  [green]  ✓[/green] [dim]{rule['name']} not exposed[/dim]"
                )

    # ── Check 3: CORS misconfiguration ────────────────────────────────────────

    def _check_cors(
        self, resp: requests.Response, result: HeadersAuditResult
    ) -> None:
        console.print("\n  [dim]→ Checking CORS configuration...[/dim]")

        try:
            cors_resp = self._session.get(
                self.target_url,
                timeout=self.timeout,
                headers={
                    **self.DEFAULT_HEADERS,
                    "Origin": "https://evil.vibecheck.test",
                },
                allow_redirects=True,
            )
        except RequestException:
            return

        acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
        acac = cors_resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            console.print(
                "  [bold red]  ⚠ CORS wildcard[/bold red]  "
                "Access-Control-Allow-Origin: *"
            )
            result.findings.append(HeaderFinding(
                test_type="cors",
                severity="MEDIUM",
                detail="CORS wildcard — any origin can read responses.",
                evidence="Access-Control-Allow-Origin: *",
            ))
        elif "evil.vibecheck.test" in acao:
            severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
            console.print(
                f"  [bold red]  ⚠ CORS reflects arbitrary origin[/bold red]  "
                f"[dim]credentials={'yes' if acac.lower() == 'true' else 'no'}[/dim]"
            )
            result.findings.append(HeaderFinding(
                test_type="cors",
                severity=severity,
                detail="CORS reflects arbitrary Origin header"
                       + (" with credentials — auth bypass possible." if acac.lower() == "true"
                          else "."),
                evidence=f"ACAO: {acao}  |  ACAC: {acac or 'not set'}",
            ))
        else:
            console.print(
                f"  [green]  ✓[/green] [dim]CORS not misconfigured  "
                f"(ACAO: {acao or 'not set'})[/dim]"
            )

    # ── Check 4: Exposed sensitive paths ──────────────────────────────────────

    def _check_exposed_paths(self, result: HeadersAuditResult) -> None:
        console.print(
            f"\n  [dim]→ Probing {len(self._exposed_paths)} sensitive paths...[/dim]"
        )

        for path in self._exposed_paths:
            url = urljoin(self.target_url + "/", path.lstrip("/"))
            result.paths_checked += 1

            try:
                resp = self._session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            except RequestException:
                continue

            if resp.status_code == 200:
                console.print(
                    f"  [bold red]  ⚠ EXPOSED[/bold red]  "
                    f"[bold yellow]{url}[/bold yellow]  "
                    f"[dim](HTTP 200  {len(resp.content)} bytes)[/dim]"
                )
                result.exposed_paths.append(url)

                # Scan contents for secrets
                secrets = self._scan_for_secrets(resp.text, url)
                result.secrets_found.extend(secrets)

                severity = "CRITICAL" if secrets else "HIGH"
                result.findings.append(HeaderFinding(
                    test_type="exposed_path",
                    severity=severity,
                    detail=f"Sensitive file publicly accessible: {path}",
                    evidence=f"HTTP 200  |  {len(resp.content)} bytes"
                             + (f"  |  Secrets: {', '.join(secrets)}" if secrets else ""),
                ))

    # ── Secret scanner ─────────────────────────────────────────────────────────

    def _scan_for_secrets(self, body: str, source: str) -> list[str]:
        found: list[str] = []
        for key_type, pattern in API_KEY_PATTERNS.items():
            if pattern.search(body):
                console.print(
                    f"    [bold red]  ⚠ SECRET DETECTED[/bold red]  "
                    f"[bold white]{key_type}[/bold white]  "
                    f"[dim]in {source}[/dim]"
                )
                found.append(key_type)
        return found

    # ── Path loader ────────────────────────────────────────────────────────────

    def _load_paths(self) -> list[str]:
        if not EXPOSED_PATHS.exists():
            console.print(
                f"  [yellow]  ⚠[/yellow] Path list not found at "
                f"[dim]{EXPOSED_PATHS}[/dim] — using built-in defaults"
            )
            return ["/.env", "/.git/config", "/config.json", "/package.json"]

        paths = []
        with EXPOSED_PATHS.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    paths.append(stripped)
        return paths

    # ── Rich output ────────────────────────────────────────────────────────────

    def _print_summary(self, result: HeadersAuditResult) -> None:
        console.print()

        if not result.findings:
            console.print(
                "  [bold green]✓[/bold green] "
                "[green]No header or path vulnerabilities detected.[/green]\n"
            )
            return

        table = Table(
            title="Headers & Exposure Findings",
            box=box.SIMPLE_HEAVY,
            border_style="magenta",
            show_lines=True,
        )
        table.add_column("Severity",  style="bold",     width=10)
        table.add_column("Type",      style="cyan",     width=16)
        table.add_column("Detail",    style="white",    no_wrap=False)
        table.add_column("Evidence",  style="dim",      no_wrap=False)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            result.findings,
            key=lambda f: severity_order.get(f.severity, 9)
        )

        for f in sorted_findings:
            color = {
                "CRITICAL": "bold red",
                "HIGH":     "red",
                "MEDIUM":   "yellow",
                "LOW":      "dim white",
            }.get(f.severity, "white")
            table.add_row(
                f"[{color}]{f.severity}[/{color}]",
                f.test_type,
                f.detail,
                f.evidence,
            )

        console.print(table)

        critical = sum(1 for f in result.findings if f.severity == "CRITICAL")
        high     = sum(1 for f in result.findings if f.severity == "HIGH")
        medium   = sum(1 for f in result.findings if f.severity == "MEDIUM")

        color  = "bold red" if (critical + high) > 0 else "bold yellow" if medium > 0 else "bold green"
        symbol = "⚠" if (critical + high + medium) > 0 else "✓"

        console.print(
            f"  [{color}]{symbol} Headers Audit complete[/{color}] —"
            f"  [bold]{result.headers_checked}[/bold] headers checked,"
            f"  [bold]{result.paths_checked}[/bold] paths probed,"
            f"  [bold red]{critical}[/bold red] CRITICAL,"
            f"  [bold red]{high}[/bold red] HIGH,"
            f"  [bold]{len(result.findings)}[/bold] total finding(s)\n"
        )