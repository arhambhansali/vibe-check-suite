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
PAYLOAD_DIR      = Path(__file__).resolve().parent.parent / "payloads"
PATTERN_FILE     = PAYLOAD_DIR / "secret_patterns.txt"

# ── Hardcoded patterns (fallback + extras not in file) ────────────────────────
BUILTIN_PATTERNS: dict[str, re.Pattern] = {
    "AWS Access Key":     re.compile(r"AKIA[0-9A-Z]{16}"),
    "Stripe Secret":      re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "Stripe Public":      re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
    "OpenAI Key":         re.compile(r"sk-[a-zA-Z0-9]{32,}"),
    "GitHub Token":       re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "Google API Key":     re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "SendGrid Key":       re.compile(r"SG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{43,}"),
    "Private Key Block":  re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "Bearer Token":       re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-_]{20,}"),
    "Generic Secret":     re.compile(
        r'(?i)(secret|password|api_key|apikey|auth_token|access_token)'
        r'["\s]*[:=]["\s]*[a-zA-Z0-9_\-!@#$%^&*]{8,}'
    ),
    "Hardcoded JWT":      re.compile(
        r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    ),
}

# ── Insecure storage patterns ──────────────────────────────────────────────────
STORAGE_PATTERNS: dict[str, re.Pattern] = {
    "localStorage token storage":    re.compile(
        r'localStorage\.setItem\s*\(\s*["\'][^"\']*(?:token|jwt|auth|key|secret)[^"\']*["\']',
        re.IGNORECASE,
    ),
    "sessionStorage token storage":  re.compile(
        r'sessionStorage\.setItem\s*\(\s*["\'][^"\']*(?:token|jwt|auth|key|secret)[^"\']*["\']',
        re.IGNORECASE,
    ),
    "document.cookie token write":   re.compile(
        r'document\.cookie\s*=.*(?:token|jwt|auth)',
        re.IGNORECASE,
    ),
}

# ── JS bundle link patterns ────────────────────────────────────────────────────
JS_LINK_RE = re.compile(
    r'(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
    re.IGNORECASE,
)


# ── Data containers ────────────────────────────────────────────────────────────

@dataclass
class SecretFinding:
    source_url: str
    finding_type: str     # secret | insecure_storage | env_var_hint
    secret_kind: str      # e.g. "OpenAI Key", "localStorage token storage"
    severity: str
    evidence: str         # redacted snippet


@dataclass
class SecretScanResult:
    findings: list[SecretFinding]  = field(default_factory=list)
    urls_scanned: int              = 0
    js_bundles_scanned: int        = 0
    secrets_found: int             = 0
    storage_issues: int            = 0


# ── Scanner ────────────────────────────────────────────────────────────────────

class SecretScanner:
    """
    Scans page HTML and JavaScript bundles for:
      1. Hardcoded API keys and secrets
      2. Insecure token storage (localStorage / sessionStorage)
      3. Environment variable hints left in frontend code
    """

    DEFAULT_HEADERS: dict[str, str] = {
        "User-Agent": "vibecheck-auditor/0.1 (security audit; read-only)",
    }

    def __init__(
        self,
        target_url: str,
        pages: list[str] | None = None,
        timeout: int = 10,
    ) -> None:
        self.target_url = target_url.rstrip("/")
        self.pages      = pages or [target_url]
        self.timeout    = timeout

        self._session = requests.Session()
        self._session.headers.update(self.DEFAULT_HEADERS)
        self._patterns = self._load_patterns()

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self) -> SecretScanResult:
        result = SecretScanResult()

        console.print(
            f"\n  [bold cyan][[/bold cyan]secret_scan[bold cyan]][/bold cyan]"
            f"  Scanning [bold yellow]{self.target_url}[/bold yellow]"
            f"  [dim]({len(self.pages)} page(s))[/dim]\n"
        )

        js_urls: set[str] = set()

        for page_url in self.pages:
            result.urls_scanned += 1
            console.print(f"  [dim]Scanning:[/dim]  [white]{page_url}[/white]")

            try:
                resp = self._session.get(
                    page_url, timeout=self.timeout, allow_redirects=True
                )
            except RequestException as exc:
                console.print(f"  [red]  ✗[/red] [dim]{exc}[/dim]")
                continue

            # Scan HTML body directly
            findings = self._scan_body(resp.text, page_url, is_js=False)
            result.findings.extend(findings)

            # Collect JS bundle URLs
            for match in JS_LINK_RE.finditer(resp.text):
                href = match.group(1)
                absolute = urljoin(page_url, href)
                if urlparse(absolute).netloc == urlparse(self.target_url).netloc:
                    js_urls.add(absolute)

        # Scan all discovered JS bundles
        if js_urls:
            console.print(
                f"\n  [dim]→ Scanning {len(js_urls)} JS bundle(s)...[/dim]"
            )
            for js_url in sorted(js_urls):
                result.js_bundles_scanned += 1
                console.print(f"  [dim]  bundle:[/dim]  [white]{js_url}[/white]")
                try:
                    resp = self._session.get(
                        js_url, timeout=self.timeout, allow_redirects=True
                    )
                    findings = self._scan_body(resp.text, js_url, is_js=True)
                    result.findings.extend(findings)
                except RequestException as exc:
                    console.print(f"  [red]  ✗[/red] [dim]{exc}[/dim]")

        # Tally
        result.secrets_found  = sum(
            1 for f in result.findings if f.finding_type == "secret"
        )
        result.storage_issues = sum(
            1 for f in result.findings if f.finding_type == "insecure_storage"
        )

        self._print_summary(result)
        return result

    # ── Body scanner ───────────────────────────────────────────────────────────

    def _scan_body(
        self, body: str, source_url: str, is_js: bool
    ) -> list[SecretFinding]:
        findings: list[SecretFinding] = []
        seen: set[str] = set()

        # ── Secret patterns ───────────────────────────────────────────────────
        for kind, pattern in self._patterns.items():
            for match in pattern.finditer(body):
                snippet = self._redact(match.group())
                dedup_key = f"{kind}:{source_url}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                severity = self._severity_for(kind)
                console.print(
                    f"  [bold red]  ⚠ SECRET[/bold red]  "
                    f"[bold white]{kind}[/bold white]  "
                    f"[dim]{snippet}[/dim]"
                )
                findings.append(SecretFinding(
                    source_url=source_url,
                    finding_type="secret",
                    secret_kind=kind,
                    severity=severity,
                    evidence=snippet,
                ))

        # ── Insecure storage (JS only) ────────────────────────────────────────
        if is_js:
            for kind, pattern in STORAGE_PATTERNS.items():
                for match in pattern.finditer(body):
                    snippet = self._redact(match.group())
                    dedup_key = f"{kind}:{source_url}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    console.print(
                        f"  [bold yellow]  ⚠ INSECURE STORAGE[/bold yellow]  "
                        f"[bold white]{kind}[/bold white]  "
                        f"[dim]{snippet}[/dim]"
                    )
                    findings.append(SecretFinding(
                        source_url=source_url,
                        finding_type="insecure_storage",
                        secret_kind=kind,
                        severity="MEDIUM",
                        evidence=snippet,
                    ))

            # ── ENV var hints left in bundles ─────────────────────────────────
            env_pattern = re.compile(
                r'(?i)(?:process\.env\.|import\.meta\.env\.)'
                r'([A-Z_]{4,}(?:KEY|SECRET|TOKEN|PASSWORD|PASS|PWD|API))',
            )
            for match in env_pattern.finditer(body):
                var_name = match.group(1)
                dedup_key = f"env:{var_name}:{source_url}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                console.print(
                    f"  [bold yellow]  ⚠ ENV HINT[/bold yellow]  "
                    f"[white]{match.group()}[/white]  "
                    f"[dim]verify this is not inlined at build time[/dim]"
                )
                findings.append(SecretFinding(
                    source_url=source_url,
                    finding_type="env_var_hint",
                    secret_kind=f"ENV: {var_name}",
                    severity="LOW",
                    evidence=match.group(),
                ))

        return findings

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _redact(self, raw: str) -> str:
        """Show first 6 and last 4 chars, mask the middle."""
        raw = raw.strip()
        if len(raw) <= 12:
            return raw[:3] + "***"
        return raw[:6] + "..." + raw[-4:]

    def _severity_for(self, kind: str) -> str:
        critical = {"AWS Access Key", "Stripe Secret", "OpenAI Key",
                    "GitHub Token", "Private Key Block", "SendGrid Key"}
        high     = {"Google API Key", "Bearer Token", "Hardcoded JWT"}
        if kind in critical:
            return "CRITICAL"
        if kind in high:
            return "HIGH"
        return "MEDIUM"

    def _load_patterns(self) -> dict[str, re.Pattern]:
        """Load builtin patterns — file patterns are for documentation only."""
        return BUILTIN_PATTERNS

    # ── Rich output ────────────────────────────────────────────────────────────

    def _print_summary(self, result: SecretScanResult) -> None:
        console.print()

        if not result.findings:
            console.print(
                "  [bold green]✓[/bold green] "
                "[green]No secrets or insecure storage detected.[/green]\n"
            )
            return

        table = Table(
            title="Secret Scan Findings",
            box=box.SIMPLE_HEAVY,
            border_style="red",
            show_lines=True,
        )
        table.add_column("Severity",     style="bold",   width=10)
        table.add_column("Type",         style="cyan",   width=18)
        table.add_column("Kind",         style="white",  width=22)
        table.add_column("Source",       style="yellow", no_wrap=False)
        table.add_column("Evidence",     style="dim",    no_wrap=False)

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
                f.finding_type,
                f.secret_kind,
                f.source_url,
                f.evidence,
            )

        console.print(table)

        critical = sum(1 for f in result.findings if f.severity == "CRITICAL")
        high     = sum(1 for f in result.findings if f.severity == "HIGH")
        color    = "bold red" if (critical + high) > 0 else "bold yellow"
        symbol   = "⚠" if result.findings else "✓"

        console.print(
            f"  [{color}]{symbol} Secret Scan complete[/{color}] —"
            f"  [bold]{result.urls_scanned}[/bold] page(s),"
            f"  [bold]{result.js_bundles_scanned}[/bold] JS bundle(s),"
            f"  [bold red]{critical}[/bold red] CRITICAL,"
            f"  [bold red]{high}[/bold red] HIGH,"
            f"  [bold]{len(result.findings)}[/bold] total finding(s)\n"
        )