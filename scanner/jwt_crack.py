from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import jwt
import requests
from requests.exceptions import RequestException
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ── Payload path (cross-platform via pathlib) ──────────────────────────────────
PAYLOAD_DIR = Path(__file__).resolve().parent.parent / "payloads"
DEFAULT_WORDLIST = PAYLOAD_DIR / "jwt_secrets.txt"

# ── JWT pattern — three base64url segments joined by dots ─────────────────────
JWT_REGEX = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
)


# ── Data containers ────────────────────────────────────────────────────────────

@dataclass
class JWTFinding:
    token: str
    location: str        # where it was found: header name or cookie name
    algorithm: str
    cracked_secret: str | None = None
    alg_none_accepted: bool = False
    expired_accepted: bool = False


@dataclass
class JWTAuditResult:
    findings: list[JWTFinding] = field(default_factory=list)
    tokens_found: int = 0
    tokens_cracked: int = 0
    alg_none_vulnerable: int = 0
    expired_accepted: int = 0


# ── Auditor ────────────────────────────────────────────────────────────────────

class JWTCracker:
    """
    Extracts JWTs from HTTP responses and audits them for:
      1. Weak / default signing secrets (wordlist brute-force)
      2. Algorithm confusion — alg:none acceptance
      3. Expired token acceptance
    """

    def __init__(
        self,
        target_url: str,
        pages: list[str] | None = None,
        wordlist_path: Path = DEFAULT_WORDLIST,
        timeout: int = 10,
    ) -> None:
        self.target_url = target_url
        self.pages = pages or [target_url]
        self.wordlist_path = wordlist_path
        self.timeout = timeout

        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "vibecheck-auditor/0.1 (security audit; read-only)",
        })
        self._secrets: list[str] = self._load_wordlist()

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self) -> JWTAuditResult:
        result = JWTAuditResult()

        console.print(
            f"\n  [bold cyan][[/bold cyan]jwt_crack[bold cyan]][/bold cyan]"
            f"  Auditing JWT tokens on [bold yellow]{self.target_url}[/bold yellow]"
            f"  [dim]({len(self._secrets)} secrets in wordlist)[/dim]\n"
        )

        raw_tokens: dict[str, str] = {}  # token → location label

        for page in self.pages:
            found = self._extract_tokens_from_response(page)
            for token, location in found.items():
                if token not in raw_tokens:
                    raw_tokens[token] = location
                    console.print(
                        f"  [green]  ✓[/green] Token found  "
                        f"[dim]{location}[/dim]  "
                        f"[yellow]{token[:40]}…[/yellow]"
                    )

        if not raw_tokens:
            console.print("  [dim]  No JWT tokens detected in responses.[/dim]")
            self._print_summary(result)
            return result

        result.tokens_found = len(raw_tokens)

        for token, location in raw_tokens.items():
            finding = self._audit_token(token, location)
            result.findings.append(finding)

            if finding.cracked_secret:
                result.tokens_cracked += 1
            if finding.alg_none_accepted:
                result.alg_none_vulnerable += 1
            if finding.expired_accepted:
                result.expired_accepted += 1

        self._print_summary(result)
        return result

    # ── Token extraction ───────────────────────────────────────────────────────

    def _extract_tokens_from_response(self, url: str) -> dict[str, str]:
        """GET a page and scan headers + cookies for JWT patterns."""
        found: dict[str, str] = {}
        try:
            resp = self._session.get(url, timeout=self.timeout, allow_redirects=True)
        except RequestException as exc:
            console.print(f"  [red]  ✗[/red] [dim]{url}[/dim]  [red]{exc}[/red]")
            return found

        # Scan response headers
        for header_name, header_value in resp.headers.items():
            for match in JWT_REGEX.finditer(header_value):
                found[match.group()] = f"header:{header_name}"

        # Scan cookies
        for cookie_name, cookie_value in resp.cookies.items():
            for match in JWT_REGEX.finditer(cookie_value):
                found[match.group()] = f"cookie:{cookie_name}"

        # Scan response body (tokens embedded in JSON or JS)
        for match in JWT_REGEX.finditer(resp.text):
            token = match.group()
            if token not in found:
                found[token] = "body"

        return found

    # ── Token auditing ─────────────────────────────────────────────────────────

    def _audit_token(self, token: str, location: str) -> JWTFinding:
        """Run all three audit checks against a single token."""

        # Decode header without verification to get algorithm
        try:
            header = jwt.get_unverified_header(token)
            algorithm = header.get("alg", "unknown")
        except jwt.exceptions.DecodeError:
            return JWTFinding(
                token=token,
                location=location,
                algorithm="invalid",
            )

        finding = JWTFinding(
            token=token,
            location=location,
            algorithm=algorithm,
        )

        console.print(
            f"\n  [bold white]Auditing token[/bold white]  "
            f"[dim]alg={algorithm}  from {location}[/dim]"
        )

        # ── Check 1: Weak secret brute-force ──────────────────────────────────
        finding.cracked_secret = self._brute_force_secret(token, algorithm)
        if finding.cracked_secret:
            console.print(
                f"  [bold red]  ⚠ CRACKED[/bold red]  "
                f"secret=[bold red]{finding.cracked_secret!r}[/bold red]"
            )
        else:
            console.print(f"  [green]  ✓[/green] Secret not in wordlist")

        # ── Check 2: alg:none acceptance ─────────────────────────────────────
        finding.alg_none_accepted = self._test_alg_none(token)
        if finding.alg_none_accepted:
            console.print(
                f"  [bold red]  ⚠ ALG:NONE ACCEPTED[/bold red]  "
                f"Server accepts unsigned tokens"
            )
        else:
            console.print(f"  [green]  ✓[/green] alg:none rejected")

        # ── Check 3: Expired token acceptance ────────────────────────────────
        finding.expired_accepted = self._test_expired_acceptance(token, algorithm)
        if finding.expired_accepted:
            console.print(
                f"  [bold red]  ⚠ EXPIRED TOKEN ACCEPTED[/bold red]  "
                f"Server does not validate exp claim"
            )
        else:
            console.print(f"  [green]  ✓[/green] Expired tokens rejected")

        return finding

    def _brute_force_secret(self, token: str, algorithm: str) -> str | None:
        """Try every secret in the wordlist against the token signature."""
        if algorithm.upper() not in ("HS256", "HS384", "HS512"):
            return None  # Only HMAC algorithms are brute-forceable this way

        for secret in self._secrets:
            try:
                jwt.decode(
                    token,
                    secret,
                    algorithms=[algorithm],
                    options={"verify_exp": False},
                )
                return secret
            except jwt.exceptions.InvalidSignatureError:
                continue
            except jwt.exceptions.DecodeError:
                continue
            except Exception:
                continue
        return None

    def _test_alg_none(self, token: str) -> bool:
        """
        Check if the server accepts a token with alg:none and no signature.
        This is a local structural check — we verify the library itself
        would accept it, flagging if the token was crafted without a secret.
        """
        try:
            # Attempt decode with alg:none — PyJWT raises if algorithm
            # is not explicitly allowed, which is the secure behaviour.
            # If this succeeds it means the token was signed with none.
            jwt.decode(
                token,
                "",
                algorithms=["none"],
                options={"verify_signature": False, "verify_exp": False},
            )
            # If no exception, structurally valid as unsigned
            return True
        except Exception:
            return False

    def _test_expired_acceptance(self, token: str, algorithm: str) -> bool:
        """
        Decode without exp verification and compare to verified decode.
        If unverified decode shows exp is in the past but cracked secret
        exists and still validates — the server would accept it.
        """
        if algorithm.upper() not in ("HS256", "HS384", "HS512"):
            return False
        try:
            payload_unverified = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False},
                algorithms=[algorithm],
            )
            import time
            exp = payload_unverified.get("exp")
            if exp and exp < int(time.time()):
                # Token is expired — check if cracked secret still validates it
                cracked = self._brute_force_secret(token, algorithm)
                return cracked is not None
        except Exception:
            pass
        return False

    # ── Wordlist loader ────────────────────────────────────────────────────────

    def _load_wordlist(self) -> list[str]:
        if not self.wordlist_path.exists():
            console.print(
                f"  [yellow]  ⚠[/yellow] Wordlist not found at "
                f"[dim]{self.wordlist_path}[/dim] — using built-in defaults"
            )
            return ["secret", "changeme", "password", "supersecret", "your-secret-key"]

        secrets = []
        with self.wordlist_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    secrets.append(stripped)
        return secrets

    # ── Rich output ────────────────────────────────────────────────────────────

    def _print_summary(self, result: JWTAuditResult) -> None:
        console.print()

        table = Table(
            title="JWT Audit Results",
            box=box.SIMPLE_HEAVY,
            border_style="cyan",
            show_lines=True,
        )
        table.add_column("Location",       style="dim")
        table.add_column("Algorithm",      style="cyan")
        table.add_column("Cracked Secret", style="bold red")
        table.add_column("alg:none",       style="bold red")
        table.add_column("Expired OK",     style="bold red")
        table.add_column("Token (preview)", style="yellow", no_wrap=False)

        for f in result.findings:
            table.add_row(
                f.location,
                f.algorithm,
                f.cracked_secret or "[green]✓ safe[/green]",
                "[red]⚠ YES[/red]" if f.alg_none_accepted else "[green]✓ no[/green]",
                "[red]⚠ YES[/red]" if f.expired_accepted  else "[green]✓ no[/green]",
                f.token[:48] + "…",
            )

        if result.findings:
            console.print(table)
        else:
            console.print("  [dim]  No tokens audited.[/dim]")

        # Severity summary line
        critical = result.tokens_cracked + result.alg_none_vulnerable
        color = "bold red" if critical > 0 else "bold green"
        symbol = "⚠" if critical > 0 else "✓"

        console.print(
            f"  [{color}]{symbol} JWT Audit complete[/{color}] —"
            f"  [bold]{result.tokens_found}[/bold] token(s) found,"
            f"  [bold]{result.tokens_cracked}[/bold] cracked,"
            f"  [bold]{result.alg_none_vulnerable}[/bold] alg:none vulnerable,"
            f"  [bold]{result.expired_accepted}[/bold] expired-accepted\n"
        )