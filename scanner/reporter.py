from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box

console = Console()

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "reports"


# ── Data containers ────────────────────────────────────────────────────────────

@dataclass
class ReportFinding:
    module: str
    severity: str
    finding_type: str
    detail: str
    evidence: str = ""
    url: str = ""


@dataclass
class AuditReport:
    target_url: str
    timestamp: str
    findings: list[ReportFinding]  = field(default_factory=list)
    modules_run: list[str]         = field(default_factory=list)
    stats: dict[str, int]          = field(default_factory=dict)


# ── Reporter ───────────────────────────────────────────────────────────────────

class Reporter:
    """
    Collects findings from all modules and:
      1. Prints a full styled report to the terminal
      2. Offers optional export to PDF, JSON, or TXT
    """

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    SEVERITY_COLORS = {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "dim white",
        "INFO":     "dim",
    }

    def __init__(self, target_url: str) -> None:
        self.target_url = target_url
        self.timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.report     = AuditReport(
            target_url=target_url,
            timestamp=self.timestamp,
        )

    # ── Ingestion API ──────────────────────────────────────────────────────────

    def ingest_spider(self, result) -> None:
        self.report.modules_run.append("core_spider")
        self.report.stats["pages_crawled"] = len(result.pages_visited)
        self.report.stats["forms_found"]   = len(result.forms)
        for url, reason in result.errors:
            self.report.findings.append(ReportFinding(
                module="core_spider",
                severity="INFO",
                finding_type="crawl_error",
                detail=reason,
                url=url,
            ))

    def ingest_jwt(self, result) -> None:
        self.report.modules_run.append("jwt_crack")
        self.report.stats["jwt_tokens_found"]   = result.tokens_found
        self.report.stats["jwt_tokens_cracked"] = result.tokens_cracked
        for f in result.findings:
            if f.cracked_secret:
                self.report.findings.append(ReportFinding(
                    module="jwt_crack",
                    severity="CRITICAL",
                    finding_type="weak_jwt_secret",
                    detail=f"JWT signed with weak secret: {f.cracked_secret!r}",
                    evidence=f"Location: {f.location}  |  Algorithm: {f.algorithm}",
                    url=self.target_url,
                ))
            if f.alg_none_accepted:
                self.report.findings.append(ReportFinding(
                    module="jwt_crack",
                    severity="CRITICAL",
                    finding_type="alg_none_accepted",
                    detail="Server accepts unsigned JWT tokens (alg:none)",
                    evidence=f"Location: {f.location}",
                    url=self.target_url,
                ))
            if f.expired_accepted:
                self.report.findings.append(ReportFinding(
                    module="jwt_crack",
                    severity="HIGH",
                    finding_type="expired_token_accepted",
                    detail="Server accepts expired JWT tokens",
                    evidence=f"Location: {f.location}",
                    url=self.target_url,
                ))

    def ingest_abuse(self, result) -> None:
        self.report.modules_run.append("abuse_test")
        self.report.stats["abuse_endpoints_tested"] = result.endpoints_tested
        for f in result.findings:
            self.report.findings.append(ReportFinding(
                module="abuse_test",
                severity=f.severity,
                finding_type=f.test_type,
                detail=f.detail,
                evidence=f.evidence,
                url=f.endpoint,
            ))

    def ingest_headers(self, result) -> None:
        self.report.modules_run.append("headers_audit")
        self.report.stats["paths_probed"]  = result.paths_checked
        self.report.stats["exposed_paths"] = len(result.exposed_paths)
        for f in result.findings:
            self.report.findings.append(ReportFinding(
                module="headers_audit",
                severity=f.severity,
                finding_type=f.test_type,
                detail=f.detail,
                evidence=f.evidence,
                url=self.target_url,
            ))

    def ingest_secrets(self, result) -> None:
        self.report.modules_run.append("secret_scan")
        self.report.stats["secrets_found"] = result.secrets_found
        self.report.stats["js_bundles"]    = result.js_bundles_scanned
        for f in result.findings:
            self.report.findings.append(ReportFinding(
                module="secret_scan",
                severity=f.severity,
                finding_type=f.finding_type,
                detail=f"{f.secret_kind} detected",
                evidence=f.evidence,
                url=f.source_url,
            ))

    def ingest_injection(self, result) -> None:
        self.report.modules_run.append("injection_surface")
        self.report.stats["injection_params_tested"] = result.params_tested
        for f in result.findings:
            self.report.findings.append(ReportFinding(
                module="injection_surface",
                severity=f.severity,
                finding_type=f.injection_type,
                detail=f.detail,
                evidence=f.evidence,
                url=f.url,
            ))

    # ── Finalize ───────────────────────────────────────────────────────────────

    def finalize(self) -> None:
        """Print full terminal report, then offer export options."""
        self._print_full_report()
        self._prompt_export()

    # ── Terminal report ────────────────────────────────────────────────────────

    def _print_full_report(self) -> None:
        sorted_findings = sorted(
            self.report.findings,
            key=lambda f: self.SEVERITY_ORDER.get(f.severity, 9),
        )

        counts = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.report.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        # ── Header panel ──────────────────────────────────────────────────────
        console.print()
        console.print(Panel(
            f"[bold yellow]{self.report.target_url}[/bold yellow]\n"
            f"[dim]{self.report.timestamp}[/dim]\n"
            f"[dim]Modules: {', '.join(self.report.modules_run)}[/dim]",
            title="[bold cyan]VIBECHECK AUDIT REPORT[/bold cyan]",
            border_style="cyan",
            padding=(1, 4),
        ))

        # ── Severity scorecard ────────────────────────────────────────────────
        console.print()
        score_table = Table(
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold white",
            border_style="cyan",
            padding=(0, 3),
        )
        score_table.add_column("CRITICAL", style="bold red",    justify="center")
        score_table.add_column("HIGH",     style="red",         justify="center")
        score_table.add_column("MEDIUM",   style="yellow",      justify="center")
        score_table.add_column("LOW",      style="dim white",   justify="center")
        score_table.add_column("INFO",     style="dim",         justify="center")
        score_table.add_row(
            str(counts["CRITICAL"]),
            str(counts["HIGH"]),
            str(counts["MEDIUM"]),
            str(counts["LOW"]),
            str(counts["INFO"]),
        )
        console.print(score_table)

        # ── Stats table ───────────────────────────────────────────────────────
        if self.report.stats:
            console.print("\n  [bold cyan]Scan Statistics[/bold cyan]")
            stats_table = Table(
                box=box.SIMPLE,
                show_header=False,
                padding=(0, 2),
            )
            stats_table.add_column(style="dim",        width=30)
            stats_table.add_column(style="bold white")
            for k, v in self.report.stats.items():
                stats_table.add_row(k.replace("_", " ").title(), str(v))
            console.print(stats_table)

        # ── Per-module findings ───────────────────────────────────────────────
        modules_in_report = list(dict.fromkeys(f.module for f in sorted_findings))

        for module in modules_in_report:
            module_findings = [f for f in sorted_findings if f.module == module]
            if not module_findings:
                continue

            console.print(
                f"\n  [bold cyan][[/bold cyan]{module}"
                f"[bold cyan]][/bold cyan]"
                f"  [dim]{len(module_findings)} finding(s)[/dim]"
            )

            mod_table = Table(
                box=box.SIMPLE_HEAVY,
                show_lines=True,
                border_style="dim",
                padding=(0, 1),
            )
            mod_table.add_column("Severity",  width=10)
            mod_table.add_column("Type",      width=22, style="cyan")
            mod_table.add_column("Detail",    no_wrap=False)
            mod_table.add_column("URL",       style="dim yellow", no_wrap=False)

            for f in module_findings:
                color = self.SEVERITY_COLORS.get(f.severity, "white")
                mod_table.add_row(
                    f"[{color}]{f.severity}[/{color}]",
                    f.finding_type,
                    f.detail,
                    f.url,
                )

            console.print(mod_table)

            # Print evidence lines under the table
            for f in module_findings:
                if f.evidence:
                    console.print(
                        f"    [dim]↳ {f.evidence}[/dim]"
                    )

        if not sorted_findings:
            console.print(
                "\n  [bold green]✓ No findings — target looks clean.[/bold green]"
            )

        console.print()

    # ── Export prompt ──────────────────────────────────────────────────────────

    def _prompt_export(self) -> None:
        console.print(
            Panel(
                "[bold white]Export Report[/bold white]\n\n"
                "  [bold cyan]1[/bold cyan]  JSON  — machine-readable, pipe into other tools\n"
                "  [bold cyan]2[/bold cyan]  TXT   — plain text, shareable anywhere\n"
                "  [bold cyan]3[/bold cyan]  PDF   — requires [dim]reportlab[/dim] "
                           "[dim](pip install reportlab)[/dim]\n"
                "  [bold cyan]4[/bold cyan]  Skip  — no export",
                border_style="dim",
                padding=(1, 4),
            )
        )

        choice = Prompt.ask(
            "  [bold cyan]Export as[/bold cyan]",
            choices=["1", "2", "3", "4"],
            default="4",
        )

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        slug = (
            self.target_url
            .replace("https://", "")
            .replace("http://", "")
            .replace("/", "_")
            .strip("_")
        )
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = f"vibecheck_{slug}_{ts}"

        if choice == "1":
            path = self._write_json(stem)
            console.print(f"\n  [bold green]✓[/bold green] JSON saved → [cyan]{path}[/cyan]\n")
        elif choice == "2":
            path = self._write_txt(stem)
            console.print(f"\n  [bold green]✓[/bold green] TXT saved  → [cyan]{path}[/cyan]\n")
        elif choice == "3":
            path = self._write_pdf(stem)
            if path:
                console.print(f"\n  [bold green]✓[/bold green] PDF saved  → [cyan]{path}[/cyan]\n")
        else:
            console.print("\n  [dim]Export skipped.[/dim]\n")

    # ── JSON export ────────────────────────────────────────────────────────────

    def _write_json(self, stem: str) -> Path:
        path = OUTPUT_DIR / f"{stem}.json"
        counts = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.report.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        data = {
            "target_url":  self.report.target_url,
            "timestamp":   self.report.timestamp,
            "modules_run": self.report.modules_run,
            "stats":       self.report.stats,
            "summary":     counts,
            "findings": [
                {
                    "module":       f.module,
                    "severity":     f.severity,
                    "finding_type": f.finding_type,
                    "detail":       f.detail,
                    "evidence":     f.evidence,
                    "url":          f.url,
                }
                for f in sorted(
                    self.report.findings,
                    key=lambda x: self.SEVERITY_ORDER.get(x.severity, 9),
                )
            ],
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    # ── TXT export ─────────────────────────────────────────────────────────────

    def _write_txt(self, stem: str) -> Path:
        path  = OUTPUT_DIR / f"{stem}.txt"
        lines = []

        lines.append("=" * 70)
        lines.append("  VIBECHECK AUDIT REPORT")
        lines.append("=" * 70)
        lines.append(f"  Target    : {self.report.target_url}")
        lines.append(f"  Timestamp : {self.report.timestamp}")
        lines.append(f"  Modules   : {', '.join(self.report.modules_run)}")
        lines.append("")

        counts = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.report.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        lines.append("  SEVERITY SUMMARY")
        lines.append("  " + "─" * 40)
        for sev, count in counts.items():
            lines.append(f"  {sev:<12} {count}")
        lines.append("")

        lines.append("  STATISTICS")
        lines.append("  " + "─" * 40)
        for k, v in self.report.stats.items():
            lines.append(f"  {k.replace('_',' ').title():<30} {v}")
        lines.append("")

        sorted_findings = sorted(
            self.report.findings,
            key=lambda f: self.SEVERITY_ORDER.get(f.severity, 9),
        )

        lines.append("  FINDINGS")
        lines.append("  " + "─" * 40)
        for i, f in enumerate(sorted_findings, 1):
            lines.append(f"\n  [{i}] {f.severity}  —  {f.module}  —  {f.finding_type}")
            lines.append(f"      Detail   : {f.detail}")
            lines.append(f"      URL      : {f.url}")
            if f.evidence:
                lines.append(f"      Evidence : {f.evidence}")

        lines.append("\n" + "=" * 70)
        lines.append("  Generated by VibeCheck — QA & Security Posture Auditor")
        lines.append("=" * 70)

        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    # ── PDF export ─────────────────────────────────────────────────────────────

    def _write_pdf(self, stem: str) -> Path | None:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import mm
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            )
        except ImportError:
            console.print(
                "\n  [bold red]✗[/bold red] reportlab is not installed.\n"
                "  Run: [bold cyan]pip install reportlab[/bold cyan]\n"
            )
            return None

        path = OUTPUT_DIR / f"{stem}.pdf"
        doc  = SimpleDocTemplate(
            str(path),
            pagesize=A4,
            leftMargin=20*mm, rightMargin=20*mm,
            topMargin=20*mm,  bottomMargin=20*mm,
        )

        styles  = getSampleStyleSheet()
        title_s = ParagraphStyle("title", fontSize=18, textColor=colors.HexColor("#21d4fd"),
                                 spaceAfter=6)
        head_s  = ParagraphStyle("head",  fontSize=11, textColor=colors.HexColor("#21d4fd"),
                                 spaceBefore=12, spaceAfter=4)
        body_s  = ParagraphStyle("body",  fontSize=8,  textColor=colors.HexColor("#e6edf3"),
                                 spaceAfter=2)
        dim_s   = ParagraphStyle("dim",   fontSize=7,  textColor=colors.HexColor("#8b949e"),
                                 spaceAfter=2)

        SEV_COLORS = {
            "CRITICAL": colors.HexColor("#ff4444"),
            "HIGH":     colors.HexColor("#ff8800"),
            "MEDIUM":   colors.HexColor("#ffcc00"),
            "LOW":      colors.HexColor("#aaaaaa"),
            "INFO":     colors.HexColor("#888888"),
        }

        story = []

        # Title
        story.append(Paragraph("VibeCheck Audit Report", title_s))
        story.append(Paragraph(f"Target: {self.report.target_url}", body_s))
        story.append(Paragraph(f"Date: {self.report.timestamp}", dim_s))
        story.append(Paragraph(
            f"Modules: {', '.join(self.report.modules_run)}", dim_s
        ))
        story.append(Spacer(1, 6*mm))

        # Severity summary table
        counts = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.report.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        story.append(Paragraph("Severity Summary", head_s))
        sev_data = [["Severity", "Count"]] + [
            [s, str(c)] for s, c in counts.items()
        ]
        sev_table = Table(sev_data, colWidths=[60*mm, 30*mm])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#21262d")),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.HexColor("#8b949e")),
            ("FONTSIZE",    (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#161b22"), colors.HexColor("#1c2128")]),
            ("TEXTCOLOR",   (0, 1), (-1, -1), colors.HexColor("#e6edf3")),
            ("GRID",        (0, 0), (-1, -1), 0.25, colors.HexColor("#30363d")),
            ("LEFTPADDING",  (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 6*mm))

        # Findings table
        story.append(Paragraph("Findings", head_s))
        sorted_findings = sorted(
            self.report.findings,
            key=lambda f: self.SEVERITY_ORDER.get(f.severity, 9),
        )

        find_data = [["Severity", "Module", "Type", "Detail", "URL"]]
        for f in sorted_findings:
            find_data.append([
                f.severity,
                f.module,
                f.finding_type,
                f.detail[:80] + ("…" if len(f.detail) > 80 else ""),
                f.url[:50] + ("…" if len(f.url) > 50 else ""),
            ])

        find_table = Table(
            find_data,
            colWidths=[22*mm, 28*mm, 30*mm, 60*mm, 30*mm],
            repeatRows=1,
        )
        row_styles = [
            ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#21262d")),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.HexColor("#8b949e")),
            ("FONTSIZE",     (0, 0), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#161b22"), colors.HexColor("#1c2128")]),
            ("TEXTCOLOR",    (0, 1), (-1, -1), colors.HexColor("#e6edf3")),
            ("GRID",         (0, 0), (-1, -1), 0.25, colors.HexColor("#30363d")),
            ("LEFTPADDING",  (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING",   (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
            ("WORDWRAP",     (0, 0), (-1, -1), True),
        ]
        for i, f in enumerate(sorted_findings, 1):
            sev_color = SEV_COLORS.get(f.severity, colors.HexColor("#888888"))
            row_styles.append(("TEXTCOLOR", (0, i), (0, i), sev_color))

        find_table.setStyle(TableStyle(row_styles))
        story.append(find_table)

        doc.build(story)
        return path