"""Terminal reporter with ANSI color auto-detection and plain-text fallback."""

from __future__ import annotations

import os
import sys
from typing import List, Optional

from secureclaw.core.models import (
    Finding,
    PostureCheck,
    ScanResult,
    Severity,
    Triage,
)


def _supports_color() -> bool:
    """Detect if the terminal supports ANSI colors."""
    # Respect NO_COLOR convention (https://no-color.org)
    if os.environ.get("NO_COLOR"):
        return False
    # Respect FORCE_COLOR
    if os.environ.get("FORCE_COLOR"):
        return True
    # Check if stdout is a TTY
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    # Windows: check for modern terminal
    if os.name == "nt":
        return (
            os.environ.get("ANSICON") is not None
            or os.environ.get("WT_SESSION") is not None
            or "xterm" in os.environ.get("TERM", "").lower()
        )
    return True


class Colors:
    """ANSI color codes with auto-detection."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled and _supports_color()

    def _wrap(self, code: str, text: str) -> str:
        if self.enabled:
            return f"\033[{code}m{text}\033[0m"
        return text

    def red(self, text: str) -> str:
        return self._wrap("1;31", text)

    def yellow(self, text: str) -> str:
        return self._wrap("1;33", text)

    def blue(self, text: str) -> str:
        return self._wrap("1;34", text)

    def green(self, text: str) -> str:
        return self._wrap("1;32", text)

    def cyan(self, text: str) -> str:
        return self._wrap("1;36", text)

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)


def _severity_color(colors: Colors, severity: Severity, text: str) -> str:
    if severity == Severity.CRITICAL:
        return colors.red(text)
    if severity == Severity.HIGH:
        return colors.yellow(text)
    return colors.blue(text)


def format_terminal_report(result: ScanResult, use_color: Optional[bool] = None) -> str:
    """Format scan results for terminal output."""
    colors = Colors(enabled=use_color if use_color is not None else True)
    lines: List[str] = []

    # Header
    lines.append("")
    lines.append(colors.bold("SecureClaw Scan Report"))
    lines.append(colors.bold("=" * 60))
    lines.append(f"  Powered by Sparkry AI - Your Solo Founder's AI Advantage")
    lines.append("")

    # Executive Summary
    lines.append(colors.bold("SUMMARY"))
    lines.append("-" * 60)
    s = result.summary
    lines.append(f"  Files scanned:    {s.total_files_scanned:,}")
    lines.append(f"  Files skipped:    {s.total_files_skipped:,}")
    lines.append(f"  Patterns checked: {s.patterns_checked}")
    lines.append(f"  Scan duration:    {s.scan_duration_seconds:.1f}s")
    if result.allowlist_suppressions > 0:
        lines.append(f"  Allowlist suppressed: {result.allowlist_suppressions}")
    lines.append("")

    # Verdict
    if s.critical_count > 0:
        lines.append(colors.red(f"  {s.critical_count} CRITICAL  |  {s.high_count} HIGH  |  {s.advisory_count} ADVISORY"))
    elif s.high_count > 0:
        lines.append(colors.yellow(f"  {s.critical_count} CRITICAL  |  {s.high_count} HIGH  |  {s.advisory_count} ADVISORY"))
    elif s.advisory_count > 0:
        lines.append(colors.blue(f"  {s.critical_count} CRITICAL  |  {s.high_count} HIGH  |  {s.advisory_count} ADVISORY"))
    else:
        lines.append(colors.green("  No issues found!"))
    lines.append("")
    lines.append(f"  {result.verdict}")
    lines.append("")

    # Security Posture
    if result.posture_checks:
        lines.append(colors.bold("AI TOOL SECURITY POSTURE"))
        lines.append("-" * 60)
        for check in result.posture_checks:
            status_icon = {
                "secure": colors.green("[SECURE]"),
                "warning": colors.yellow("[WARNING]"),
                "insecure": colors.red("[INSECURE]"),
                "not_found": colors.dim("[NOT FOUND]"),
                "advisory": colors.cyan("[ADVISORY]"),
            }.get(check.status, f"[{check.status.upper()}]")
            lines.append(f"  {status_icon} {check.tool_name}: {check.check_name}")
            lines.append(f"           {check.description}")
            if check.recommendation:
                lines.append(f"           Recommendation: {check.recommendation}")
        lines.append("")

    # Findings by triage tier
    if result.findings:
        lines.append(colors.bold("FINDINGS"))
        lines.append("-" * 60)

        # Count by triage tier
        act_now = [f for f in result.findings if f.triage == Triage.ACT_NOW]
        review = [f for f in result.findings if f.triage == Triage.REVIEW]
        suppressed = [f for f in result.findings if f.triage == Triage.SUPPRESSED]

        lines.append(f"  Triage: {colors.red(str(len(act_now)) + ' ACT NOW')} | "
                      f"{colors.yellow(str(len(review)) + ' REVIEW')} | "
                      f"{colors.dim(str(len(suppressed)) + ' SUPPRESSED')}")
        lines.append("")

        tier_configs = [
            (Triage.ACT_NOW, act_now, colors.red, "These need immediate attention:"),
            (Triage.REVIEW, review, colors.yellow, "Review these when you can:"),
            (Triage.SUPPRESSED, suppressed, colors.dim, "Low confidence — likely noise:"),
        ]

        for tier, tier_findings, color_fn, desc in tier_configs:
            if not tier_findings:
                continue

            lines.append(color_fn(f"  [{tier.label.upper()}] ({len(tier_findings)} findings)"))
            lines.append(f"  {desc}")
            lines.append("")

            for finding in tier_findings:
                context_tag = ""
                if finding.file_context.value == "ai_config":
                    context_tag = colors.cyan(" [AI CONFIG]")
                elif finding.file_context.value == "test_fixture":
                    context_tag = colors.dim(" [TEST]")

                confidence_tag = colors.dim(f" [{finding.confidence}%]")
                fix_tag = ""
                if finding.auto_fixable:
                    fix_tag = colors.green(" [AUTO-FIX]")

                lines.append(
                    f"    {_severity_color(colors, finding.severity, finding.severity.label)} "
                    f"{finding.pattern_name}{context_tag}{confidence_tag}{fix_tag}"
                )
                lines.append(f"    File: {finding.file_path}:{finding.line_number}")
                lines.append(f"    Match: {finding.matched_text[:100]}")
                if finding.confidence_reason:
                    lines.append(f"    Score: {finding.confidence_reason}")
                lines.append(f"    Why:   {finding.description}")
                lines.append(f"    Fix:   {finding.remediation}")
                lines.append(
                    f"    Suppress: secureclaw allowlist add "
                    f"--file \"{finding.file_path}\" --pattern {finding.pattern_id}"
                )
                lines.append("")

        # Auto-fix hint
        auto_fixable = [f for f in result.findings if f.auto_fixable]
        if auto_fixable:
            lines.append(colors.bold(f"  {len(auto_fixable)} findings can be auto-fixed."))
            lines.append(f"  Run: secureclaw scan . --format json -o report.json")
            lines.append(f"  Then: secureclaw fix report.json  (dry-run by default; add --apply to execute)")
            lines.append("")

    # Footer
    lines.append("-" * 60)
    lines.append(f"  SecureClaw v{result.tool_version} | secureclaw.sparkry.ai")
    lines.append(f"  Run periodically to stay safe. Update: pip install -U secureclaw")
    lines.append("")

    return "\n".join(lines)
