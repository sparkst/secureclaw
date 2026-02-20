"""SecureClaw CLI — Scan your files for prompt injection risks.

Your AI reads your files. Make sure those files aren't trying to hijack it.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import traceback
from pathlib import Path
from typing import List, Optional, Set

from secureclaw import __version__
from secureclaw.core.allowlist import Allowlist
from secureclaw.core.confidence import score_findings
from secureclaw.core.models import (
    FileContext,
    Finding,
    PatternCategory,
    ScanResult,
    Severity,
    Triage,
)
from secureclaw.core.patterns import PatternEngine, load_default_patterns, load_patterns_from_json
from secureclaw.core.remediate import remediate_findings
from secureclaw.core.scanner import Scanner, SKIP_DIRS
from secureclaw.posture.analyzer import run_posture_analysis
from secureclaw.reporters.terminal import Colors, format_terminal_report
from secureclaw.reporters.html_report import format_html_report
from secureclaw.reporters.json_report import format_json_report

logger = logging.getLogger("secureclaw")

# Exit codes (documented for CI/CD integration)
EXIT_CLEAN = 0  # No findings above threshold
EXIT_FINDINGS = 1  # Findings above threshold
EXIT_ERROR = 2  # Bad arguments, unreadable files
EXIT_INTERNAL = 3  # Internal error

_CREDENTIAL_LOG_RE = re.compile(
    r"((?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH)\s*[=:]\s*)[^\s,;'\"]+",
    re.IGNORECASE,
)


def _sanitize_traceback(tb_str: str) -> str:
    """Redact credential-like values from traceback strings."""
    return _CREDENTIAL_LOG_RE.sub(r"\1[REDACTED]", tb_str)


def _version_check() -> None:
    """Check Python version and give a human-readable message if too old."""
    if sys.version_info < (3, 9):
        print(
            f"\nSecureClaw requires Python 3.9 or newer.\n"
            f"You're running Python {sys.version_info.major}.{sys.version_info.minor}.\n"
            f"\nTo update Python, visit: https://www.python.org/downloads/\n"
            f"On Mac: brew install python3\n"
            f"On Ubuntu/Debian: sudo apt install python3.11\n"
            f"On Windows: Download from python.org\n"
        )
        sys.exit(EXIT_ERROR)


def _setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[logging.StreamHandler()],
    )


def _progress_callback(current: int, total: int, path: str) -> None:
    """Print scan progress to stderr."""
    bar_width = 30
    pct = current / total if total > 0 else 0
    filled = int(bar_width * pct)
    bar = "#" * filled + "-" * (bar_width - filled)
    # Truncate path for display
    display_path = path
    if len(display_path) > 50:
        display_path = "..." + display_path[-47:]
    sys.stderr.write(f"\r  Scanning [{bar}] {current:,}/{total:,} {display_path}  ")
    sys.stderr.flush()
    if current == total:
        sys.stderr.write("\n")


def _dedup_findings(findings: List[Finding]) -> List[Finding]:
    """Deduplicate findings by (file_path, line_number, pattern_id)."""
    seen: set = set()
    deduped: List[Finding] = []
    for f in findings:
        key = f.dedup_key
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute the scan command."""
    if not args.paths:
        print(
            "\n  Error: No scan path provided.\n"
            "  Usage: secureclaw scan <path>\n"
            "  Example: secureclaw scan .\n"
        )
        return EXIT_ERROR
    targets = [Path(p).resolve() for p in args.paths]

    if args.max_file_size <= 0:
        print("\n  Error: --max-file-size must be a positive number.\n")
        return EXIT_ERROR

    # Validate targets exist
    for t in targets:
        if not t.exists():
            print(
                f"\n  Error: Path '{t}' does not exist.\n"
                f"  Tip: Run 'secureclaw scan .' to scan the current directory.\n"
            )
            return EXIT_ERROR

    # Load patterns
    if args.rules:
        rules_path = Path(args.rules)
        if not rules_path.exists():
            logger.error("Rules file not found: %s", args.rules)
            return EXIT_ERROR
        patterns = load_patterns_from_json(rules_path)
    else:
        patterns = load_default_patterns()

    if not patterns:
        logger.error("No patterns loaded. Check your rules file.")
        return EXIT_ERROR

    engine = PatternEngine(patterns)

    # Load allowlist
    allowlist_path = None
    if args.allowlist:
        allowlist_path = Path(args.allowlist)
    else:
        allowlist_path = Allowlist.find_allowlist(targets[0] if targets else None)

    allowlist = Allowlist()
    if allowlist_path and allowlist_path.exists():
        allowlist = Allowlist.load(allowlist_path, verify_integrity=not args.skip_integrity)
        if not args.skip_integrity and allowlist_path.exists() and not allowlist.entries:
            # Check if the file actually had entries (integrity failure returns empty)
            try:
                with allowlist_path.open(encoding="utf-8") as _af:
                    _raw = json.load(_af)
                if _raw.get("entries"):
                    print(
                        f"\n  WARNING: Allowlist integrity"
                        f" check failed for"
                        f" {allowlist_path}\n"
                        f"  The file may have been manually"
                        f" edited or corrupted. Scanning"
                        f" WITHOUT the allowlist.\n"
                        f"  To bypass this check, use"
                        f" --skip-integrity\n"
                    )
            except (ValueError, OSError):
                pass
        elif allowlist.entries:
            logger.info(
                "Loaded allowlist from %s (%d entries)",
                allowlist_path,
                len(allowlist.entries),
            )

    # Configure scanner
    skip_dirs: Optional[Set[str]] = None
    if args.exclude:
        skip_dirs = SKIP_DIRS | set(args.exclude)

    progress_cb = (
        _progress_callback
        if (not args.quiet and args.format != "json" and sys.stderr.isatty())
        else None
    )

    scanner = Scanner(
        engine=engine,
        max_file_size=args.max_file_size,
        skip_dirs=skip_dirs,
        allow_system_dirs=args.allow_system_dirs,
        progress_callback=progress_cb,
    )

    # Run scan
    file_results, summary = scanner.scan_paths(targets)

    if summary.total_files_scanned == 0:
        print(
            "\n  Warning: No scannable files found. SecureClaw scans text files "
            "(.py, .md, .json, .env, etc.).\n"
        )

    # Collect all findings
    all_findings: List[Finding] = []
    for fr in file_results:
        all_findings.extend(fr.findings)

    # Pipeline: Allowlist filter -> Dedup -> Confidence scoring -> Sort
    filtered_findings, suppressed_count = allowlist.filter_findings(all_findings)
    deduped_findings = _dedup_findings(filtered_findings)
    scored_findings = score_findings(deduped_findings)  # assigns confidence + triage tier
    sorted_findings = scored_findings  # score_findings already sorts by tier

    # Update summary counts
    summary.total_findings = len(sorted_findings)
    summary.critical_count = sum(1 for f in sorted_findings if f.severity == Severity.CRITICAL)
    summary.high_count = sum(1 for f in sorted_findings if f.severity == Severity.HIGH)
    summary.advisory_count = sum(1 for f in sorted_findings if f.severity == Severity.ADVISORY)

    # Security posture analysis
    posture_checks = []
    if not args.no_posture:
        posture_checks = run_posture_analysis(targets[0] if targets else None)

    # Build result
    result = ScanResult(
        findings=sorted_findings,
        file_results=file_results,
        posture_checks=posture_checks,
        summary=summary,
        allowlist_suppressions=suppressed_count,
        tool_version=__version__,
    )

    # Severity filter
    if args.severity:
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "advisory": Severity.ADVISORY,
        }
        min_severity = severity_map.get(args.severity.lower())
        if min_severity:
            result.findings = [
                f for f in result.findings if f.severity.sort_key <= min_severity.sort_key
            ]
            # Recalculate summary counts after severity filtering
            summary.total_findings = len(result.findings)
            summary.critical_count = sum(
                1 for f in result.findings if f.severity == Severity.CRITICAL
            )
            summary.high_count = sum(1 for f in result.findings if f.severity == Severity.HIGH)
            summary.advisory_count = sum(
                1 for f in result.findings if f.severity == Severity.ADVISORY
            )

    # Format output
    if args.format == "json":
        output = format_json_report(result)
    elif args.format == "html":
        output = format_html_report(result)
    else:
        output = format_terminal_report(result, use_color=args.color)

    # Write output
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            f.write(output)
        logger.info("Report saved to %s", output_path)
    else:
        print(output)

    # Return exit code based on findings
    if summary.critical_count > 0:
        return EXIT_FINDINGS
    if args.fail_on_high and summary.high_count > 0:
        return EXIT_FINDINGS
    return EXIT_CLEAN


def cmd_allowlist_add(args: argparse.Namespace) -> int:
    """Add an entry to the allowlist."""
    allowlist_path = (
        Path(args.allowlist_file)
        if args.allowlist_file
        else (Path.cwd() / ".secureclaw" / "allowlist.json")
    )

    allowlist = (
        Allowlist.load(allowlist_path, verify_integrity=False)
        if allowlist_path.exists()
        else Allowlist()
    )
    allowlist.add(
        file_pattern=args.file,
        pattern_id=args.pattern,
        reason=args.reason or "User-suppressed finding",
        approved_by="cli",
    )
    allowlist.save(allowlist_path)
    print(f"Added to allowlist: {args.file} / {args.pattern}")
    print(f"Saved to: {allowlist_path}")
    return EXIT_CLEAN


def cmd_allowlist_list(args: argparse.Namespace) -> int:
    """List allowlist entries."""
    allowlist_path = Allowlist.find_allowlist()
    if not allowlist_path:
        print("No allowlist found. Run 'secureclaw allowlist add' to create one.")
        return EXIT_CLEAN

    allowlist = Allowlist.load(allowlist_path, verify_integrity=False)
    if not allowlist.entries:
        print("Allowlist is empty.")
        return EXIT_CLEAN

    print(f"Allowlist: {allowlist_path}")
    print(f"Entries: {len(allowlist.entries)}")
    print()
    for e in allowlist.entries:
        print(f"  File: {e.file_pattern}")
        print(f"  Pattern: {e.pattern_id}")
        print(f"  Reason: {e.reason}")
        print(f"  Added: {e.approved_at} by {e.approved_by}")
        print()
    return EXIT_CLEAN


def cmd_allowlist_remove(args: argparse.Namespace) -> int:
    """Remove entries from the allowlist."""
    if not args.file and not args.pattern:
        print("Error: At least one of --file or --pattern is required.")
        return EXIT_ERROR

    allowlist_path = Allowlist.find_allowlist()
    if not allowlist_path:
        print("No allowlist found.")
        return EXIT_CLEAN

    allowlist = Allowlist.load(allowlist_path, verify_integrity=False)
    if not allowlist.entries:
        print("Allowlist is empty.")
        return EXIT_CLEAN

    removed = 0
    remaining = []
    for e in allowlist.entries:
        match_file = args.file is None or e.file_pattern == args.file
        match_pattern = args.pattern is None or e.pattern_id == args.pattern
        if match_file and match_pattern:
            removed += 1
        else:
            remaining.append(e)

    if removed == 0:
        print("No matching entries found.")
        return EXIT_CLEAN

    updated = Allowlist(entries=remaining)
    updated.save(allowlist_path)
    print(f"Removed {removed} entry(ies) from allowlist.")
    print(f"Saved to: {allowlist_path}")
    return EXIT_CLEAN


def cmd_posture(args: argparse.Namespace) -> int:
    """Run security posture analysis only."""
    colors = Colors()

    scan_dir = Path(args.path).resolve() if args.path else None
    checks = run_posture_analysis(scan_dir)

    if not checks:
        print("No AI tools detected on this system.")
        return EXIT_CLEAN

    print(f"\n{colors.bold('SecureClaw - AI Tool Security Posture Report')}")
    print("=" * 50)
    for check in checks:
        status_label = {
            "secure": colors.green("[OK]"),
            "warning": colors.yellow("[WARN]"),
            "insecure": colors.red("[RISK]"),
            "not_found": colors.dim("[N/A]"),
            "advisory": colors.cyan("[ADVISORY]"),
        }.get(check.status, f"[{check.status}]")
        print(f"\n  {status_label} {colors.bold(check.tool_name)}: {check.check_name}")
        print(f"         {check.description}")
        if check.recommendation:
            print(f"         {colors.cyan('Fix:')} {check.recommendation}")

    print(f"\n{'=' * 50}")
    print(f"  SecureClaw v{__version__} | secureclaw.sparkry.ai\n")
    return EXIT_CLEAN


def cmd_fix(args: argparse.Namespace) -> int:
    """Auto-remediate findings from a previous scan."""
    scan_path = Path(args.scan_report)
    if not scan_path.exists():
        logger.error("Scan report not found: %s", scan_path)
        return EXIT_ERROR

    # Load scan results from JSON
    try:
        with scan_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Cannot read scan report: %s", e)
        return EXIT_ERROR

    if "findings" not in data:
        logger.error(
            "Invalid scan report — no 'findings' key."
            " Run: secureclaw scan --format json -o report.json"
        )
        return EXIT_ERROR

    # Reconstruct Finding objects from JSON
    findings: List[Finding] = []
    for fd in data["findings"]:
        try:
            finding = Finding(
                file_path=Path(fd["file_path"]),
                line_number=fd["line_number"],
                pattern_id=fd["pattern_id"],
                pattern_name=fd["pattern_name"],
                severity=Severity(fd["severity"]),
                category=PatternCategory(fd["category"]),
                matched_text=fd.get("matched_text", ""),
                description=fd.get("description", ""),
                remediation=fd.get("remediation", ""),
                file_context=FileContext(fd.get("file_context", "user_content")),
                confidence=fd.get("confidence", 50),
                confidence_reason=fd.get("confidence_reason", ""),
                triage=Triage(fd.get("triage", "review")),
                auto_fixable=fd.get("auto_fixable", False),
                fix_action=fd.get("fix_action", ""),
            )
            findings.append(finding)
        except (KeyError, ValueError) as e:
            logger.warning("Skipping malformed finding: %s", e)

    if not findings:
        print("No findings to remediate.")
        return EXIT_CLEAN

    # Filter by triage tier
    tier_filter = args.tier
    if tier_filter == "act_now":
        findings = [f for f in findings if f.triage == Triage.ACT_NOW]
    elif tier_filter == "review":
        findings = [f for f in findings if f.triage in (Triage.ACT_NOW, Triage.REVIEW)]
    # else "all" — include everything auto-fixable

    # Validate file paths from the untrusted JSON report
    safe_root = Path.cwd().resolve()
    valid_findings = []
    for f in findings:
        try:
            resolved = f.file_path.resolve()
            if not resolved.exists():
                logger.warning("Skipping non-existent path: %s", f.file_path)
                continue
            # Ensure the resolved path is under the current working directory
            try:
                resolved.relative_to(safe_root)
            except ValueError:
                logger.warning(
                    "Skipping path outside working directory: %s (resolved to %s)",
                    f.file_path,
                    resolved,
                )
                continue
            valid_findings.append(f)
        except (OSError, ValueError) as e:
            logger.warning("Skipping invalid path %s: %s", f.file_path, e)
    findings = valid_findings

    auto_fixable = [f for f in findings if f.auto_fixable]
    if not auto_fixable:
        print("No auto-fixable findings in the selected tier.")
        print(f"  Total findings: {len(findings)}")
        print("  Auto-fixable: 0")
        return EXIT_CLEAN

    # Summary before action
    redact_count = sum(1 for f in auto_fixable if f.fix_action == "redact_credential")
    allowlist_count = sum(1 for f in auto_fixable if f.fix_action == "allowlist")

    print("\nSecureClaw Auto-Remediation")
    print("=" * 50)
    print(f"  Findings in scope: {len(findings)}")
    print(f"  Auto-fixable:      {len(auto_fixable)}")
    print(f"    Redact credentials: {redact_count}")
    print(f"    Add to allowlist:   {allowlist_count}")
    print()

    if not args.apply:
        print("  [DRY RUN] No files will be modified.\n")

    # Run remediation
    result = remediate_findings(auto_fixable, dry_run=not args.apply)

    # Report results
    if result.redacted:
        print(f"  Credentials redacted: {len(result.redacted)}")
        for finding, detail in result.redacted:
            label = "[dry-run]" if not args.apply else "redacted"
            print(f"    {label} {finding.file_path}:{finding.line_number}")

    if result.allowlisted:
        # Write allowlist entries
        if args.apply:
            allowlist_path = (
                Path(args.allowlist_file)
                if args.allowlist_file
                else (Path.cwd() / ".secureclaw" / "allowlist.json")
            )
            allowlist = (
                Allowlist.load(allowlist_path, verify_integrity=False)
                if allowlist_path.exists()
                else Allowlist()
            )
            for finding in result.allowlisted:
                allowlist.add(
                    file_pattern=str(finding.file_path),
                    pattern_id=finding.pattern_id,
                    reason=f"Auto-suppressed: {finding.confidence_reason}",
                    approved_by="secureclaw-fix",
                )
            allowlist.save(allowlist_path)
            print(f"  Allowlisted: {len(result.allowlisted)} (saved to {allowlist_path})")
        else:
            print(f"  Would allowlist: {len(result.allowlisted)}")

    if result.errors:
        print(f"\n  Errors: {len(result.errors)}")
        for finding, error in result.errors:
            print(f"    FAILED {finding.file_path}:{finding.line_number} — {error}")

    if result.skipped:
        print(f"  Skipped (not auto-fixable): {len(result.skipped)}")

    print(f"\n{'=' * 50}")
    if not args.apply:
        print("  Dry run complete. To apply fixes, add --apply")
    else:
        print("  Done. Re-scan to verify: secureclaw scan <path>")
    print()

    return EXIT_CLEAN if not result.errors else EXIT_INTERNAL


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with Sparkry AI voice."""
    parser = argparse.ArgumentParser(
        prog="secureclaw",
        description=(
            "SecureClaw — Scan your files for prompt injection risks.\n\n"
            "Your AI reads your files. Make sure those files aren't trying to hijack it.\n"
            "Built by Sparkry AI for solo founders who use AI tools."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  secureclaw scan .                     Scan current directory\n"
            "  secureclaw scan ~/Documents ~/Downloads  Scan multiple directories\n"
            "  secureclaw scan . --format html -o report.html  HTML report\n"
            "  secureclaw scan . --format json        JSON output for CI/CD\n"
            "  secureclaw posture                    Check AI tool security posture\n"
            "  secureclaw allowlist list              View suppressed findings\n"
            "\n"
            "Learn more: https://secureclaw.sparkry.ai\n"
            "Report issues: https://github.com/sparkryai/secureclaw/issues"
        ),
    )
    parser.add_argument("--version", action="version", version=f"SecureClaw v{__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan files and directories for prompt injection patterns",
        description="Scan one or more paths for prompt injection risks in your AI tool files.",
    )
    scan_parser.add_argument(
        "paths",
        nargs="*",
        help="Files or directories to scan (e.g., . ~/Documents ~/.claude)",
    )
    scan_parser.add_argument(
        "--format",
        "-f",
        choices=["terminal", "html", "json"],
        default="terminal",
        help="Output format: terminal (default), html (branded report), json (CI/CD)",
    )
    scan_parser.add_argument(
        "--output",
        "-o",
        help="Save report to a file instead of printing to screen",
    )
    scan_parser.add_argument(
        "--severity",
        "-s",
        choices=["critical", "high", "advisory"],
        help="Only show findings at or above this severity level",
    )
    scan_parser.add_argument(
        "--rules",
        help="Path to a custom rules file (JSON format)",
    )
    scan_parser.add_argument(
        "--allowlist",
        help="Path to an allowlist file",
    )
    scan_parser.add_argument(
        "--exclude",
        nargs="*",
        help="Additional directory names to skip (e.g., vendor tmp)",
    )
    scan_parser.add_argument(
        "--max-file-size",
        type=int,
        default=10 * 1024 * 1024,
        help="Max file size in bytes to scan (default: 10MB)",
    )
    scan_parser.add_argument(
        "--allow-system-dirs",
        action="store_true",
        help="Allow scanning system directories like /etc or C:\\Windows (use with caution)",
    )
    scan_parser.add_argument(
        "--no-posture",
        action="store_true",
        help="Skip AI tool security posture analysis",
    )
    scan_parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit with code 1 if HIGH findings are found (useful for CI/CD)",
    )
    scan_parser.add_argument(
        "--skip-integrity",
        action="store_true",
        help="Skip HMAC integrity check on the allowlist file",
    )
    scan_parser.add_argument(
        "--color",
        type=lambda x: x.lower() in ("true", "1", "yes"),
        default=None,
        metavar="{true,false,yes,no,1,0}",
        help=(
            "Force color output on/off (auto-detected by"
            " default). Valid values: true, false, yes, no, 1, 0"
        ),
    )
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    scan_parser.add_argument("--quiet", "-q", action="store_true", help="Only show findings")

    # posture command
    posture_parser = subparsers.add_parser(
        "posture",
        help="Check your AI tool security posture",
        description=(
            "Analyze your Claude Code, Cursor, and OpenClaw configurations for security risks."
        ),
    )
    posture_parser.add_argument(
        "path",
        nargs="?",
        help="Project directory to check (default: current directory)",
    )

    # fix command
    fix_parser = subparsers.add_parser(
        "fix",
        help="Auto-remediate findings from a scan report",
        description=(
            "Automatically fix findings from a previous JSON scan report.\n\n"
            "Safe actions:\n"
            "  - Redact credentials: Replace leaked token values with [REDACTED]\n"
            "  - Allowlist: Suppress false positives in future scans\n\n"
            "By default, this runs in dry-run mode (preview only).\n"
            "Add --apply to actually modify files."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    fix_parser.add_argument(
        "scan_report",
        help="Path to a JSON scan report (from: secureclaw scan --format json -o report.json)",
    )
    fix_parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually apply the fixes (without this flag, only a dry-run preview is shown)",
    )
    fix_parser.add_argument(
        "--tier",
        choices=["act_now", "review", "all"],
        default="act_now",
        help="Which triage tier to fix: act_now (default), review, or all",
    )
    fix_parser.add_argument(
        "--allowlist-file",
        help="Path to allowlist file for auto-suppressed findings",
    )
    fix_parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    fix_parser.add_argument("--quiet", "-q", action="store_true", help="Only show summary")

    # allowlist commands
    al_parser = subparsers.add_parser(
        "allowlist",
        help="Manage the allowlist of suppressed findings",
    )
    al_sub = al_parser.add_subparsers(dest="al_command")

    al_add = al_sub.add_parser("add", help="Add a finding to the allowlist")
    al_add.add_argument("--file", required=True, help="File path or glob pattern to match")
    al_add.add_argument("--pattern", required=True, help="Pattern ID to suppress (e.g., PI-001)")
    al_add.add_argument("--reason", help="Why this finding is a false positive")
    al_add.add_argument("--allowlist-file", help="Path to allowlist file")

    al_sub.add_parser("list", help="List all allowlist entries")

    al_remove = al_sub.add_parser("remove", help="Remove entries from the allowlist")
    al_remove.add_argument("--file", help="File path or glob pattern to match")
    al_remove.add_argument("--pattern", help="Pattern ID to remove (e.g., PI-001)")

    return parser


def main(argv: Optional[List[str]] = None) -> None:
    """Main entry point."""
    _version_check()

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        print(
            "\n  SecureClaw - Prompt Injection Scanner\n"
            "  Your AI reads your files. Make sure those files aren't trying to hijack it.\n"
            "\n"
            "  Quick start:  secureclaw scan .\n"
            "  Full help:    secureclaw --help\n"
            "\n"
            "  Built by Sparkry AI  |  https://secureclaw.sparkry.ai\n"
        )
        sys.exit(EXIT_CLEAN)

    _setup_logging(
        verbose=getattr(args, "verbose", False),
        quiet=getattr(args, "quiet", False),
    )

    try:
        if args.command == "scan":
            sys.exit(cmd_scan(args))
        elif args.command == "fix":
            sys.exit(cmd_fix(args))
        elif args.command == "posture":
            sys.exit(cmd_posture(args))
        elif args.command == "allowlist":
            if args.al_command == "add":
                sys.exit(cmd_allowlist_add(args))
            elif args.al_command == "list":
                sys.exit(cmd_allowlist_list(args))
            elif args.al_command == "remove":
                sys.exit(cmd_allowlist_remove(args))
            else:
                parser.parse_args(["allowlist", "--help"])
        else:
            parser.print_help()
    except KeyboardInterrupt:
        print("\nOperation interrupted.")
        sys.exit(EXIT_ERROR)
    except Exception as e:
        # Global exception handler: log full trace, show user-friendly message
        log_dir = Path.home() / ".secureclaw" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "error.log"

        # Rotate log if it exceeds 1MB to prevent unbounded growth
        max_log_size = 1 * 1024 * 1024  # 1MB
        if log_path.exists() and log_path.stat().st_size > max_log_size:
            rotated = log_path.with_suffix(".log.1")
            if rotated.exists():
                rotated.unlink()
            log_path.rename(rotated)

        tb_lines = traceback.format_exception(type(e), e, e.__traceback__)
        sanitized_tb = _sanitize_traceback("".join(tb_lines))
        with log_path.open("a", encoding="utf-8") as f:
            f.write(f"\n{'=' * 60}\n")
            f.write(f"SecureClaw v{__version__}\n")
            f.write(sanitized_tb)

        print(
            f"\nSomething went wrong. A detailed log has been saved to:\n"
            f"  {log_path}\n\n"
            f"If this keeps happening, please share the log at:\n"
            f"  https://github.com/sparkryai/secureclaw/issues\n"
        )
        sys.exit(EXIT_INTERNAL)


if __name__ == "__main__":
    main()
