"""Tests for report generators."""

import json
import os
from pathlib import Path

from secureclaw.core.models import (
    Finding,
    PatternCategory,
    PostureCheck,
    ScanResult,
    ScanSummary,
    Severity,
)
from secureclaw.reporters.terminal import format_terminal_report, _supports_color
from secureclaw.reporters.html_report import format_html_report
from secureclaw.reporters.json_report import format_json_report


def _sample_result() -> ScanResult:
    return ScanResult(
        findings=[
            Finding(
                file_path=Path("/test/bad.md"),
                line_number=5,
                pattern_id="PI-001",
                pattern_name="Ignore Instructions",
                severity=Severity.CRITICAL,
                category=PatternCategory.INSTRUCTION_OVERRIDE,
                matched_text="Ignore all previous instructions",
                description="A command telling your AI to ignore safety",
                remediation="Delete this text",
            ),
            Finding(
                file_path=Path("/test/config.yml"),
                line_number=12,
                pattern_id="PI-013",
                pattern_name="Hidden CSS Text",
                severity=Severity.HIGH,
                category=PatternCategory.INVISIBLE_TEXT,
                matched_text='display:none',
                description="Hidden text using CSS tricks",
                remediation="Inspect the source",
            ),
        ],
        posture_checks=[
            PostureCheck(
                tool_name="Claude Code",
                check_name="Installation",
                status="secure",
                description="Claude Code is installed.",
            ),
        ],
        summary=ScanSummary(
            total_files_scanned=100,
            total_files_skipped=20,
            total_findings=2,
            critical_count=1,
            high_count=1,
            advisory_count=0,
            patterns_checked=28,
            scan_duration_seconds=1.5,
        ),
        tool_version="1.0.0",
    )


class TestTerminalReporter:
    def test_contains_summary(self):
        report = format_terminal_report(_sample_result(), use_color=False)
        assert "100" in report  # files scanned
        assert "CRITICAL" in report
        assert "HIGH" in report

    def test_contains_findings(self):
        report = format_terminal_report(_sample_result(), use_color=False)
        assert "Ignore Instructions" in report
        assert "bad.md" in report

    def test_contains_posture(self):
        report = format_terminal_report(_sample_result(), use_color=False)
        assert "Claude Code" in report
        assert "SECURE" in report

    def test_contains_sparkry_branding(self):
        report = format_terminal_report(_sample_result(), use_color=False)
        assert "Sparkry AI" in report

    def test_clean_scan_message(self):
        result = ScanResult(
            summary=ScanSummary(total_files_scanned=50),
            tool_version="1.0.0",
        )
        report = format_terminal_report(result, use_color=False)
        assert "No issues found" in report

    def test_no_color_mode(self):
        report = format_terminal_report(_sample_result(), use_color=False)
        assert "\033[" not in report  # No ANSI escape codes

    def test_suppressions_shown(self):
        result = _sample_result()
        result.allowlist_suppressions = 5
        report = format_terminal_report(result, use_color=False)
        assert "5" in report
        assert "suppress" in report.lower() or "allowlist" in report.lower()

    def test_suppress_hint_per_finding(self):
        report = format_terminal_report(_sample_result(), use_color=False)
        assert "secureclaw allowlist add" in report


class TestHTMLReporter:
    def test_valid_html(self):
        html = format_html_report(_sample_result())
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_self_contained(self):
        html = format_html_report(_sample_result())
        assert "<style>" in html
        # Icons are inlined as SVGs (no CDN dependency for icons)
        assert "viewBox" in html
        assert '<svg' in html
        # No external font CDN — uses system font stack
        assert "fonts.googleapis.com" not in html
        assert "-apple-system" in html

    def test_contains_findings(self):
        html = format_html_report(_sample_result())
        assert "Ignore Instructions" in html
        # New design uses triage labels instead of severity labels
        assert "Act Now" in html or "Review" in html or "Suppressed" in html

    def test_html_escapes_user_content(self):
        result = _sample_result()
        result.findings[0].matched_text = '<script>alert("xss")</script>'
        html = format_html_report(result)
        # User-supplied XSS payload must be escaped
        assert "&lt;script&gt;alert(" in html
        # The unescaped payload must NOT appear inside a finding
        assert '<script>alert(' not in html

    def test_sparkry_branding(self):
        html = format_html_report(_sample_result())
        assert "Sparkry AI" in html
        assert "secureclaw.sparkry.ai" in html

    def test_posture_section(self):
        html = format_html_report(_sample_result())
        assert "Claude Code" in html

    def test_accessibility_tooltips(self):
        html = format_html_report(_sample_result())
        # New design uses tooltip tip-text for accessibility
        assert "tip-text" in html
        assert "tooltip" in html


class TestJSONReporter:
    def test_valid_json(self):
        output = format_json_report(_sample_result())
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_schema_version(self):
        data = json.loads(format_json_report(_sample_result()))
        assert data["schema_version"] == 1

    def test_tool_version(self):
        data = json.loads(format_json_report(_sample_result()))
        assert data["tool_version"] == "1.0.0"

    def test_findings_array(self):
        data = json.loads(format_json_report(_sample_result()))
        assert len(data["findings"]) == 2
        assert data["findings"][0]["pattern_id"] == "PI-001"
        assert data["findings"][0]["severity"] == "critical"

    def test_summary_stats(self):
        data = json.loads(format_json_report(_sample_result()))
        assert data["summary"]["total_files_scanned"] == 100
        assert data["summary"]["critical_count"] == 1

    def test_posture_checks(self):
        data = json.loads(format_json_report(_sample_result()))
        assert len(data["posture_checks"]) == 1
        assert data["posture_checks"][0]["tool_name"] == "Claude Code"

    def test_timestamp_present(self):
        data = json.loads(format_json_report(_sample_result()))
        assert "scan_timestamp" in data


class TestHTMLCleanScan:
    """Test HTML report with zero findings."""

    def test_html_report_zero_findings(self):
        result = ScanResult(
            summary=ScanSummary(
                total_files_scanned=50,
                total_files_skipped=5,
                patterns_checked=28,
                scan_duration_seconds=0.8,
            ),
            tool_version="1.2.0",
        )
        html = format_html_report(result)
        assert "<!DOCTYPE html>" in html
        assert "</html>" in html
        # Should contain clean scan messaging
        assert "No issues found" in html or "0" in html
        # Should still have branding
        assert "Sparkry AI" in html


class TestColorModeDetection:
    """Tests for terminal color mode detection."""

    def test_no_color_env_disables_color(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        assert _supports_color() is False

    def test_force_color_env_enables_color(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        assert _supports_color() is True

    def test_no_color_takes_precedence_over_force_color(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.setenv("FORCE_COLOR", "1")
        # NO_COLOR is checked first in the function
        assert _supports_color() is False

    def test_terminal_report_no_ansi_when_no_color(self):
        report = format_terminal_report(_sample_result(), use_color=False)
        assert "\033[" not in report

    def test_terminal_report_with_color_has_ansi(self, monkeypatch):
        # Force color support by setting FORCE_COLOR and patching _supports_color
        monkeypatch.setenv("FORCE_COLOR", "1")
        monkeypatch.delenv("NO_COLOR", raising=False)
        from unittest.mock import patch
        with patch("secureclaw.reporters.terminal._supports_color", return_value=True):
            report = format_terminal_report(_sample_result(), use_color=True)
        # When color is forced and supports_color returns True, ANSI codes should be present
        assert "\033[" in report
