"""Tests for core data models."""

from secureclaw.core.models import (
    Finding,
    PatternCategory,
    ScanResult,
    ScanSummary,
    Severity,
)
from pathlib import Path


class TestSeverity:
    def test_labels_are_plain_english(self):
        assert Severity.CRITICAL.label == "CRITICAL RISK"
        assert Severity.HIGH.label == "HIGH RISK"
        assert Severity.ADVISORY.label == "ADVISORY"

    def test_descriptions_are_non_technical(self):
        for sev in Severity:
            desc = sev.description
            assert len(desc) > 20
            assert "P0" not in desc
            assert "P1" not in desc

    def test_sort_key_ordering(self):
        assert Severity.CRITICAL.sort_key < Severity.HIGH.sort_key
        assert Severity.HIGH.sort_key < Severity.ADVISORY.sort_key


class TestFinding:
    def test_dedup_key(self):
        f = Finding(
            file_path=Path("/test/file.txt"),
            line_number=10,
            pattern_id="PI-001",
            pattern_name="Test",
            severity=Severity.CRITICAL,
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            matched_text="test",
            description="test",
            remediation="test",
        )
        assert f.dedup_key == ("/test/file.txt", 10, "PI-001")

    def test_dedup_key_uniqueness(self):
        base = dict(
            pattern_name="Test",
            severity=Severity.CRITICAL,
            category=PatternCategory.INSTRUCTION_OVERRIDE,
            matched_text="test",
            description="test",
            remediation="test",
        )
        f1 = Finding(file_path=Path("/a.txt"), line_number=1, pattern_id="PI-001", **base)
        f2 = Finding(file_path=Path("/a.txt"), line_number=1, pattern_id="PI-002", **base)
        f3 = Finding(file_path=Path("/b.txt"), line_number=1, pattern_id="PI-001", **base)
        assert f1.dedup_key != f2.dedup_key
        assert f1.dedup_key != f3.dedup_key


class TestScanResult:
    def test_verdict_clean(self):
        result = ScanResult(summary=ScanSummary())
        assert "No issues found" in result.verdict

    def test_verdict_critical(self):
        result = ScanResult(summary=ScanSummary(critical_count=3))
        assert "critical" in result.verdict.lower()

    def test_verdict_high_only(self):
        result = ScanResult(summary=ScanSummary(high_count=5))
        assert "high-risk" in result.verdict.lower()

    def test_verdict_advisory_only(self):
        result = ScanResult(summary=ScanSummary(advisory_count=2))
        assert "advisory" in result.verdict.lower()
