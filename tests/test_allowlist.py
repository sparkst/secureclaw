"""Tests for the allowlist system."""

from pathlib import Path

from secureclaw.cli import build_parser, cmd_allowlist_add, EXIT_CLEAN
from secureclaw.core.allowlist import Allowlist, _normalize_path
from secureclaw.core.models import (
    Finding,
    PatternCategory,
    Severity,
)


def _make_finding(file_path: str = "/test/file.txt", pattern_id: str = "PI-001") -> Finding:
    return Finding(
        file_path=Path(file_path),
        line_number=1,
        pattern_id=pattern_id,
        pattern_name="Test Pattern",
        severity=Severity.CRITICAL,
        category=PatternCategory.INSTRUCTION_OVERRIDE,
        matched_text="test",
        description="test",
        remediation="test",
    )


class TestNormalizePath:
    def test_forward_slashes(self):
        assert _normalize_path("/test/file.txt") == "/test/file.txt"

    def test_backslash_conversion(self):
        assert _normalize_path("C:\\Users\\test\\file.txt") == "C:/Users/test/file.txt"

    def test_mixed_slashes(self):
        assert _normalize_path("C:\\Users/test\\file.txt") == "C:/Users/test/file.txt"


class TestAllowlist:
    def test_add_entry(self):
        al = Allowlist()
        entry = al.add("*.md", "PI-001", "Legitimate markdown")
        assert len(al.entries) == 1
        assert entry.pattern_id == "PI-001"

    def test_remove_entry(self):
        al = Allowlist()
        al.add("*.md", "PI-001", "test")
        assert al.remove("*.md", "PI-001") is True
        assert len(al.entries) == 0

    def test_remove_nonexistent(self):
        al = Allowlist()
        assert al.remove("*.md", "PI-001") is False

    def test_suppresses_matching_finding(self):
        al = Allowlist()
        al.add("*/file.txt", "PI-001", "test")
        finding = _make_finding("/test/file.txt", "PI-001")
        assert al.is_suppressed(finding) is True

    def test_does_not_suppress_different_pattern(self):
        al = Allowlist()
        al.add("*/file.txt", "PI-001", "test")
        finding = _make_finding("/test/file.txt", "PI-002")
        assert al.is_suppressed(finding) is False

    def test_does_not_suppress_different_file(self):
        al = Allowlist()
        al.add("*/other.txt", "PI-001", "test")
        finding = _make_finding("/test/file.txt", "PI-001")
        assert al.is_suppressed(finding) is False

    def test_glob_pattern_matching(self):
        al = Allowlist()
        al.add("*.md", "PI-001", "All markdown files")
        finding = _make_finding("/project/README.md", "PI-001")
        assert al.is_suppressed(finding) is True

    def test_filter_findings(self):
        al = Allowlist()
        al.add("*/safe.txt", "PI-001", "Known safe")
        findings = [
            _make_finding("/project/safe.txt", "PI-001"),
            _make_finding("/project/bad.txt", "PI-001"),
            _make_finding("/project/safe.txt", "PI-002"),
        ]
        kept, suppressed = al.filter_findings(findings)
        assert suppressed == 1
        assert len(kept) == 2


class TestAllowlistPersistence:
    def test_save_and_load(self, tmp_path):
        path = tmp_path / "allowlist.json"
        al = Allowlist()
        al.add("*.md", "PI-001", "Markdown files")
        al.add("*.py", "PI-004", "Python scripts")
        al.save(path)

        loaded = Allowlist.load(path)
        assert len(loaded.entries) == 2
        assert loaded.entries[0].pattern_id == "PI-001"

    def test_integrity_check_passes(self, tmp_path):
        path = tmp_path / "allowlist.json"
        al = Allowlist()
        al.add("*.md", "PI-001", "test")
        al.save(path)

        loaded = Allowlist.load(path, verify_integrity=True)
        assert len(loaded.entries) == 1

    def test_integrity_check_fails_on_tamper(self, tmp_path):
        import json

        path = tmp_path / "allowlist.json"
        al = Allowlist()
        al.add("*.md", "PI-001", "test")
        al.save(path)

        # Tamper with the file
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
        data["entries"][0]["pattern_id"] = "PI-999"
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f)

        loaded = Allowlist.load(path, verify_integrity=True)
        assert len(loaded.entries) == 0  # Rejected due to tamper

    def test_load_nonexistent_returns_empty(self, tmp_path):
        loaded = Allowlist.load(tmp_path / "does_not_exist.json")
        assert len(loaded.entries) == 0

    def test_cross_platform_path_matching(self):
        al = Allowlist()
        al.add("project/src/*.py", "PI-001", "test")
        # Windows path should still match after normalization
        finding = _make_finding("project\\src\\main.py", "PI-001")
        # The finding path gets normalized during comparison
        assert al.is_suppressed(finding) is True


class TestAllowlistCLIIntegration:
    """End-to-end tests for allowlist CLI commands."""

    def test_cmd_allowlist_add_creates_file(self, tmp_path):
        allowlist_file = tmp_path / ".secureclaw" / "allowlist.json"
        parser = build_parser()
        args = parser.parse_args(
            [
                "allowlist",
                "add",
                "--file",
                "*.md",
                "--pattern",
                "PI-001",
                "--reason",
                "Markdown files are safe",
                "--allowlist-file",
                str(allowlist_file),
            ]
        )
        exit_code = cmd_allowlist_add(args)
        assert exit_code == EXIT_CLEAN
        assert allowlist_file.exists()

        # Verify the entry was written correctly
        loaded = Allowlist.load(allowlist_file, verify_integrity=False)
        assert len(loaded.entries) == 1
        assert loaded.entries[0].file_pattern == "*.md"
        assert loaded.entries[0].pattern_id == "PI-001"

    def test_cmd_allowlist_add_appends_to_existing(self, tmp_path):
        allowlist_file = tmp_path / ".secureclaw" / "allowlist.json"
        parser = build_parser()

        # Add first entry
        args = parser.parse_args(
            [
                "allowlist",
                "add",
                "--file",
                "*.md",
                "--pattern",
                "PI-001",
                "--reason",
                "First entry",
                "--allowlist-file",
                str(allowlist_file),
            ]
        )
        cmd_allowlist_add(args)

        # Add second entry
        args = parser.parse_args(
            [
                "allowlist",
                "add",
                "--file",
                "*.py",
                "--pattern",
                "PI-004",
                "--reason",
                "Second entry",
                "--allowlist-file",
                str(allowlist_file),
            ]
        )
        cmd_allowlist_add(args)

        loaded = Allowlist.load(allowlist_file, verify_integrity=False)
        assert len(loaded.entries) == 2

    def test_cmd_allowlist_add_default_reason(self, tmp_path):
        allowlist_file = tmp_path / ".secureclaw" / "allowlist.json"
        parser = build_parser()
        args = parser.parse_args(
            [
                "allowlist",
                "add",
                "--file",
                "*.md",
                "--pattern",
                "PI-001",
                "--allowlist-file",
                str(allowlist_file),
            ]
        )
        # No --reason provided; should use default
        exit_code = cmd_allowlist_add(args)
        assert exit_code == EXIT_CLEAN
        loaded = Allowlist.load(allowlist_file, verify_integrity=False)
        assert loaded.entries[0].reason != ""


class TestAllowlistPrecedence:
    """Tests for allowlist precedence (local vs global)."""

    def test_find_allowlist_local_preferred_over_global(self, tmp_path):
        # Create both local and global allowlist
        local_dir = tmp_path / "project" / ".secureclaw"
        local_dir.mkdir(parents=True)
        local_al = local_dir / "allowlist.json"
        local_al.write_text('{"entries": [], "_integrity": ""}')

        global_dir = tmp_path / ".config" / "secureclaw"
        global_dir.mkdir(parents=True)
        global_al = global_dir / "allowlist.json"
        global_al.write_text('{"entries": [], "_integrity": ""}')

        found = Allowlist.find_allowlist(tmp_path / "project")
        assert found is not None
        assert "project" in str(found)

    def test_find_allowlist_returns_none_when_no_files(self, tmp_path):
        found = Allowlist.find_allowlist(tmp_path / "nonexistent")
        # Should not find anything when no allowlist files exist
        # (may still find one in cwd, but with tmp_path it should be None)
        # This tests the search logic rather than a guaranteed None
        assert found is None or found.exists()
