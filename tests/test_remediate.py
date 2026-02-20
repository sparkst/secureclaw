"""Tests for auto-remediation engine."""

import tempfile
import unittest
from pathlib import Path

from secureclaw.core.models import (
    Finding,
    PatternCategory,
    Severity,
    Triage,
)
from secureclaw.core.remediate import (
    REDACTED,
    redact_credential_in_file,
    remediate_findings,
)


def _make_finding(file_path=None, **kwargs):
    defaults = dict(
        file_path=file_path or Path("/tmp/test.env"),
        line_number=1,
        pattern_id="PI-022",
        pattern_name="Exposed Credential",
        severity=Severity.CRITICAL,
        category=PatternCategory.EXFILTRATION,
        matched_text="OPENAI_API_KEY=sk-ant-abc123456789",
        description="Leaked credential",
        remediation="Redact and rotate",
        confidence=90,
        triage=Triage.ACT_NOW,
        auto_fixable=True,
        fix_action="redact_credential",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class TestRedactCredentialInFile(unittest.TestCase):
    """Test in-place credential redaction."""

    def test_redacts_simple_env_var(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".env", delete=False, encoding="utf-8"
        ) as f:
            f.write("OPENAI_API_KEY=sk-ant-abc123456789def\n")
            f.write("OTHER_VAR=safe_value\n")
            path = Path(f.name)

        finding = _make_finding(file_path=path)
        ok, detail = redact_credential_in_file(finding)

        self.assertTrue(ok)
        content = path.read_text()
        self.assertIn(REDACTED, content)
        self.assertNotIn("sk-ant-abc123456789def", content)
        self.assertIn("OTHER_VAR=safe_value", content)
        path.unlink()

    def test_redacts_quoted_value(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".env", delete=False, encoding="utf-8"
        ) as f:
            f.write('GITHUB_TOKEN="ghp_1234567890abcdefghij"\n')
            path = Path(f.name)

        finding = _make_finding(file_path=path)
        ok, detail = redact_credential_in_file(finding)

        self.assertTrue(ok)
        content = path.read_text()
        self.assertIn(REDACTED, content)
        self.assertNotIn("ghp_1234567890abcdefghij", content)
        path.unlink()

    def test_preserves_key_name(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".env", delete=False, encoding="utf-8"
        ) as f:
            f.write("ANTHROPIC_API_KEY=sk-ant-test1234567890\n")
            path = Path(f.name)

        finding = _make_finding(file_path=path)
        ok, _ = redact_credential_in_file(finding)

        self.assertTrue(ok)
        content = path.read_text()
        self.assertIn("ANTHROPIC_API_KEY=", content)
        path.unlink()

    def test_fails_on_nonexistent_file(self):
        finding = _make_finding(file_path=Path("/nonexistent/path/file.env"))
        ok, detail = redact_credential_in_file(finding)
        self.assertFalse(ok)
        self.assertIn("Cannot read", detail)

    def test_fails_on_line_out_of_range(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".env", delete=False, encoding="utf-8"
        ) as f:
            f.write("ONLY_ONE_LINE=value\n")
            path = Path(f.name)

        finding = _make_finding(file_path=path, line_number=99)
        ok, detail = redact_credential_in_file(finding)

        self.assertFalse(ok)
        self.assertIn("out of range", detail)
        path.unlink()

    def test_fails_if_no_credential_pattern_on_line(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".env", delete=False, encoding="utf-8"
        ) as f:
            f.write("just some normal text\n")
            path = Path(f.name)

        finding = _make_finding(file_path=path)
        ok, detail = redact_credential_in_file(finding)

        self.assertFalse(ok)
        self.assertIn("Could not locate", detail)
        path.unlink()


class TestRemediateFindings(unittest.TestCase):
    """Test batch remediation."""

    def test_dry_run_does_not_modify(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".env", delete=False, encoding="utf-8"
        ) as f:
            f.write("OPENAI_API_KEY=sk-ant-abc123456789def\n")
            path = Path(f.name)

        finding = _make_finding(file_path=path)
        result = remediate_findings([finding], dry_run=True)

        self.assertEqual(len(result.redacted), 1)
        # File should be unchanged
        content = path.read_text()
        self.assertIn("sk-ant-abc123456789def", content)
        path.unlink()

    def test_skips_non_auto_fixable(self):
        finding = _make_finding(auto_fixable=False)
        result = remediate_findings([finding])
        self.assertEqual(len(result.skipped), 1)

    def test_allowlist_action(self):
        finding = _make_finding(fix_action="allowlist", triage=Triage.REVIEW)
        result = remediate_findings([finding])
        self.assertEqual(len(result.allowlisted), 1)

    def test_unknown_action_skipped(self):
        finding = _make_finding(fix_action="unknown_action")
        result = remediate_findings([finding])
        self.assertEqual(len(result.skipped), 1)

    def test_mixed_findings(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".env", delete=False, encoding="utf-8"
        ) as f:
            f.write("OPENAI_API_KEY=sk-ant-abc123456789def\n")
            path = Path(f.name)

        findings = [
            _make_finding(file_path=path),  # redact_credential
            _make_finding(fix_action="allowlist", triage=Triage.REVIEW),  # allowlist
            _make_finding(auto_fixable=False),  # skip
        ]
        result = remediate_findings(findings, dry_run=True)

        self.assertEqual(len(result.redacted), 1)
        self.assertEqual(len(result.allowlisted), 1)
        self.assertEqual(len(result.skipped), 1)
        path.unlink()


if __name__ == "__main__":
    unittest.main()
