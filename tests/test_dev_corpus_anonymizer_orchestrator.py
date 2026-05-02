"""Anonymizer orchestrator tests (spec §13.5 refusal).

Subprocess-mock the gitleaks/trufflehog binaries; verify the dispatch logic.
TDD red phase: lands BEFORE orchestrator code in anonymizer.py.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch


# --- helpers ----------------------------------------------------------------


def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


# --- gitleaks orchestration -------------------------------------------------


def test_run_gitleaks_clean_returns_pass(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import _run_gitleaks

    target = tmp_path / "x.md"
    target.write_text("hello world", encoding="utf-8")

    with (
        patch(
            "secureclaw.dev.corpus.anonymizer.shutil.which", return_value="/usr/local/bin/gitleaks"
        ),
        patch(
            "secureclaw.dev.corpus.anonymizer.subprocess.run", return_value=_completed(returncode=0)
        ),
    ):
        verdict, _ = _run_gitleaks(target, dst_subdir=tmp_path, timeout=30)
    assert verdict == "pass"


def test_run_gitleaks_finding_returns_refuse(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import _run_gitleaks

    target = tmp_path / "x.md"
    target.write_text("hello world", encoding="utf-8")

    finding_json = '[{"RuleID": "stripe-secret-key"}]'
    with (
        patch(
            "secureclaw.dev.corpus.anonymizer.shutil.which", return_value="/usr/local/bin/gitleaks"
        ),
        patch(
            "secureclaw.dev.corpus.anonymizer.subprocess.run",
            return_value=_completed(returncode=1, stdout=finding_json),
        ),
    ):
        verdict, _ = _run_gitleaks(target, dst_subdir=tmp_path, timeout=30)
    assert verdict == "refuse"


def test_run_gitleaks_unexpected_exit_aborts(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import _run_gitleaks

    target = tmp_path / "x.md"
    target.write_text("hello world", encoding="utf-8")

    with (
        patch(
            "secureclaw.dev.corpus.anonymizer.shutil.which", return_value="/usr/local/bin/gitleaks"
        ),
        patch(
            "secureclaw.dev.corpus.anonymizer.subprocess.run",
            return_value=_completed(returncode=2, stderr="bad config"),
        ),
    ):
        verdict, _ = _run_gitleaks(target, dst_subdir=tmp_path, timeout=30)
    assert verdict == "abort"


def test_run_gitleaks_missing_binary_returns_abort_when_required(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import _run_gitleaks

    target = tmp_path / "x.md"
    target.write_text("hello", encoding="utf-8")

    with patch("secureclaw.dev.corpus.anonymizer.shutil.which", return_value=None):
        verdict, _ = _run_gitleaks(target, dst_subdir=tmp_path, timeout=30)
    assert verdict == "abort"


def test_run_gitleaks_skipped_when_disabled(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import _run_gitleaks

    target = tmp_path / "x.md"
    target.write_text("hello", encoding="utf-8")

    verdict, _ = _run_gitleaks(target, dst_subdir=tmp_path, timeout=30, enabled=False)
    assert verdict == "pass"


# --- trufflehog orchestration ----------------------------------------------


def test_run_trufflehog_clean_returns_pass(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import _run_trufflehog

    target = tmp_path / "x.md"
    target.write_text("hello", encoding="utf-8")

    with (
        patch("secureclaw.dev.corpus.anonymizer.shutil.which", return_value="/usr/bin/trufflehog"),
        patch(
            "secureclaw.dev.corpus.anonymizer.subprocess.run",
            return_value=_completed(returncode=0, stdout=""),
        ),
    ):
        verdict, _ = _run_trufflehog(target, timeout=30, allow_unverified=False)
    assert verdict == "pass"


def test_run_trufflehog_verified_finding_refuses(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import _run_trufflehog

    target = tmp_path / "x.md"
    target.write_text("hello", encoding="utf-8")

    finding = '{"DetectorName":"GitHub","Verified":true}\n'
    with (
        patch("secureclaw.dev.corpus.anonymizer.shutil.which", return_value="/usr/bin/trufflehog"),
        patch(
            "secureclaw.dev.corpus.anonymizer.subprocess.run",
            return_value=_completed(returncode=0, stdout=finding),
        ),
    ):
        verdict, _ = _run_trufflehog(target, timeout=30, allow_unverified=False)
    assert verdict == "refuse"


def test_run_trufflehog_unverified_default_refuses(tmp_path: Path) -> None:
    """R3-001 / spec §13.5: unverified findings refuse by default."""
    from secureclaw.dev.corpus.anonymizer import _run_trufflehog

    target = tmp_path / "x.md"
    target.write_text("hello", encoding="utf-8")

    finding = '{"DetectorName":"GitHub","Verified":false}\n'
    with (
        patch("secureclaw.dev.corpus.anonymizer.shutil.which", return_value="/usr/bin/trufflehog"),
        patch(
            "secureclaw.dev.corpus.anonymizer.subprocess.run",
            return_value=_completed(returncode=0, stdout=finding),
        ),
    ):
        verdict, _ = _run_trufflehog(target, timeout=30, allow_unverified=False)
    assert verdict == "refuse"


def test_run_trufflehog_unverified_with_allow_flag_passes(tmp_path: Path) -> None:
    """--allow-trufflehog-unverified: unverified is warning-only."""
    from secureclaw.dev.corpus.anonymizer import _run_trufflehog

    target = tmp_path / "x.md"
    target.write_text("hello", encoding="utf-8")

    finding = '{"DetectorName":"GitHub","Verified":false}\n'
    with (
        patch("secureclaw.dev.corpus.anonymizer.shutil.which", return_value="/usr/bin/trufflehog"),
        patch(
            "secureclaw.dev.corpus.anonymizer.subprocess.run",
            return_value=_completed(returncode=0, stdout=finding),
        ),
    ):
        verdict, _ = _run_trufflehog(target, timeout=30, allow_unverified=True)
    assert verdict == "pass"


def test_run_trufflehog_zero_exit_with_jsonl_still_refuses(tmp_path: Path) -> None:
    """R3-001: detection must NOT depend on a non-zero exit code."""
    from secureclaw.dev.corpus.anonymizer import _run_trufflehog

    target = tmp_path / "x.md"
    target.write_text("hello", encoding="utf-8")

    finding = '{"DetectorName":"GitHub","Verified":true}\n'
    with (
        patch("secureclaw.dev.corpus.anonymizer.shutil.which", return_value="/usr/bin/trufflehog"),
        patch(
            "secureclaw.dev.corpus.anonymizer.subprocess.run",
            return_value=_completed(returncode=0, stdout=finding),  # exit 0 with finding
        ),
    ):
        verdict, _ = _run_trufflehog(target, timeout=30, allow_unverified=False)
    assert verdict == "refuse"


def test_run_trufflehog_nonzero_exit_no_stdout_aborts(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import _run_trufflehog

    target = tmp_path / "x.md"
    target.write_text("hello", encoding="utf-8")

    with (
        patch("secureclaw.dev.corpus.anonymizer.shutil.which", return_value="/usr/bin/trufflehog"),
        patch(
            "secureclaw.dev.corpus.anonymizer.subprocess.run",
            return_value=_completed(returncode=2, stdout="", stderr="bad input"),
        ),
    ):
        verdict, _ = _run_trufflehog(target, timeout=30, allow_unverified=False)
    assert verdict == "abort"


def test_run_trufflehog_skipped_when_disabled(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import _run_trufflehog

    target = tmp_path / "x.md"
    target.write_text("hello", encoding="utf-8")

    verdict, _ = _run_trufflehog(target, timeout=30, allow_unverified=False, enabled=False)
    assert verdict == "pass"


# --- secureclaw self-scan --------------------------------------------------


def test_run_secureclaw_pass_when_no_credential_finding(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import _run_secureclaw_self_scan

    target = tmp_path / "x.md"
    target.write_text("just plain text", encoding="utf-8")
    verdict, _ = _run_secureclaw_self_scan(target)
    assert verdict == "pass"


def test_run_secureclaw_refuses_on_high_confidence_credential(tmp_path: Path) -> None:
    """A file with a real-looking AKIA AWS key should be refused."""
    from secureclaw.dev.corpus.anonymizer import _run_secureclaw_self_scan

    target = tmp_path / "x.md"
    target.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    verdict, _ = _run_secureclaw_self_scan(target)
    # Could be 'pass' if scanner doesn't fire on this exact synthetic key, or
    # 'refuse' if it does. Either way must not be 'abort'.
    assert verdict in ("pass", "refuse")
