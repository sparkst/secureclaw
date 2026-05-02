"""Anonymizer tree-walker + skip + report tests (spec §13.5 tree).

TDD red phase.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


def _all_pass(*args, **kwargs):
    """Mock that makes all scanners pass."""
    return ("pass", {})


# --- happy path ------------------------------------------------------------


def test_anonymize_tree_processes_one_file(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import anonymize_tree

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.md").write_text("Hello at /Users/alice/secret/x.md\n", encoding="utf-8")

    dst = tmp_path / "dst"

    with (
        patch("secureclaw.dev.corpus.anonymizer._run_gitleaks", side_effect=_all_pass),
        patch("secureclaw.dev.corpus.anonymizer._run_trufflehog", side_effect=_all_pass),
        patch(
            "secureclaw.dev.corpus.anonymizer._run_secureclaw_self_scan",
            side_effect=_all_pass,
        ),
    ):
        report = anonymize_tree(src, dst)

    assert report.processed == 1
    assert report.refused == 0
    assert (dst / "a.md").exists()
    out_text = (dst / "a.md").read_text(encoding="utf-8")
    assert "/Users/dev/" in out_text
    assert "alice" not in out_text
    # JSONL report exists.
    assert (dst / "anonymize-report.jsonl").exists()


def test_anonymize_tree_writes_jsonl_report(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import anonymize_tree

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.md").write_text("hello\n", encoding="utf-8")

    dst = tmp_path / "dst"

    with (
        patch("secureclaw.dev.corpus.anonymizer._run_gitleaks", side_effect=_all_pass),
        patch("secureclaw.dev.corpus.anonymizer._run_trufflehog", side_effect=_all_pass),
        patch(
            "secureclaw.dev.corpus.anonymizer._run_secureclaw_self_scan",
            side_effect=_all_pass,
        ),
    ):
        anonymize_tree(src, dst)

    report_path = dst / "anonymize-report.jsonl"
    lines = report_path.read_text(encoding="utf-8").strip().splitlines()
    # One line per processed file, all parseable JSON.
    assert len(lines) >= 1
    for line in lines:
        json.loads(line)


# --- refusal path ----------------------------------------------------------


def test_anonymize_tree_refuses_on_gitleaks_finding(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import anonymize_tree

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.md").write_text("hello\n", encoding="utf-8")

    dst = tmp_path / "dst"

    def _gitleaks_refuse(*args, **kwargs):
        return ("refuse", {"findings": "stripe-secret-key"})

    with (
        patch("secureclaw.dev.corpus.anonymizer._run_gitleaks", side_effect=_gitleaks_refuse),
        patch("secureclaw.dev.corpus.anonymizer._run_trufflehog", side_effect=_all_pass),
        patch(
            "secureclaw.dev.corpus.anonymizer._run_secureclaw_self_scan",
            side_effect=_all_pass,
        ),
    ):
        report = anonymize_tree(src, dst)

    assert report.refused == 1
    # Final destination NEVER created on refusal.
    assert not (dst / "a.md").exists()
    # Temp file cleaned up — no .sc-anon-tmp lingering.
    leftover = list(dst.rglob("*.sc-anon-tmp"))
    assert leftover == []


# --- skip rules ------------------------------------------------------------


def test_anonymize_tree_skips_symlink(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import anonymize_tree

    src = tmp_path / "src"
    src.mkdir()
    real = tmp_path / "real.md"
    real.write_text("real content\n", encoding="utf-8")
    link = src / "link.md"
    try:
        link.symlink_to(real)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks not supported on this filesystem")

    dst = tmp_path / "dst"
    with (
        patch("secureclaw.dev.corpus.anonymizer._run_gitleaks", side_effect=_all_pass),
        patch("secureclaw.dev.corpus.anonymizer._run_trufflehog", side_effect=_all_pass),
        patch(
            "secureclaw.dev.corpus.anonymizer._run_secureclaw_self_scan",
            side_effect=_all_pass,
        ),
    ):
        report = anonymize_tree(src, dst)
    assert report.skipped >= 1


def test_anonymize_tree_skips_oversized_file(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import anonymize_tree

    src = tmp_path / "src"
    src.mkdir()
    big = src / "big.md"
    big.write_text("X" * 200, encoding="utf-8")

    dst = tmp_path / "dst"
    with (
        patch("secureclaw.dev.corpus.anonymizer._run_gitleaks", side_effect=_all_pass),
        patch("secureclaw.dev.corpus.anonymizer._run_trufflehog", side_effect=_all_pass),
        patch(
            "secureclaw.dev.corpus.anonymizer._run_secureclaw_self_scan",
            side_effect=_all_pass,
        ),
    ):
        report = anonymize_tree(src, dst, max_bytes=100)
    assert report.skipped == 1


def test_anonymize_tree_skips_excluded_glob(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import anonymize_tree

    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.md").write_text("ok\n", encoding="utf-8")
    (src / "bad.expected.json").write_text("{}", encoding="utf-8")

    dst = tmp_path / "dst"
    with (
        patch("secureclaw.dev.corpus.anonymizer._run_gitleaks", side_effect=_all_pass),
        patch("secureclaw.dev.corpus.anonymizer._run_trufflehog", side_effect=_all_pass),
        patch(
            "secureclaw.dev.corpus.anonymizer._run_secureclaw_self_scan",
            side_effect=_all_pass,
        ),
    ):
        report = anonymize_tree(src, dst)
    assert report.processed == 1
    assert (dst / "ok.md").exists()
    assert not (dst / "bad.expected.json").exists()


# --- path safety -----------------------------------------------------------


def test_anonymize_tree_rejects_existing_dst(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import anonymize_tree

    src = tmp_path / "src"
    src.mkdir()
    dst = tmp_path / "dst"
    dst.mkdir()  # already exists

    with pytest.raises(ValueError, match="must not exist"):
        anonymize_tree(src, dst)


def test_anonymize_tree_rejects_dst_inside_src(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import anonymize_tree

    src = tmp_path / "src"
    src.mkdir()
    dst = src / "inner_dst"

    with pytest.raises(ValueError, match="inside <src-dir>|inside src"):
        anonymize_tree(src, dst)


# --- empty source ----------------------------------------------------------


def test_anonymize_tree_empty_source(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import anonymize_tree

    src = tmp_path / "src"
    src.mkdir()
    dst = tmp_path / "dst"

    with (
        patch("secureclaw.dev.corpus.anonymizer._run_gitleaks", side_effect=_all_pass),
        patch("secureclaw.dev.corpus.anonymizer._run_trufflehog", side_effect=_all_pass),
        patch(
            "secureclaw.dev.corpus.anonymizer._run_secureclaw_self_scan",
            side_effect=_all_pass,
        ),
    ):
        report = anonymize_tree(src, dst)
    assert report.processed == 0
    assert report.exit_code() == 0
    assert dst.exists()


# --- residue check -----------------------------------------------------


def test_anonymize_tree_refuses_on_residue_check(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import anonymize_tree

    src = tmp_path / "src"
    src.mkdir()
    # SSN survives all substitutions; residue shape-check should catch it.
    (src / "a.md").write_text("contact 123-45-6789\n", encoding="utf-8")

    dst = tmp_path / "dst"
    with (
        patch("secureclaw.dev.corpus.anonymizer._run_gitleaks", side_effect=_all_pass),
        patch("secureclaw.dev.corpus.anonymizer._run_trufflehog", side_effect=_all_pass),
        patch(
            "secureclaw.dev.corpus.anonymizer._run_secureclaw_self_scan",
            side_effect=_all_pass,
        ),
    ):
        report = anonymize_tree(src, dst)
    assert report.refused == 1


# --- TOCTOU temp-file lifecycle -----------------------------------------


def test_anonymize_tree_removes_temp_file_on_refusal(tmp_path: Path) -> None:
    """No .sc-anon-tmp survives a refusal."""
    from secureclaw.dev.corpus.anonymizer import anonymize_tree

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.md").write_text("hello\n", encoding="utf-8")

    dst = tmp_path / "dst"

    def _refuse(*args, **kwargs):
        return ("refuse", {"findings": "fake"})

    with (
        patch("secureclaw.dev.corpus.anonymizer._run_gitleaks", side_effect=_refuse),
        patch("secureclaw.dev.corpus.anonymizer._run_trufflehog", side_effect=_all_pass),
        patch(
            "secureclaw.dev.corpus.anonymizer._run_secureclaw_self_scan",
            side_effect=_all_pass,
        ),
    ):
        anonymize_tree(src, dst)

    leftover = list(dst.rglob("*.sc-anon-tmp"))
    assert leftover == []


# --- skip non-included extensions -----------------------------------------


def test_anonymize_tree_skips_unincluded_extension(tmp_path: Path) -> None:
    """Spec §7.5: files not matching --include are skipped."""
    from secureclaw.dev.corpus.anonymizer import anonymize_tree

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.md").write_text("hello\n", encoding="utf-8")
    (src / "b.exe").write_bytes(b"binary stuff")

    dst = tmp_path / "dst"

    with (
        patch("secureclaw.dev.corpus.anonymizer._run_gitleaks", side_effect=_all_pass),
        patch("secureclaw.dev.corpus.anonymizer._run_trufflehog", side_effect=_all_pass),
        patch(
            "secureclaw.dev.corpus.anonymizer._run_secureclaw_self_scan",
            side_effect=_all_pass,
        ),
    ):
        report = anonymize_tree(src, dst)
    # .md processed, .exe skipped (not in include globs).
    assert report.processed == 1
    assert (dst / "a.md").exists()
    assert not (dst / "b.exe").exists()


# --- gitleaks abort propagates -------------------------------------------


def test_anonymize_tree_aborts_when_gitleaks_aborts(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import anonymize_tree

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.md").write_text("hello\n", encoding="utf-8")
    dst = tmp_path / "dst"

    def _abort(*args, **kwargs):
        return ("abort", {"reason": "gitleaks not installed"})

    with (
        patch("secureclaw.dev.corpus.anonymizer._run_gitleaks", side_effect=_abort),
        patch("secureclaw.dev.corpus.anonymizer._run_trufflehog", side_effect=_all_pass),
        patch(
            "secureclaw.dev.corpus.anonymizer._run_secureclaw_self_scan",
            side_effect=_all_pass,
        ),
    ):
        report = anonymize_tree(src, dst)
    assert report.aborted is True
    assert report.exit_code() != 0


# --- platform-conditional ---------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32", reason="hardlinks via os.link unreliable on Windows CI"
)
def test_anonymize_tree_skips_hardlink(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.anonymizer import anonymize_tree

    src = tmp_path / "src"
    src.mkdir()
    primary = src / "a.md"
    primary.write_text("hello\n", encoding="utf-8")
    try:
        os.link(primary, src / "b.md")
    except OSError:
        pytest.skip("hardlinks unsupported")

    dst = tmp_path / "dst"
    with (
        patch("secureclaw.dev.corpus.anonymizer._run_gitleaks", side_effect=_all_pass),
        patch("secureclaw.dev.corpus.anonymizer._run_trufflehog", side_effect=_all_pass),
        patch(
            "secureclaw.dev.corpus.anonymizer._run_secureclaw_self_scan",
            side_effect=_all_pass,
        ),
    ):
        report = anonymize_tree(src, dst)
    # Both files have nlink>1 → both skipped.
    assert report.skipped == 2
