"""CLI tests for `secureclaw dev corpus *` (spec §13.6).

TDD red phase: lands BEFORE the cli module rewrite.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _build_parser():
    """Build top-level secureclaw parser (mirrors secureclaw.cli)."""
    import argparse

    from secureclaw.dev.cli import add_dev_parser

    p = argparse.ArgumentParser(prog="secureclaw")
    sub = p.add_subparsers(dest="command")
    add_dev_parser(sub)
    return p


# --- argparse plumbing -----------------------------------------------------


def test_dev_corpus_no_verb_exits_2() -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["dev", "corpus"])
    assert exc.value.code == 2


def test_dev_corpus_help_lists_subverbs(capsys) -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["dev", "corpus", "--help"])
    out = capsys.readouterr().out
    for verb in ("add", "list", "validate", "anonymize", "set-pr-number"):
        assert verb in out


def test_dev_corpus_add_help_lists_class_and_source_attestation(capsys) -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["dev", "corpus", "add", "--help"])
    out = capsys.readouterr().out
    assert "--class" in out
    assert "--source-attestation" in out
    assert "--license" in out


# --- list ------------------------------------------------------------------


def test_dev_corpus_list_runs_against_root(tmp_path: Path, capsys) -> None:
    """`list` walks the root and prints fixtures."""
    from secureclaw.dev.corpus.cli import dispatch

    # Create a single fixture under a tmp root.
    pos = tmp_path / "positive"
    pos.mkdir()
    (pos / "x.md").write_text("hi", encoding="utf-8")
    (pos / "x.md.expected.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "file": "x.md",
                "mode": "exact",
                "expected_findings": [{"pattern_id": "PI-001"}],
                "source": "own work",
                "license": "MIT (own work)",
            }
        ),
        encoding="utf-8",
    )

    import argparse

    args = argparse.Namespace(
        corpus_verb="list",
        klass=None,
        pattern_id=None,
        root=str(tmp_path),
        json=False,
    )
    code = dispatch(args)
    assert code == 0
    out = capsys.readouterr().out
    assert "x.md" in out


# --- validate --------------------------------------------------------------


def test_dev_corpus_validate_passes_on_clean_root(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.cli import dispatch

    pos = tmp_path / "positive"
    pos.mkdir()
    (pos / "x.md").write_text("hi", encoding="utf-8")
    (pos / "x.md.expected.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "file": "x.md",
                "mode": "exact",
                "source": "own work",
                "license": "MIT (own work)",
            }
        ),
        encoding="utf-8",
    )

    import argparse

    args = argparse.Namespace(
        corpus_verb="validate",
        root=str(tmp_path),
        strict=False,
        json=False,
    )
    code = dispatch(args)
    assert code == 0


def test_dev_corpus_validate_fails_on_bad_license(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.cli import dispatch

    pos = tmp_path / "positive"
    pos.mkdir()
    (pos / "x.md").write_text("hi", encoding="utf-8")
    (pos / "x.md.expected.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "file": "x.md",
                "mode": "exact",
                "source": "Some Project",
                "license": "GPL-3.0",
            }
        ),
        encoding="utf-8",
    )

    import argparse

    args = argparse.Namespace(
        corpus_verb="validate",
        root=str(tmp_path),
        strict=False,
        json=False,
    )
    code = dispatch(args)
    assert code == 1


# --- set-pr-number ---------------------------------------------------------


def test_dev_corpus_set_pr_number_updates_files(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.cli import dispatch

    pos = tmp_path / "positive"
    pos.mkdir()
    meta = pos / "x.md.expected.json"
    meta.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "file": "x.md",
                "mode": "exact",
                "source": "own work",
                "license": "MIT (own work)",
                "added_in_pr": "#TBD-C",
            }
        ),
        encoding="utf-8",
    )

    import argparse

    args = argparse.Namespace(
        corpus_verb="set-pr-number",
        pr_number=42,
        root=str(tmp_path),
        dry_run=False,
        json=False,
    )
    code = dispatch(args)
    assert code == 0
    data = json.loads(meta.read_text(encoding="utf-8"))
    assert data["added_in_pr"] == "#42"


def test_dev_corpus_set_pr_number_dry_run_does_not_write(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.cli import dispatch

    pos = tmp_path / "positive"
    pos.mkdir()
    meta = pos / "x.md.expected.json"
    meta.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "file": "x.md",
                "mode": "exact",
                "source": "own work",
                "license": "MIT (own work)",
                "added_in_pr": "#TBD-C",
            }
        ),
        encoding="utf-8",
    )

    import argparse

    args = argparse.Namespace(
        corpus_verb="set-pr-number",
        pr_number=42,
        root=str(tmp_path),
        dry_run=True,
        json=False,
    )
    code = dispatch(args)
    assert code == 0
    data = json.loads(meta.read_text(encoding="utf-8"))
    assert data["added_in_pr"] == "#TBD-C"  # unchanged


def test_dev_corpus_set_pr_number_json_output(tmp_path: Path, capsys) -> None:
    from secureclaw.dev.corpus.cli import dispatch

    pos = tmp_path / "positive"
    pos.mkdir()
    (pos / "x.md.expected.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "file": "x.md",
                "mode": "exact",
                "source": "own work",
                "license": "MIT (own work)",
                "added_in_pr": "#TBD-C",
            }
        ),
        encoding="utf-8",
    )

    import argparse

    args = argparse.Namespace(
        corpus_verb="set-pr-number",
        pr_number=42,
        root=str(tmp_path),
        dry_run=True,
        json=True,
    )
    dispatch(args)
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert "updated" in payload


def test_dev_corpus_set_pr_number_skipped_files_listed(tmp_path: Path, capsys) -> None:
    from secureclaw.dev.corpus.cli import dispatch

    pos = tmp_path / "positive"
    pos.mkdir()
    # File has no #TBD-C — should land in skipped.
    (pos / "x.md.expected.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "file": "x.md",
                "mode": "exact",
                "source": "own work",
                "license": "MIT (own work)",
                "added_in_pr": "#7",
            }
        ),
        encoding="utf-8",
    )

    import argparse

    args = argparse.Namespace(
        corpus_verb="set-pr-number",
        pr_number=42,
        root=str(tmp_path),
        dry_run=False,
        json=True,
    )
    dispatch(args)
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert "skipped" in payload
    assert any("x.md" in p for p in payload["skipped"])
