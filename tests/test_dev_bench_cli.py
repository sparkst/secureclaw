"""Tests for ``secureclaw.dev.bench.cli`` (spec §6, §9.5)."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import pytest


def _build_top_parser() -> argparse.ArgumentParser:
    """Mirror ``secureclaw.cli`` parser construction."""
    from secureclaw.dev.cli import add_dev_parser

    p = argparse.ArgumentParser(prog="secureclaw")
    sub = p.add_subparsers(dest="command")
    add_dev_parser(sub)
    return p


# --- argparse plumbing -----------------------------------------------------


def test_dev_bench_no_verb_exits_2() -> None:
    parser = _build_top_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["dev", "bench"])
    assert exc.value.code == 2


def test_dev_bench_help_lists_subverbs(capsys) -> None:
    parser = _build_top_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["dev", "bench", "--help"])
    out = capsys.readouterr().out
    for verb in ("run", "diff", "baseline"):
        assert verb in out


def test_dev_bench_run_help_lists_flags(capsys) -> None:
    parser = _build_top_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["dev", "bench", "run", "--help"])
    out = capsys.readouterr().out
    for flag in ("--rules-file", "--corpus-root", "--out", "--time-budget", "--json"):
        assert flag in out


def test_dev_bench_diff_help_lists_thresholds(capsys) -> None:
    parser = _build_top_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["dev", "bench", "diff", "--help"])
    out = capsys.readouterr().out
    for flag in ("--threshold-recall", "--threshold-fp"):
        assert flag in out


def test_dev_bench_baseline_help_lists_force(capsys) -> None:
    parser = _build_top_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["dev", "bench", "baseline", "--help"])
    out = capsys.readouterr().out
    assert "--force" in out


# --- attach/dispatch contract (no aliased imports) -------------------------


def test_attach_dispatch_names_are_unaliased() -> None:
    """Per spec §11: must export attach_bench / dispatch_bench (NOT
    attach/dispatch) so the standalone bundler doesn't alias-collide with
    corpus and rule modules."""
    from secureclaw.dev.bench import cli as bench_cli

    assert hasattr(bench_cli, "attach_bench")
    assert hasattr(bench_cli, "dispatch_bench")


# --- end-to-end via subprocess ---------------------------------------------


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_python_m_secureclaw_dev_bench_run_writes_json(tmp_path: Path) -> None:
    out_path = tmp_path / "run.json"
    rules_file = REPO_ROOT / "secureclaw" / "rules" / "default_rules.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "secureclaw",
            "dev",
            "bench",
            "run",
            "corpus",
            "--rules-file",
            str(rules_file),
            "--corpus-root",
            str(REPO_ROOT / "tests" / "corpus"),
            "--out",
            str(out_path),
            "--time-budget",
            "5000",
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    assert out_path.exists()
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["suite"] == "corpus"
    assert isinstance(data["fixtures"], list)


def test_python_m_secureclaw_dev_bench_baseline_refuses_overwrite(
    tmp_path: Path,
) -> None:
    """`bench baseline` should refuse to overwrite an existing file without
    --force."""
    rules_file = REPO_ROOT / "secureclaw" / "rules" / "default_rules.json"
    run_path = tmp_path / "run.json"
    baseline_path = tmp_path / "baseline.json"

    # Step 1: produce a run.
    p1 = subprocess.run(
        [
            sys.executable,
            "-m",
            "secureclaw",
            "dev",
            "bench",
            "run",
            "corpus",
            "--rules-file",
            str(rules_file),
            "--corpus-root",
            str(REPO_ROOT / "tests" / "corpus"),
            "--out",
            str(run_path),
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert p1.returncode == 0, p1.stderr

    # Step 2: promote to baseline.
    p2 = subprocess.run(
        [
            sys.executable,
            "-m",
            "secureclaw",
            "dev",
            "bench",
            "baseline",
            "corpus",
            "--from",
            str(run_path),
            "--baseline-path",
            str(baseline_path),
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert p2.returncode == 0, p2.stderr
    assert baseline_path.exists()

    # Step 3: try again without --force -> exit non-zero.
    p3 = subprocess.run(
        [
            sys.executable,
            "-m",
            "secureclaw",
            "dev",
            "bench",
            "baseline",
            "corpus",
            "--from",
            str(run_path),
            "--baseline-path",
            str(baseline_path),
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert p3.returncode != 0


def test_python_m_secureclaw_dev_bench_diff_identical_exits_zero(
    tmp_path: Path,
) -> None:
    """Running twice with the same rules should yield an identical diff (exit 0)."""
    rules_file = REPO_ROOT / "secureclaw" / "rules" / "default_rules.json"
    run_path = tmp_path / "run.json"
    baseline_path = tmp_path / "baseline.json"

    # Run + promote + run again.
    for path, extra in [(run_path, []), (baseline_path, ["--force"])]:
        cmd = [
            sys.executable,
            "-m",
            "secureclaw",
            "dev",
            "bench",
            "run",
            "corpus",
            "--rules-file",
            str(rules_file),
            "--corpus-root",
            str(REPO_ROOT / "tests" / "corpus"),
            "--out",
            str(path),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
        assert proc.returncode == 0, proc.stderr

    # Diff: baseline vs current
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "secureclaw",
            "dev",
            "bench",
            "diff",
            "corpus",
            "--baseline-path",
            str(baseline_path),
            "--current",
            str(run_path),
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
