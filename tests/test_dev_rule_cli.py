"""Tests for ``secureclaw.dev.rule.cli`` (spec §9.6).

TDD red phase: lands BEFORE the cli module rewrite.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


def _build_top_parser():
    """Build the top-level secureclaw parser exactly like ``secureclaw.cli``."""
    import argparse

    from secureclaw.dev.cli import add_dev_parser

    p = argparse.ArgumentParser(prog="secureclaw")
    sub = p.add_subparsers(dest="command")
    add_dev_parser(sub)
    return p


# --- argparse plumbing -----------------------------------------------------


def test_dev_rule_no_verb_exits_2() -> None:
    parser = _build_top_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["dev", "rule"])
    assert exc.value.code == 2


def test_dev_rule_help_lists_subverbs(capsys) -> None:
    parser = _build_top_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["dev", "rule", "--help"])
    out = capsys.readouterr().out
    for verb in ("new", "test", "validate"):
        assert verb in out


def test_dev_rule_new_help_lists_required_flags(capsys) -> None:
    parser = _build_top_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["dev", "rule", "new", "--help"])
    out = capsys.readouterr().out
    for flag in (
        "--name",
        "--category",
        "--severity",
        "--regex",
        "--description",
        "--remediation",
        "--source",
        "--license",
        "--upstream-url",
        "--upstream-commit",
    ):
        assert flag in out, f"missing {flag} in `dev rule new --help`"


def test_dev_rule_test_help_lists_id_argument(capsys) -> None:
    parser = _build_top_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["dev", "rule", "test", "--help"])
    out = capsys.readouterr().out
    assert "--rules-file" in out
    assert "--corpus-root" in out


def test_dev_rule_validate_help_lists_strict_flag(capsys) -> None:
    parser = _build_top_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["dev", "rule", "validate", "--help"])
    out = capsys.readouterr().out
    assert "--strict-attribution" in out


# --- attach_rule / dispatch_rule live in dev.rule.cli ----------------------


def test_attach_rule_and_dispatch_rule_exist() -> None:
    """Per spec §7, the names must be attach_rule / dispatch_rule (NOT
    attach / dispatch) so the standalone bundler doesn't alias-collide
    with the corpus module's attach/dispatch (the bug PR-C hit)."""
    from secureclaw.dev.rule.cli import attach_rule, dispatch_rule

    assert callable(attach_rule)
    assert callable(dispatch_rule)


def test_dev_cli_imports_attach_rule_dispatch_rule_directly() -> None:
    """Verifies dev/cli.py imports attach_rule and dispatch_rule (NOT aliased)."""
    text = (
        Path(__file__)
        .resolve()
        .parent.parent.joinpath("secureclaw", "dev", "cli.py")
        .read_text(encoding="utf-8")
    )
    assert "attach_rule" in text
    assert "dispatch_rule" in text
    # Forbid alias forms that PR-C's bundler bug would re-introduce.
    assert " as attach_rule" not in text
    assert " as dispatch_rule" not in text


# --- Validate verb dispatches end-to-end ------------------------------------


def test_dispatch_rule_validate_against_committed_rules(tmp_path) -> None:
    """`dev rule validate` against committed rules exits 0."""
    parser = _build_top_parser()
    args = parser.parse_args(["dev", "rule", "validate"])
    from secureclaw.dev.cli import cmd_dev

    rc = cmd_dev(args)
    assert rc == 0


def test_dispatch_rule_validate_strict_against_committed_rules() -> None:
    """`dev rule validate --strict-attribution` against committed rules exits
    non-zero (existing rules don't have upstream_url)."""
    parser = _build_top_parser()
    args = parser.parse_args(["dev", "rule", "validate", "--strict-attribution"])
    from secureclaw.dev.cli import cmd_dev

    rc = cmd_dev(args)
    assert rc == 1


# --- New verb: refuses dup id ----------------------------------------------


def test_dispatch_rule_new_refuses_duplicate(tmp_path: Path) -> None:
    """`dev rule new <existing-id>` against a rules file already containing
    that id exits non-zero."""
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "pattern_version": "1.3.1",
                "min_tool_version": "1.3.0",
                "description": "x",
                "patterns": [
                    {
                        "id": "PI-N06",
                        "name": "x",
                        "regex": "x",
                        "severity": "advisory",
                        "category": "x",
                        "description": "x",
                        "remediation": "x",
                        "examples": [],
                        "introduced_in_version": "1.3.1",
                        "applies_to": ["any"],
                        "region_kinds": ["any"],
                        "applies_in_string_literal": False,
                        "applies_in_ai_config": False,
                        "requires_same_sentence_with": [],
                        "boost_on_high_entropy": False,
                        "boost_on_invisible_chars": False,
                        "large_file_safe": False,
                        "sources": [{"source": "own work", "license": "MIT (own work)"}],
                        "license_chain_audited": False,
                        "severity_promotion_evidence": None,
                        "owasp": None,
                        "atlas": None,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    parser = _build_top_parser()
    args = parser.parse_args(
        [
            "dev",
            "rule",
            "new",
            "PI-N06",
            "--name",
            "Dup",
            "--category",
            "x",
            "--severity",
            "advisory",
            "--regex",
            "foo",
            "--description",
            "d",
            "--remediation",
            "r",
            "--source",
            "own work",
            "--license",
            "MIT (own work)",
            "--rules-file",
            str(rules),
            "--corpus-root",
            str(tmp_path / "corpus"),
        ]
    )
    from secureclaw.dev.cli import cmd_dev

    rc = cmd_dev(args)
    assert rc != 0


# --- Integration via subprocess --------------------------------------------


def test_dev_rule_validate_subprocess() -> None:
    """`python -m secureclaw dev rule validate` exits 0 against committed rules."""
    repo_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "-m", "secureclaw", "dev", "rule", "validate"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
