"""Smoke tests for the `secureclaw dev` CLI subcommand stub.

Foundation PR-A: every verb returns 0 with a "scaffolding only" message on
stderr. Full implementations land in PR-C/D/E.
"""

from __future__ import annotations

from secureclaw.cli import build_parser
from secureclaw.dev.cli import cmd_dev


def test_dev_subcommand_present_in_top_parser() -> None:
    parser = build_parser()
    actions = {a.dest: a for a in parser._actions}
    sub = actions.get("command")
    assert sub is not None
    choices = sub.choices
    assert "dev" in choices, "expected 'dev' subcommand in top-level parser"


def test_dev_corpus_returns_zero_on_stub(monkeypatch) -> None:
    parser = build_parser()
    args = parser.parse_args(["dev", "corpus", "list"])
    rc = cmd_dev(args)
    assert rc == 0


def test_dev_rule_returns_zero_on_stub() -> None:
    parser = build_parser()
    args = parser.parse_args(["dev", "rule", "validate"])
    rc = cmd_dev(args)
    assert rc == 0


def test_dev_bench_returns_zero_on_stub() -> None:
    parser = build_parser()
    args = parser.parse_args(["dev", "bench", "run"])
    rc = cmd_dev(args)
    assert rc == 0


def test_dev_no_subcommand_returns_two() -> None:
    parser = build_parser()
    args = parser.parse_args(["dev"])
    rc = cmd_dev(args)
    assert rc == 2


def test_dev_message_mentions_scaffolding(capsys) -> None:
    parser = build_parser()
    args = parser.parse_args(["dev", "corpus", "list"])
    cmd_dev(args)
    captured = capsys.readouterr()
    assert "scaffolding" in captured.err.lower()


def test_dev_help_includes_all_subcommands() -> None:
    parser = build_parser()
    # Trigger help formatting to ensure no argparse errors
    sub = next(a for a in parser._actions if a.dest == "command")
    dev_choice = sub.choices.get("dev")
    assert dev_choice is not None
    dev_sub = next(a for a in dev_choice._actions if a.dest == "dev_command")
    expected = {"corpus", "rule", "bench", "fed", "sync", "triage"}
    assert set(dev_sub.choices.keys()) == expected
