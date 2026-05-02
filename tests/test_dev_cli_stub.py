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


def test_dev_corpus_returns_zero_on_stub(monkeypatch, tmp_path) -> None:
    """PR-C replaces the corpus stub with a real implementation.

    `dev corpus list` against an empty root exits 0.
    """
    parser = build_parser()
    args = parser.parse_args(["dev", "corpus", "list", "--root", str(tmp_path)])
    rc = cmd_dev(args)
    assert rc == 0


def test_dev_rule_returns_zero_on_stub() -> None:
    parser = build_parser()
    args = parser.parse_args(["dev", "rule", "validate"])
    rc = cmd_dev(args)
    assert rc == 0


def test_dev_bench_run_no_suite_exits_2() -> None:
    """PR-E replaces the bench stub with a real implementation. ``run`` now
    requires a positional <suite>; calling without it triggers argparse exit."""
    import pytest

    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["dev", "bench", "run"])
    assert exc.value.code == 2


def test_dev_no_subcommand_returns_two() -> None:
    parser = build_parser()
    args = parser.parse_args(["dev"])
    rc = cmd_dev(args)
    assert rc == 2


def test_dev_message_mentions_scaffolding(capsys) -> None:
    """Stubbed verbs (fed/sync/triage) still print a scaffolding hint.

    PR-C replaced corpus, PR-D replaced rule, PR-E replaced bench. This test
    now uses ``fed`` (still stubbed) to verify the scaffolding message.
    """
    parser = build_parser()
    args = parser.parse_args(["dev", "fed", "dispatch"])
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
