"""Argparse subparsers and dispatch for `secureclaw dev`.

Spec §10. The `corpus` block uses sub-subparsers (one per verb) so each
verb can carry its own flags. Other verbs (`rule`, `bench`, `fed`, `sync`,
`triage`) keep their stub structure — those PRs will perform the same
restructure.
"""

from __future__ import annotations

import argparse
import sys


def add_dev_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """Attach the `dev` subcommand tree to the top-level parser."""
    dev_parser = subparsers.add_parser(
        "dev",
        help="Internal developer commands (corpus, rule, bench, fed, sync, triage)",
        description=(
            "Internal commands for managing the SecureClaw test corpus, "
            "authoring detection rules, running benchmarks, and dispatching "
            "federated tests. Not for customer use."
        ),
    )
    dev_sub = dev_parser.add_subparsers(dest="dev_command")

    # corpus — sub-subparsers per spec §10 / PR-C.
    corpus_parser = dev_sub.add_parser("corpus", help="Manage tests/corpus/ fixtures")
    # Local import keeps `secureclaw.dev.cli` lightweight when other verbs run.
    from secureclaw.dev.corpus.cli import attach_corpus

    attach_corpus(corpus_parser)

    rule_parser = dev_sub.add_parser("rule", help="Author and validate detection rules")
    # Local import keeps `secureclaw.dev.cli` lightweight when other verbs run.
    from secureclaw.dev.rule.cli import attach_rule

    attach_rule(rule_parser)

    bench_parser = dev_sub.add_parser("bench", help="Run the benchmark suite")
    bench_parser.add_argument(
        "verb",
        nargs="?",
        choices=["run", "diff", "baseline"],
        help="Operation to perform",
    )

    fed_parser = dev_sub.add_parser("fed", help="Dispatch federated test runs")
    fed_parser.add_argument(
        "verb",
        nargs="?",
        choices=["dispatch", "aggregate", "status"],
        help="Operation to perform",
    )

    sync_parser = dev_sub.add_parser("sync", help="Pull upstream rule updates")
    sync_parser.add_argument(
        "verb",
        nargs="?",
        choices=["upstream-fetch", "diff", "propose-pr"],
        help="Operation to perform",
    )

    dev_sub.add_parser("triage", help="Interactive finding classifier")

    return dev_parser


def cmd_dev(args: argparse.Namespace) -> int:
    """Dispatch `secureclaw dev <subcommand>`."""
    sub = getattr(args, "dev_command", None)
    if sub is None:
        print(
            "Usage: secureclaw dev {corpus|rule|bench|fed|sync|triage} <verb>",
            file=sys.stderr,
        )
        return 2

    if sub == "corpus":
        from secureclaw.dev.corpus.cli import dispatch_corpus

        return dispatch_corpus(args)

    if sub == "rule":
        from secureclaw.dev.rule.cli import dispatch_rule

        return dispatch_rule(args)

    print(
        f"secureclaw dev {sub}: scaffolding only in v1.3.0 Foundation. "
        f"Full implementation lands in PR-{_pr_for(sub)}.",
        file=sys.stderr,
    )
    return 0


def _pr_for(sub: str) -> str:
    return {
        "corpus": "C",
        "rule": "D",
        "bench": "E",
        "fed": "v1.3.2",
        "sync": "v1.3.2",
        "triage": "v1.3.2",
    }.get(sub, "?")
