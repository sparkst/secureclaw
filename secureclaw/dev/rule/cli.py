"""Argparse sub-subparsers and dispatch for ``secureclaw dev rule *`` (spec §6, §10).

Public names are :func:`attach_rule` and :func:`dispatch_rule` (NOT
``attach``/``dispatch``) so the standalone bundler doesn't alias-collide
with the corpus module's same-named callables — a bug PR-C had to fix.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from secureclaw.dev.rule.runner import test_all_rules, test_rule
from secureclaw.dev.rule.scaffolder import scaffold_rule
from secureclaw.dev.rule.validator import validate_rules

_DEFAULT_RULES = "secureclaw/rules/default_rules.json"
_DEFAULT_CORPUS = "tests/corpus"


def attach_rule(rule_parser: argparse.ArgumentParser) -> None:
    """Attach all `dev rule *` sub-subparsers to ``rule_parser``."""
    sub = rule_parser.add_subparsers(dest="rule_verb", required=True)

    # `new`
    p_new = sub.add_parser("new", help="Scaffold a new detection rule")
    p_new.add_argument("rule_id", type=str, help="Rule id (e.g. PI-N06)")
    p_new.add_argument("--name", required=True)
    p_new.add_argument("--category", required=True)
    p_new.add_argument(
        "--severity",
        choices=("info", "low", "medium", "high", "critical", "advisory"),
        required=True,
    )
    p_new.add_argument("--regex", required=True)
    p_new.add_argument("--description", required=True)
    p_new.add_argument("--remediation", required=True)
    p_new.add_argument("--source", required=True, help="Provenance text")
    p_new.add_argument("--license", required=True, help="License of the source")
    p_new.add_argument("--upstream-url", dest="upstream_url", default=None)
    p_new.add_argument("--upstream-commit", dest="upstream_commit", default=None)
    p_new.add_argument("--derived-from", dest="derived_from", default=None)
    p_new.add_argument(
        "--applies-to",
        dest="applies_to",
        default=None,
        help="Comma-separated list (default: any)",
    )
    p_new.add_argument(
        "--region-kinds",
        dest="region_kinds",
        default=None,
        help="Comma-separated list (default: any)",
    )
    p_new.add_argument(
        "--examples",
        default=None,
        help='Semicolon-separated examples ("ex1;ex2")',
    )
    p_new.add_argument("--rules-file", dest="rules_file", default=_DEFAULT_RULES)
    p_new.add_argument("--corpus-root", dest="corpus_root", default=_DEFAULT_CORPUS)
    p_new.add_argument("--dry-run", dest="dry_run", action="store_true")
    p_new.add_argument("--json", dest="json", action="store_true")

    # `test`
    p_test = sub.add_parser("test", help="Run a rule (or all) against fixtures")
    p_test.add_argument(
        "rule_id_or_all",
        type=str,
        help="Rule id or 'all' to run every rule",
    )
    p_test.add_argument("--rules-file", dest="rules_file", default=_DEFAULT_RULES)
    p_test.add_argument("--corpus-root", dest="corpus_root", default=_DEFAULT_CORPUS)
    p_test.add_argument("--json", dest="json", action="store_true")

    # `validate`
    p_val = sub.add_parser("validate", help="Validate every rule in the file")
    p_val.add_argument("--rules-file", dest="rules_file", default=_DEFAULT_RULES)
    p_val.add_argument("--corpus-root", dest="corpus_root", default=_DEFAULT_CORPUS)
    p_val.add_argument("--strict-attribution", dest="strict_attribution", action="store_true")
    p_val.add_argument("--json", dest="json", action="store_true")


def dispatch_rule(args: argparse.Namespace) -> int:
    """Route a parsed namespace to the backing module. Returns exit code."""
    verb = getattr(args, "rule_verb", None)
    if verb == "new":
        return _cmd_new(args)
    if verb == "test":
        return _cmd_test(args)
    if verb == "validate":
        return _cmd_validate(args)
    print(f"unknown rule verb: {verb}", file=sys.stderr)
    return 2


# --- new -------------------------------------------------------------------


def _split_csv(value):  # type: ignore[no-untyped-def]
    if value is None:
        return None
    return [s.strip() for s in value.split(",") if s.strip()]


def _split_examples(value):  # type: ignore[no-untyped-def]
    if value is None:
        return None
    return [s.strip() for s in value.split(";") if s.strip()]


def _cmd_new(args: argparse.Namespace) -> int:
    try:
        rule = scaffold_rule(
            args.rule_id,
            name=args.name,
            category=args.category,
            severity=args.severity,
            regex=args.regex,
            description=args.description,
            remediation=args.remediation,
            source=args.source,
            license=args.license,
            upstream_url=args.upstream_url,
            upstream_commit=args.upstream_commit,
            derived_from=args.derived_from,
            examples=_split_examples(args.examples),
            applies_to=_split_csv(args.applies_to),
            region_kinds=_split_csv(args.region_kinds),
            rules_file=Path(args.rules_file),
            corpus_root=Path(args.corpus_root),
            dry_run=args.dry_run,
        )
    except (ValueError, FileNotFoundError, FileExistsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"rule_id": rule["id"], "dry_run": args.dry_run}))
    return 0


# --- test ------------------------------------------------------------------


def _print_result_text(result) -> None:  # type: ignore[no-untyped-def]
    pos_pass = sum(1 for p in result.positives if p[1])
    neg_pass = sum(1 for n in result.negatives if n[1])
    status = "PASS" if result.passed else "FAIL"
    print(
        f"RULE {result.rule_id}: {pos_pass}/{len(result.positives)} positive, "
        f"{neg_pass}/{len(result.negatives)} negative -- {status}"
    )
    if not result.passed:
        for path, ok, diag in result.positives:
            if not ok:
                print(f"  positive {path}: {diag}", file=sys.stderr)
        for path, ok, diag in result.negatives:
            if not ok:
                print(f"  negative {path}: {diag}", file=sys.stderr)


def _result_to_dict(result):  # type: ignore[no-untyped-def]
    return {
        "rule_id": result.rule_id,
        "passed": result.passed,
        "positives": [{"path": p[0], "passed": p[1], "diagnostic": p[2]} for p in result.positives],
        "negatives": [{"path": n[0], "passed": n[1], "diagnostic": n[2]} for n in result.negatives],
    }


def _cmd_test(args: argparse.Namespace) -> int:
    target = args.rule_id_or_all
    rules_file = Path(args.rules_file)
    corpus_root = Path(args.corpus_root)
    try:
        if target.lower() == "all":
            results = test_all_rules(rules_file=rules_file, corpus_root=corpus_root)
        else:
            results = [test_rule(target, rules_file=rules_file, corpus_root=corpus_root)]
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([_result_to_dict(r) for r in results], indent=2))
    else:
        for r in results:
            _print_result_text(r)

    return 0 if all(r.passed for r in results) else 1


# --- validate --------------------------------------------------------------


def _cmd_validate(args: argparse.Namespace) -> int:
    rules_file = Path(args.rules_file)
    corpus_root = Path(args.corpus_root)
    errors = validate_rules(
        rules_file,
        corpus_root=corpus_root,
        strict_attribution=args.strict_attribution,
    )
    real_errors = [e for e in errors if e.severity == "error"]
    warnings = [e for e in errors if e.severity == "warning"]
    if args.json:
        out = {
            "errors": [{"rule_id": e.rule_id, "message": e.message} for e in real_errors],
            "warnings": [{"rule_id": e.rule_id, "message": e.message} for e in warnings],
        }
        print(json.dumps(out, indent=2))
    else:
        for e in errors:
            label = "ERROR" if e.severity == "error" else "warning"
            print(f"{label}: {e.rule_id}: {e.message}", file=sys.stderr)
    return 1 if real_errors else 0
