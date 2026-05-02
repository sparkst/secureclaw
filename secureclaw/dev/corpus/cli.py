"""Argparse sub-subparsers and dispatch for ``secureclaw dev corpus *``.

Spec §6, §10. Each verb (add / list / validate / anonymize / set-pr-number)
is its own sub-subparser. ``dispatch(args)`` routes the parsed namespace
to the backing module.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from secureclaw.dev.corpus.adder import add_fixture, set_pr_number
from secureclaw.dev.corpus.anonymizer import anonymize_tree
from secureclaw.dev.corpus.loader import load_fixtures
from secureclaw.dev.corpus.validator import validate_corpus

_VALID_CLASSES = ("positive", "negative", "borderline", "regression", "dos")


def attach(corpus_parser: argparse.ArgumentParser) -> None:
    """Attach all corpus sub-subparsers to ``corpus_parser``."""
    sub = corpus_parser.add_subparsers(dest="corpus_verb", required=True)

    # `add`
    p_add = sub.add_parser("add", help="Add a fixture to tests/corpus/")
    p_add.add_argument("content_path", type=str, help="Path to the content file to add")
    p_add.add_argument(
        "--class",
        dest="klass",
        choices=_VALID_CLASSES,
        required=True,
        help="Fixture class",
    )
    p_add.add_argument(
        "--source-attestation",
        dest="source_attestation",
        required=True,
        help="Provenance text (CVE, advisory URL, or 'own work')",
    )
    p_add.add_argument("--license", dest="license", required=True, help="License of the content")
    p_add.add_argument("--pattern-id", dest="pattern_id", default=None)
    p_add.add_argument("--line", type=int, default=None)
    p_add.add_argument("--confidence-low", dest="confidence_low", type=int, default=75)
    p_add.add_argument("--confidence-high", dest="confidence_high", type=int, default=100)
    p_add.add_argument("--mode", choices=("exact", "superset", "subset"), default=None)
    p_add.add_argument("--category", default=None)
    p_add.add_argument("--regression-of", dest="regression_of", default=None)
    p_add.add_argument("--regression-group", dest="regression_group", default=None)
    p_add.add_argument(
        "--perturb",
        action="store_true",
        help="(reserved — not yet implemented in PR-C)",
    )
    p_add.add_argument("--root", default="tests/corpus", help="Corpus root directory")
    p_add.add_argument("--force", action="store_true")
    p_add.add_argument("--json", dest="json", action="store_true")

    # `list`
    p_list = sub.add_parser("list", help="List fixtures under tests/corpus/")
    p_list.add_argument("--class", dest="klass", choices=_VALID_CLASSES, default=None)
    p_list.add_argument("--pattern-id", dest="pattern_id", default=None)
    p_list.add_argument("--root", default="tests/corpus")
    p_list.add_argument("--json", dest="json", action="store_true")

    # `validate`
    p_val = sub.add_parser("validate", help="Validate fixtures against the schema and rules")
    p_val.add_argument("--root", default="tests/corpus")
    p_val.add_argument("--strict", action="store_true")
    p_val.add_argument("--json", dest="json", action="store_true")

    # `anonymize`
    p_anon = sub.add_parser("anonymize", help="Anonymize a tree of files")
    p_anon.add_argument("src", type=str, help="Source directory")
    p_anon.add_argument("dst", type=str, help="Destination directory (must not exist)")
    p_anon.add_argument(
        "--include",
        default=None,
        help="Comma-separated globs to include",
    )
    p_anon.add_argument(
        "--max-bytes",
        dest="max_bytes",
        type=int,
        default=1 * 1024 * 1024,
    )
    p_anon.add_argument("--no-gitleaks", dest="no_gitleaks", action="store_true")
    p_anon.add_argument("--no-trufflehog", dest="no_trufflehog", action="store_true")
    p_anon.add_argument("--scanner-timeout", dest="scanner_timeout", type=int, default=30)
    p_anon.add_argument(
        "--allow-trufflehog-unverified",
        dest="allow_trufflehog_unverified",
        action="store_true",
    )
    p_anon.add_argument("--json", dest="json", action="store_true")

    # `set-pr-number`
    p_set = sub.add_parser("set-pr-number", help="Replace #TBD-C placeholders with the PR number")
    p_set.add_argument("pr_number", type=int)
    p_set.add_argument("--root", default="tests/corpus")
    p_set.add_argument("--dry-run", dest="dry_run", action="store_true")
    p_set.add_argument("--json", dest="json", action="store_true")


def dispatch(args: argparse.Namespace) -> int:
    """Dispatch a parsed namespace to the backing module. Returns exit code."""
    verb = getattr(args, "corpus_verb", None)
    if verb == "add":
        return _cmd_add(args)
    if verb == "list":
        return _cmd_list(args)
    if verb == "validate":
        return _cmd_validate(args)
    if verb == "anonymize":
        return _cmd_anonymize(args)
    if verb == "set-pr-number":
        return _cmd_set_pr_number(args)
    print(f"unknown verb: {verb}", file=sys.stderr)
    return 2


def _cmd_add(args: argparse.Namespace) -> int:
    if getattr(args, "perturb", False):
        print("perturb mode is reserved; not yet implemented", file=sys.stderr)
        return 2
    try:
        add_fixture(
            Path(args.content_path),
            klass=args.klass,
            source_attestation=args.source_attestation,
            license=args.license,
            pattern_id=args.pattern_id,
            line=args.line,
            confidence_low=args.confidence_low,
            confidence_high=args.confidence_high,
            mode=args.mode,
            category=args.category,
            regression_of=args.regression_of,
            regression_group=args.regression_group,
            root=Path(args.root),
            force=args.force,
        )
    except FileExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    fixtures = load_fixtures(
        Path(args.root),
        klass=args.klass,
        pattern_id=args.pattern_id,
    )
    if args.json:
        out = [
            {
                "class": f.klass(),
                "file": f.file,
                "mode": f.mode,
                "expected_findings": [
                    {"pattern_id": ef.pattern_id, "line": ef.line} for ef in f.expected_findings
                ],
                "forbidden_findings": list(f.forbidden_findings),
            }
            for f in fixtures
        ]
        print(json.dumps(out, indent=2))
    else:
        for f in fixtures:
            ef_summary = ",".join(ef.pattern_id for ef in f.expected_findings) or "-"
            fb_summary = ",".join(f.forbidden_findings) or "-"
            print(
                f"{f.klass()}/{f.file}\tmode={f.mode}\texpected={ef_summary}\tforbidden={fb_summary}"
            )
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    errors = validate_corpus(Path(args.root), strict=args.strict)
    real_errors = [e for e in errors if e.severity == "error"]
    warnings = [e for e in errors if e.severity == "warning"]
    if args.json:
        out = {
            "errors": [{"path": str(e.path), "message": e.message} for e in real_errors],
            "warnings": [{"path": str(e.path), "message": e.message} for e in warnings],
        }
        print(json.dumps(out, indent=2))
    else:
        for e in errors:
            label = "ERROR" if e.severity == "error" else "warning"
            print(f"{label}: {e.path}: {e.message}", file=sys.stderr)
    return 1 if real_errors else 0


def _cmd_anonymize(args: argparse.Namespace) -> int:
    include = None
    if args.include:
        include = tuple(g.strip() for g in args.include.split(",") if g.strip())
    try:
        report = anonymize_tree(
            Path(args.src),
            Path(args.dst),
            max_bytes=args.max_bytes,
            include=include,
            no_gitleaks=args.no_gitleaks,
            no_trufflehog=args.no_trufflehog,
            scanner_timeout=args.scanner_timeout,
            allow_trufflehog_unverified=args.allow_trufflehog_unverified,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(
            json.dumps(
                {
                    "processed": report.processed,
                    "refused": report.refused,
                    "skipped": report.skipped,
                    "errors": report.errors,
                    "aborted": report.aborted,
                }
            )
        )
    else:
        print(
            f"processed={report.processed} refused={report.refused} "
            f"skipped={report.skipped} errors={report.errors} aborted={report.aborted}"
        )
    return report.exit_code()


def _cmd_set_pr_number(args: argparse.Namespace) -> int:
    result = set_pr_number(
        Path(args.root),
        args.pr_number,
        dry_run=args.dry_run,
    )
    if args.json:
        print(
            json.dumps(
                {
                    "updated": [str(p) for p in result["updated"]],
                    "skipped": [str(p) for p in result["skipped"]],
                    "errors": [str(p) for p in result["errors"]],
                }
            )
        )
    else:
        for p in result["updated"]:
            print(f"updated: {p}")
        for p in result["skipped"]:
            print(f"skipped: {p}")
        for p in result["errors"]:
            print(f"error: {p}", file=sys.stderr)
    return 1 if result["errors"] else 0
