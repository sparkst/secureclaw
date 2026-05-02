"""Argparse sub-subparsers and dispatch for ``secureclaw dev bench *``.

Public names are :func:`attach_bench` and :func:`dispatch_bench` (NOT
``attach``/``dispatch``) so the standalone bundler doesn't alias-collide
with the corpus and rule modules' same-named callables — the trap PR-C
and PR-D both fixed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import List, Optional

from secureclaw.dev.bench.baseline import load_baseline, write_baseline
from secureclaw.dev.bench.diff import diff_bench, diff_exit_code, render_diff_text
from secureclaw.dev.bench.runner import known_suites, run_bench

_DEFAULT_RULES = "secureclaw/rules/default_rules.json"
_DEFAULT_CORPUS = "tests/corpus"
_DEFAULT_BASELINE_DIR = "tests/bench/baselines"
_RUNS_CACHE_DIR_ENV_DEFAULT = Path.home() / ".secureclaw" / "runs"
_MAX_CACHED_RUNS = 20


_SUITE_CHOICES = [*known_suites(), "all"]


def attach_bench(bench_parser: argparse.ArgumentParser) -> None:
    """Attach all ``dev bench *`` sub-subparsers to ``bench_parser``."""
    sub = bench_parser.add_subparsers(dest="bench_verb", required=True)

    # `run`
    p_run = sub.add_parser("run", help="Run a benchmark suite and emit a BenchResult JSON")
    p_run.add_argument(
        "suite",
        choices=_SUITE_CHOICES,
        help="Suite name (corpus|pint-canary|hackaprompt-canary|all)",
    )
    p_run.add_argument("--rules-file", dest="rules_file", default=_DEFAULT_RULES)
    p_run.add_argument("--corpus-root", dest="corpus_root", default=_DEFAULT_CORPUS)
    p_run.add_argument("--pattern-id", dest="pattern_id", default=None)
    p_run.add_argument(
        "--out",
        dest="out",
        default=None,
        help="Output path; default ~/.secureclaw/runs/<sha>.json",
    )
    p_run.add_argument(
        "--time-budget",
        dest="time_budget_ms",
        type=int,
        default=5000,
        help="Per-fixture wall-clock budget in milliseconds (default 5000)",
    )
    p_run.add_argument("--json", dest="json", action="store_true")

    # `baseline`
    p_base = sub.add_parser("baseline", help="Promote a run JSON to the canonical baseline")
    p_base.add_argument("suite", choices=_SUITE_CHOICES)
    p_base.add_argument(
        "--from",
        dest="from_path",
        default=None,
        help="Source run JSON; default: latest ~/.secureclaw/runs/*.json",
    )
    p_base.add_argument(
        "--baseline-path",
        dest="baseline_path",
        default=None,
        help="Destination baseline path; default tests/bench/baselines/<suite>.json",
    )
    p_base.add_argument("--force", dest="force", action="store_true")
    p_base.add_argument("--json", dest="json", action="store_true")

    # `diff`
    p_diff = sub.add_parser("diff", help="Diff a run against the canonical baseline")
    p_diff.add_argument("suite", choices=_SUITE_CHOICES)
    p_diff.add_argument(
        "--baseline-path",
        dest="baseline_path",
        default=None,
        help="Baseline path; default tests/bench/baselines/<suite>.json",
    )
    p_diff.add_argument(
        "--current",
        dest="current_path",
        default=None,
        help="Current run JSON; default: latest ~/.secureclaw/runs/*.json",
    )
    p_diff.add_argument(
        "--threshold-recall",
        dest="threshold_recall",
        type=float,
        default=None,
    )
    p_diff.add_argument(
        "--threshold-fp",
        dest="threshold_fp",
        type=float,
        default=None,
    )
    p_diff.add_argument("--json", dest="json", action="store_true")


def dispatch_bench(args: argparse.Namespace) -> int:
    """Route a parsed namespace to a backing command. Returns exit code."""
    verb = getattr(args, "bench_verb", None)
    if verb == "run":
        return _cmd_run(args)
    if verb == "baseline":
        return _cmd_baseline(args)
    if verb == "diff":
        return _cmd_diff(args)
    print(f"unknown bench verb: {verb}", file=sys.stderr)
    return 2


# --- helpers ---------------------------------------------------------------


def _runs_cache_dir() -> Path:
    """Per-user run cache. Override with SECURECLAW_RUNS_DIR for tests."""
    import os

    override = os.environ.get("SECURECLAW_RUNS_DIR")
    if override:
        return Path(override)
    return _RUNS_CACHE_DIR_ENV_DEFAULT


def _default_baseline_path(suite: str) -> Path:
    return Path(_DEFAULT_BASELINE_DIR) / f"{suite}.json"


def _resolve_run_path(suite: str, rules_file: Path) -> Path:
    """Default run output path: ``~/.secureclaw/runs/<suite>-<sha8>.json``."""
    sha8 = hashlib.sha256(rules_file.read_bytes()).hexdigest()[:8]
    return _runs_cache_dir() / f"{suite}-{sha8}.json"


def _purge_old_runs(cache_dir: Path, keep: int = _MAX_CACHED_RUNS) -> None:
    """Best-effort cap on the per-user run cache (spec §12 risk row)."""
    if not cache_dir.is_dir():
        return
    runs = sorted(
        cache_dir.glob("*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for old in runs[keep:]:
        try:
            old.unlink()
        except OSError:
            pass


def _latest_run(cache_dir: Path, suite: Optional[str] = None) -> Optional[Path]:
    if not cache_dir.is_dir():
        return None
    pattern = f"{suite}-*.json" if suite else "*.json"
    candidates = list(cache_dir.glob(pattern))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _expand_suites(suite_arg: str) -> List[str]:
    if suite_arg == "all":
        return list(known_suites())
    return [suite_arg]


# --- run -------------------------------------------------------------------


def _cmd_run(args: argparse.Namespace) -> int:
    rules_file = Path(args.rules_file)
    corpus_root = Path(args.corpus_root)
    if not rules_file.exists():
        print(f"error: rules file not found: {rules_file}", file=sys.stderr)
        return 2

    suites = _expand_suites(args.suite)

    cache_dir = _runs_cache_dir()

    last_path: Optional[Path] = None
    for suite in suites:
        try:
            result = run_bench(
                suite,
                rules_file=rules_file,
                corpus_root=corpus_root,
                pattern_id=args.pattern_id,
                time_budget_ms=args.time_budget_ms,
            )
        except (ValueError, FileNotFoundError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        # Determine output path. Single-suite + --out wins; multi-suite ignores
        # --out (would be ambiguous) and writes one file per suite into cache.
        if args.out and len(suites) == 1:
            out_path = Path(args.out)
        else:
            cache_dir.mkdir(parents=True, exist_ok=True)
            out_path = _resolve_run_path(suite, rules_file)

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        last_path = out_path

        if args.json:
            print(json.dumps(result.to_dict()))
        else:
            s = result.summary
            print(
                f"bench[{suite}] fixtures={s.fixtures_total} "
                f"TP={s.true_positives} TN={s.true_negatives} "
                f"FP={s.false_positives} FN={s.false_negatives} "
                f"recall={s.recall:.4f} precision={s.precision:.4f} "
                f"fp_rate={s.false_positive_rate:.4f} -> {out_path}"
            )

    if last_path is not None and last_path.parent == cache_dir:
        _purge_old_runs(cache_dir)
    return 0


# --- baseline --------------------------------------------------------------


def _cmd_baseline(args: argparse.Namespace) -> int:
    suite = args.suite
    if suite == "all":
        # Promote each suite's latest run.
        rc = 0
        for s in known_suites():
            sub_args = argparse.Namespace(**vars(args))
            sub_args.suite = s
            rc = max(rc, _cmd_baseline(sub_args))
        return rc

    cache_dir = _runs_cache_dir()
    src = (
        Path(args.from_path)
        if args.from_path
        else _latest_run(cache_dir, suite=suite) or _latest_run(cache_dir)
    )
    if src is None or not src.exists():
        print(
            "error: no run JSON found; pass --from <path> or run "
            "`secureclaw dev bench run <suite>` first",
            file=sys.stderr,
        )
        return 2

    dst = Path(args.baseline_path) if args.baseline_path else _default_baseline_path(suite)

    try:
        result = load_baseline(src)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        write_baseline(result, dst, force=args.force)
    except FileExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({"suite": suite, "baseline_path": str(dst)}))
    else:
        print(f"baseline[{suite}] promoted from {src} -> {dst}")
    return 0


# --- diff ------------------------------------------------------------------


def _cmd_diff(args: argparse.Namespace) -> int:
    suite = args.suite
    if suite == "all":
        rc = 0
        for s in known_suites():
            sub_args = argparse.Namespace(**vars(args))
            sub_args.suite = s
            rc = max(rc, _cmd_diff(sub_args))
        return rc

    baseline_path = (
        Path(args.baseline_path) if args.baseline_path else _default_baseline_path(suite)
    )
    if not baseline_path.exists():
        print(f"error: baseline not found: {baseline_path}", file=sys.stderr)
        return 2

    cache_dir = _runs_cache_dir()
    cur_path = (
        Path(args.current_path)
        if args.current_path
        else _latest_run(cache_dir, suite=suite) or _latest_run(cache_dir)
    )
    if cur_path is None or not cur_path.exists():
        print(
            "error: no current run found; pass --current <path> or run "
            "`secureclaw dev bench run <suite>` first",
            file=sys.stderr,
        )
        return 2

    try:
        baseline = load_baseline(baseline_path)
        current = load_baseline(cur_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    diff = diff_bench(
        baseline,
        current,
        threshold_recall=args.threshold_recall,
        threshold_fp=args.threshold_fp,
    )

    if args.json:
        out = {
            "suite": diff.suite,
            "identical": diff.identical,
            "is_regression": diff.is_regression,
            "new_false_positives": list(diff.new_false_positives),
            "new_false_negatives": list(diff.new_false_negatives),
            "cleared_false_positives": list(diff.cleared_false_positives),
            "cleared_false_negatives": list(diff.cleared_false_negatives),
            "recall_delta": diff.recall_delta,
            "precision_delta": diff.precision_delta,
            "false_positive_rate_delta": diff.false_positive_rate_delta,
            "threshold_violations": list(diff.threshold_violations),
        }
        print(json.dumps(out, indent=2))
    else:
        print(render_diff_text(diff))

    return diff_exit_code(diff)
