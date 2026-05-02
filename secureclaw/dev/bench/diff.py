"""Bench diff (spec §6.3).

``diff_bench(baseline, current)`` returns a :class:`BenchDiff`. The
CLI-side rendering (unified-diff-style print + exit code) lives in
:func:`render_diff_text` so tests can exercise the dataclass directly.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from secureclaw.dev.bench.models import BenchDiff, BenchResult, FixtureResult, Outcome

_FAILURE_NEGATIVE = {Outcome.FALSE_POSITIVE}
_FAILURE_POSITIVE = {Outcome.FALSE_NEGATIVE}


def _by_path(result: BenchResult) -> Dict[str, FixtureResult]:
    return {fr.path: fr for fr in result.fixtures}


def _categorise_changes(
    baseline: BenchResult, current: BenchResult
) -> Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]:
    base = _by_path(baseline)
    cur = _by_path(current)

    new_fp: List[str] = []
    new_fn: List[str] = []
    cleared_fp: List[str] = []
    cleared_fn: List[str] = []

    all_paths = sorted(set(base) | set(cur))
    for path in all_paths:
        b = base.get(path)
        c = cur.get(path)
        b_outcome = b.outcome if b else None
        c_outcome = c.outcome if c else None
        if b_outcome == c_outcome:
            continue

        # New regressions.
        if c_outcome == Outcome.FALSE_POSITIVE and b_outcome != Outcome.FALSE_POSITIVE:
            new_fp.append(path)
        elif c_outcome == Outcome.FALSE_NEGATIVE and b_outcome != Outcome.FALSE_NEGATIVE:
            new_fn.append(path)

        # Cleared.
        if b_outcome == Outcome.FALSE_POSITIVE and c_outcome != Outcome.FALSE_POSITIVE:
            cleared_fp.append(path)
        elif b_outcome == Outcome.FALSE_NEGATIVE and c_outcome != Outcome.FALSE_NEGATIVE:
            cleared_fn.append(path)

    return tuple(new_fp), tuple(new_fn), tuple(cleared_fp), tuple(cleared_fn)


def diff_bench(
    baseline: BenchResult,
    current: BenchResult,
    *,
    threshold_recall: Optional[float] = None,
    threshold_fp: Optional[float] = None,
) -> BenchDiff:
    """Compare two :class:`BenchResult`s and return a :class:`BenchDiff`.

    The diff is a *regression* iff any new FALSE_POSITIVE or FALSE_NEGATIVE
    appears in ``current``, OR a threshold (recall/FP) is violated.
    """
    new_fp, new_fn, cleared_fp, cleared_fn = _categorise_changes(baseline, current)

    recall_delta = current.summary.recall - baseline.summary.recall
    precision_delta = current.summary.precision - baseline.summary.precision
    fp_rate_delta = current.summary.false_positive_rate - baseline.summary.false_positive_rate

    violations: List[str] = []
    if threshold_recall is not None and current.summary.recall < threshold_recall:
        violations.append(f"recall {current.summary.recall:.4f} < threshold {threshold_recall:.4f}")
    if threshold_fp is not None and current.summary.false_positive_rate > threshold_fp:
        violations.append(
            f"false_positive_rate {current.summary.false_positive_rate:.4f} "
            f"> threshold {threshold_fp:.4f}"
        )

    identical = not (new_fp or new_fn or cleared_fp or cleared_fn) and (
        recall_delta == 0.0 and precision_delta == 0.0 and fp_rate_delta == 0.0
    )

    return BenchDiff(
        suite=current.suite,
        identical=identical,
        new_false_positives=new_fp,
        new_false_negatives=new_fn,
        cleared_false_positives=cleared_fp,
        cleared_false_negatives=cleared_fn,
        recall_delta=recall_delta,
        precision_delta=precision_delta,
        false_positive_rate_delta=fp_rate_delta,
        threshold_violations=tuple(violations),
    )


def render_diff_text(diff: BenchDiff) -> str:
    """Render a :class:`BenchDiff` as a unified-diff-style report (spec §6.3)."""
    lines: List[str] = []
    lines.append(f"--- baseline ({diff.suite})")
    lines.append(f"+++ current  ({diff.suite})")

    if diff.identical and not diff.threshold_violations:
        lines.append("(no changes)")
        return "\n".join(lines)

    if diff.new_false_positives:
        lines.append("New FALSE POSITIVES (regression):")
        for p in diff.new_false_positives:
            lines.append(f"  + {p}")
    if diff.new_false_negatives:
        lines.append("New FALSE NEGATIVES (regression):")
        for p in diff.new_false_negatives:
            lines.append(f"  + {p}")
    if diff.cleared_false_positives:
        lines.append("Cleared FALSE POSITIVES (improvement):")
        for p in diff.cleared_false_positives:
            lines.append(f"  - {p}")
    if diff.cleared_false_negatives:
        lines.append("Cleared FALSE NEGATIVES (improvement):")
        for p in diff.cleared_false_negatives:
            lines.append(f"  - {p}")
    lines.append("Metric deltas (current - baseline):")
    lines.append(f"  recall:              {diff.recall_delta:+.4f}")
    lines.append(f"  precision:           {diff.precision_delta:+.4f}")
    lines.append(f"  false_positive_rate: {diff.false_positive_rate_delta:+.4f}")
    if diff.threshold_violations:
        lines.append("Threshold violations:")
        for v in diff.threshold_violations:
            lines.append(f"  ! {v}")
    return "\n".join(lines)


def diff_exit_code(diff: BenchDiff) -> int:
    """Exit code for ``secureclaw dev bench diff`` per spec §6.3."""
    return 1 if diff.is_regression else 0
