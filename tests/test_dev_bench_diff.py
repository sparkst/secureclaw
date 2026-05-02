"""Tests for ``secureclaw.dev.bench.diff`` (spec §6.3, §9.4)."""

from __future__ import annotations

from dataclasses import replace
from typing import Tuple


def _make_result(
    *,
    suite: str = "corpus",
    fixtures: Tuple = (),
):  # type: ignore[no-untyped-def]
    from secureclaw.dev.bench.models import (
        SCHEMA_VERSION,
        BenchResult,
        Summary,
    )

    return BenchResult(
        schema_version=SCHEMA_VERSION,
        suite=suite,
        secureclaw_version="1.3.0",
        rule_set_version="1.3.0",
        rule_set_sha256="c" * 64,
        fixtures=list(fixtures),
        summary=Summary.from_fixture_results(list(fixtures)),
    )


def _fr(path: str, klass: str, outcome):  # type: ignore[no-untyped-def]
    from secureclaw.dev.bench.models import FixtureResult

    return FixtureResult(
        path=path,
        klass=klass,
        expected_pattern_ids=("PI-001",) if klass == "positive" else (),
        forbidden_pattern_ids=() if klass == "positive" else ("PI-001",),
        actual_findings=(),
        outcome=outcome,
    )


def test_diff_identical_runs_is_empty() -> None:
    from secureclaw.dev.bench.diff import diff_bench
    from secureclaw.dev.bench.models import Outcome

    base = _make_result(
        fixtures=(_fr("positive/a.md", "positive", Outcome.TRUE_POSITIVE),)
    )
    cur = _make_result(
        fixtures=(_fr("positive/a.md", "positive", Outcome.TRUE_POSITIVE),)
    )
    diff = diff_bench(base, cur)
    assert diff.identical
    assert not diff.is_regression
    assert diff.new_false_positives == ()
    assert diff.new_false_negatives == ()


def test_diff_new_false_negative_is_regression() -> None:
    from secureclaw.dev.bench.diff import diff_bench
    from secureclaw.dev.bench.models import Outcome

    base = _make_result(
        fixtures=(_fr("positive/a.md", "positive", Outcome.TRUE_POSITIVE),)
    )
    cur = _make_result(
        fixtures=(_fr("positive/a.md", "positive", Outcome.FALSE_NEGATIVE),)
    )
    diff = diff_bench(base, cur)
    assert not diff.identical
    assert diff.is_regression
    assert "positive/a.md" in diff.new_false_negatives
    assert diff.recall_delta < 0


def test_diff_new_false_positive_is_regression() -> None:
    from secureclaw.dev.bench.diff import diff_bench
    from secureclaw.dev.bench.models import Outcome

    base = _make_result(
        fixtures=(_fr("negative/b.md", "negative", Outcome.TRUE_NEGATIVE),)
    )
    cur = _make_result(
        fixtures=(_fr("negative/b.md", "negative", Outcome.FALSE_POSITIVE),)
    )
    diff = diff_bench(base, cur)
    assert diff.is_regression
    assert "negative/b.md" in diff.new_false_positives


def test_diff_cleared_false_positive_is_improvement_not_regression() -> None:
    from secureclaw.dev.bench.diff import diff_bench
    from secureclaw.dev.bench.models import Outcome

    base = _make_result(
        fixtures=(_fr("negative/b.md", "negative", Outcome.FALSE_POSITIVE),)
    )
    cur = _make_result(
        fixtures=(_fr("negative/b.md", "negative", Outcome.TRUE_NEGATIVE),)
    )
    diff = diff_bench(base, cur)
    assert not diff.is_regression
    assert "negative/b.md" in diff.cleared_false_positives


def test_diff_cleared_false_negative_is_improvement() -> None:
    from secureclaw.dev.bench.diff import diff_bench
    from secureclaw.dev.bench.models import Outcome

    base = _make_result(
        fixtures=(_fr("positive/a.md", "positive", Outcome.FALSE_NEGATIVE),)
    )
    cur = _make_result(
        fixtures=(_fr("positive/a.md", "positive", Outcome.TRUE_POSITIVE),)
    )
    diff = diff_bench(base, cur)
    assert not diff.is_regression
    assert "positive/a.md" in diff.cleared_false_negatives


def test_diff_threshold_recall_violation() -> None:
    """Recall in current below --threshold-recall is a regression even if no
    fixture changed outcome relative to baseline."""
    from secureclaw.dev.bench.diff import diff_bench
    from secureclaw.dev.bench.models import Outcome

    # Both runs identical and at recall=0.5; threshold=0.95 should violate.
    fixtures = (
        _fr("positive/a.md", "positive", Outcome.TRUE_POSITIVE),
        _fr("positive/b.md", "positive", Outcome.FALSE_NEGATIVE),
    )
    base = _make_result(fixtures=fixtures)
    cur = _make_result(fixtures=fixtures)
    diff = diff_bench(base, cur, threshold_recall=0.95)
    assert diff.is_regression
    assert any("recall" in v for v in diff.threshold_violations)


def test_diff_threshold_fp_violation() -> None:
    from secureclaw.dev.bench.diff import diff_bench
    from secureclaw.dev.bench.models import Outcome

    fixtures = (
        _fr("negative/a.md", "negative", Outcome.TRUE_NEGATIVE),
        _fr("negative/b.md", "negative", Outcome.FALSE_POSITIVE),
    )
    base = _make_result(fixtures=fixtures)
    cur = _make_result(fixtures=fixtures)
    diff = diff_bench(base, cur, threshold_fp=0.05)
    assert diff.is_regression
    assert any("false_positive_rate" in v or "fp" in v for v in diff.threshold_violations)


def test_diff_recall_delta_computed() -> None:
    from secureclaw.dev.bench.diff import diff_bench
    from secureclaw.dev.bench.models import Outcome

    base = _make_result(
        fixtures=(
            _fr("positive/a.md", "positive", Outcome.TRUE_POSITIVE),
            _fr("positive/b.md", "positive", Outcome.TRUE_POSITIVE),
        )
    )
    cur = _make_result(
        fixtures=(
            _fr("positive/a.md", "positive", Outcome.TRUE_POSITIVE),
            _fr("positive/b.md", "positive", Outcome.FALSE_NEGATIVE),
        )
    )
    diff = diff_bench(base, cur)
    assert diff.recall_delta == -0.5  # 1.0 -> 0.5
