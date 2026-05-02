"""Tests for ``secureclaw.dev.bench.models`` (spec §9.1).

TDD red phase: lands BEFORE the models module.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_outcome_enum_exhaustive() -> None:
    """Spec §5: outcome covers all classification states."""
    from secureclaw.dev.bench.models import Outcome

    expected = {
        "true_positive",
        "true_negative",
        "false_positive",
        "false_negative",
        "borderline",
        "regression_pass",
        "regression_fail",
        "dos_pass",
        "dos_fail",
    }
    assert {o.value for o in Outcome} == expected


def test_bench_suite_basic_construction() -> None:
    """BenchSuite carries a name + the corpus root + an optional klass filter."""
    from secureclaw.dev.bench.models import BenchSuite

    s = BenchSuite(name="corpus", corpus_root=Path("tests/corpus"), benchmark_subdir=None)
    assert s.name == "corpus"
    assert s.corpus_root == Path("tests/corpus")
    assert s.benchmark_subdir is None


def test_bench_suite_pint_canary_has_subdir() -> None:
    from secureclaw.dev.bench.models import BenchSuite

    s = BenchSuite(
        name="pint-canary",
        corpus_root=Path("tests/corpus"),
        benchmark_subdir="benchmarks/pint",
    )
    assert s.benchmark_subdir == "benchmarks/pint"


def test_bench_result_round_trip_minimal() -> None:
    """BenchResult <-> dict round-trip preserves shape per spec §5."""
    from secureclaw.dev.bench.models import BenchResult, FixtureResult, Outcome, Summary

    r = BenchResult(
        schema_version=1,
        suite="corpus",
        secureclaw_version="1.3.0",
        rule_set_version="1.3.0",
        rule_set_sha256="a" * 64,
        fixtures=[
            FixtureResult(
                path="positive/foo.md",
                klass="positive",
                expected_pattern_ids=("PI-001",),
                forbidden_pattern_ids=(),
                actual_findings=({"pattern_id": "PI-001", "line": 3, "confidence": 65},),
                outcome=Outcome.TRUE_POSITIVE,
            )
        ],
        summary=Summary(
            fixtures_total=1,
            true_positives=1,
            true_negatives=0,
            false_positives=0,
            false_negatives=0,
            borderline=0,
            regression_pass=0,
            dos_pass=0,
            recall=1.0,
            precision=1.0,
            false_positive_rate=0.0,
        ),
    )
    d = r.to_dict()
    # Round-trip via JSON (bench results are persisted as JSON).
    encoded = json.dumps(d)
    r2 = BenchResult.from_dict(json.loads(encoded))
    assert r2 == r
    assert r2.summary.recall == 1.0


def test_bench_result_rejects_wrong_schema_version() -> None:
    from secureclaw.dev.bench.models import BenchResult

    bogus = {
        "schema_version": 99,
        "suite": "corpus",
        "secureclaw_version": "1.3.0",
        "rule_set_version": "1.3.0",
        "rule_set_sha256": "a" * 64,
        "fixtures": [],
        "summary": {
            "fixtures_total": 0,
            "true_positives": 0,
            "true_negatives": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "borderline": 0,
            "regression_pass": 0,
            "dos_pass": 0,
            "recall": 0.0,
            "precision": 0.0,
            "false_positive_rate": 0.0,
        },
    }
    with pytest.raises(ValueError, match="schema_version"):
        BenchResult.from_dict(bogus)


def test_summary_recall_calculation() -> None:
    """Recall = TP / (TP + FN). Spec §5."""
    from secureclaw.dev.bench.models import Summary

    s = Summary.compute(
        true_positives=8,
        true_negatives=10,
        false_positives=2,
        false_negatives=2,
        borderline=0,
        regression_pass=0,
        dos_pass=0,
    )
    assert s.recall == pytest.approx(8 / 10)
    # Precision = TP / (TP + FP)
    assert s.precision == pytest.approx(8 / 10)
    # FP-rate = FP / (FP + TN)
    assert s.false_positive_rate == pytest.approx(2 / 12)
    assert s.fixtures_total == 22


def test_summary_handles_zero_division() -> None:
    """Empty input must not raise; recall/precision default to 1.0 (no positives to miss)."""
    from secureclaw.dev.bench.models import Summary

    s = Summary.compute(
        true_positives=0,
        true_negatives=0,
        false_positives=0,
        false_negatives=0,
        borderline=0,
        regression_pass=0,
        dos_pass=0,
    )
    # When there are no positives at all, recall is undefined; we choose 1.0.
    assert s.recall == 1.0
    assert s.precision == 1.0
    assert s.false_positive_rate == 0.0
    assert s.fixtures_total == 0


def test_bench_diff_dataclass_basic() -> None:
    from secureclaw.dev.bench.models import BenchDiff

    d = BenchDiff(
        suite="corpus",
        identical=True,
        new_false_positives=(),
        new_false_negatives=(),
        cleared_false_positives=(),
        cleared_false_negatives=(),
        recall_delta=0.0,
        precision_delta=0.0,
        false_positive_rate_delta=0.0,
        threshold_violations=(),
    )
    assert d.is_regression is False


def test_bench_diff_regression_when_new_fn() -> None:
    from secureclaw.dev.bench.models import BenchDiff

    d = BenchDiff(
        suite="corpus",
        identical=False,
        new_false_positives=(),
        new_false_negatives=("positive/foo.md",),
        cleared_false_positives=(),
        cleared_false_negatives=(),
        recall_delta=-0.1,
        precision_delta=0.0,
        false_positive_rate_delta=0.0,
        threshold_violations=(),
    )
    assert d.is_regression is True


def test_bench_diff_regression_when_threshold_violation() -> None:
    from secureclaw.dev.bench.models import BenchDiff

    d = BenchDiff(
        suite="corpus",
        identical=True,
        new_false_positives=(),
        new_false_negatives=(),
        cleared_false_positives=(),
        cleared_false_negatives=(),
        recall_delta=0.0,
        precision_delta=0.0,
        false_positive_rate_delta=0.0,
        threshold_violations=("recall 0.92 < 0.95",),
    )
    assert d.is_regression is True
