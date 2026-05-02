"""Foundation types for ``secureclaw.dev.bench`` (spec §9.1).

``BenchSuite`` — a named target the runner walks (corpus / pint-canary / etc.).
``FixtureResult`` — per-fixture outcome row.
``Summary`` — derived recall/precision/FP-rate.
``BenchResult`` — top-level container persisted to JSON (spec §5).
``BenchDiff`` — per spec §6.3 (output of ``diff_bench``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = 1


class Outcome(str, Enum):
    """Fixture outcome classes (spec §5)."""

    TRUE_POSITIVE = "true_positive"
    TRUE_NEGATIVE = "true_negative"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    BORDERLINE = "borderline"
    REGRESSION_PASS = "regression_pass"
    REGRESSION_FAIL = "regression_fail"
    DOS_PASS = "dos_pass"
    DOS_FAIL = "dos_fail"


_FAILURE_OUTCOMES = {
    Outcome.FALSE_POSITIVE,
    Outcome.FALSE_NEGATIVE,
    Outcome.REGRESSION_FAIL,
    Outcome.DOS_FAIL,
}


@dataclass(frozen=True)
class BenchSuite:
    """A named benchmark target.

    ``corpus_root`` is the canonical ``tests/corpus/`` root; ``benchmark_subdir``
    is set for the vendored canary suites (``benchmarks/pint``,
    ``benchmarks/hackaprompt``) and ``None`` for the in-corpus seed.
    """

    name: str
    corpus_root: Path
    benchmark_subdir: Optional[str] = None


@dataclass(frozen=True)
class FixtureResult:
    """One fixture row in a :class:`BenchResult` (spec §5)."""

    path: str
    klass: str
    expected_pattern_ids: Tuple[str, ...]
    forbidden_pattern_ids: Tuple[str, ...]
    actual_findings: Tuple[Dict[str, Any], ...]
    outcome: Outcome

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "klass": self.klass,
            "expected_pattern_ids": list(self.expected_pattern_ids),
            "forbidden_pattern_ids": list(self.forbidden_pattern_ids),
            "actual_findings": [dict(f) for f in self.actual_findings],
            "outcome": self.outcome.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FixtureResult":
        return cls(
            path=data["path"],
            klass=data["klass"],
            expected_pattern_ids=tuple(data.get("expected_pattern_ids", [])),
            forbidden_pattern_ids=tuple(data.get("forbidden_pattern_ids", [])),
            actual_findings=tuple(dict(f) for f in data.get("actual_findings", [])),
            outcome=Outcome(data["outcome"]),
        )


@dataclass(frozen=True)
class Summary:
    """Aggregate counts + derived metrics (spec §5)."""

    fixtures_total: int
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    borderline: int
    regression_pass: int
    dos_pass: int
    recall: float
    precision: float
    false_positive_rate: float

    @classmethod
    def compute(
        cls,
        *,
        true_positives: int,
        true_negatives: int,
        false_positives: int,
        false_negatives: int,
        borderline: int,
        regression_pass: int,
        dos_pass: int,
    ) -> "Summary":
        positives_total = true_positives + false_negatives
        if positives_total == 0:
            recall = 1.0
        else:
            recall = true_positives / positives_total

        retrieved = true_positives + false_positives
        if retrieved == 0:
            precision = 1.0
        else:
            precision = true_positives / retrieved

        negatives_total = false_positives + true_negatives
        if negatives_total == 0:
            fp_rate = 0.0
        else:
            fp_rate = false_positives / negatives_total

        total = (
            true_positives
            + true_negatives
            + false_positives
            + false_negatives
            + borderline
            + regression_pass
            + dos_pass
        )
        return cls(
            fixtures_total=total,
            true_positives=true_positives,
            true_negatives=true_negatives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            borderline=borderline,
            regression_pass=regression_pass,
            dos_pass=dos_pass,
            recall=recall,
            precision=precision,
            false_positive_rate=fp_rate,
        )

    @classmethod
    def from_fixture_results(cls, fixtures: List[FixtureResult]) -> "Summary":
        counts: Dict[Outcome, int] = {o: 0 for o in Outcome}
        for fr in fixtures:
            counts[fr.outcome] += 1
        return cls.compute(
            true_positives=counts[Outcome.TRUE_POSITIVE],
            true_negatives=counts[Outcome.TRUE_NEGATIVE],
            false_positives=counts[Outcome.FALSE_POSITIVE]
            + counts[Outcome.REGRESSION_FAIL]
            + counts[Outcome.DOS_FAIL],
            false_negatives=counts[Outcome.FALSE_NEGATIVE],
            borderline=counts[Outcome.BORDERLINE],
            regression_pass=counts[Outcome.REGRESSION_PASS],
            dos_pass=counts[Outcome.DOS_PASS],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fixtures_total": self.fixtures_total,
            "true_positives": self.true_positives,
            "true_negatives": self.true_negatives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "borderline": self.borderline,
            "regression_pass": self.regression_pass,
            "dos_pass": self.dos_pass,
            "recall": self.recall,
            "precision": self.precision,
            "false_positive_rate": self.false_positive_rate,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Summary":
        return cls(
            fixtures_total=data["fixtures_total"],
            true_positives=data["true_positives"],
            true_negatives=data["true_negatives"],
            false_positives=data["false_positives"],
            false_negatives=data["false_negatives"],
            borderline=data["borderline"],
            regression_pass=data["regression_pass"],
            dos_pass=data["dos_pass"],
            recall=float(data["recall"]),
            precision=float(data["precision"]),
            false_positive_rate=float(data["false_positive_rate"]),
        )


@dataclass(frozen=True)
class BenchResult:
    """Top-level bench-result container persisted to JSON (spec §5)."""

    schema_version: int
    suite: str
    secureclaw_version: str
    rule_set_version: str
    rule_set_sha256: str
    fixtures: List[FixtureResult]
    summary: Summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "suite": self.suite,
            "secureclaw_version": self.secureclaw_version,
            "rule_set_version": self.rule_set_version,
            "rule_set_sha256": self.rule_set_sha256,
            "fixtures": [f.to_dict() for f in self.fixtures],
            "summary": self.summary.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BenchResult":
        sv = data.get("schema_version")
        if sv != SCHEMA_VERSION:
            raise ValueError(f"unsupported bench schema_version {sv!r} (expected {SCHEMA_VERSION})")
        return cls(
            schema_version=sv,
            suite=data["suite"],
            secureclaw_version=data["secureclaw_version"],
            rule_set_version=data["rule_set_version"],
            rule_set_sha256=data["rule_set_sha256"],
            fixtures=[FixtureResult.from_dict(f) for f in data.get("fixtures", [])],
            summary=Summary.from_dict(data["summary"]),
        )


@dataclass(frozen=True)
class BenchDiff:
    """Output of :func:`diff_bench` (spec §6.3)."""

    suite: str
    identical: bool
    new_false_positives: Tuple[str, ...]
    new_false_negatives: Tuple[str, ...]
    cleared_false_positives: Tuple[str, ...]
    cleared_false_negatives: Tuple[str, ...]
    recall_delta: float
    precision_delta: float
    false_positive_rate_delta: float
    threshold_violations: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_regression(self) -> bool:
        """A diff is a regression if any new failure or threshold violation appears."""
        return bool(
            self.new_false_positives or self.new_false_negatives or self.threshold_violations
        )
