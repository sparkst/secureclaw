"""``secureclaw.dev.bench`` — benchmark runner, baselines, and diffs.

Public surface (PR-E, spec §4.1).
"""

from __future__ import annotations

from secureclaw.dev.bench.baseline import load_baseline, write_baseline
from secureclaw.dev.bench.diff import diff_bench
from secureclaw.dev.bench.models import (
    BenchDiff,
    BenchResult,
    BenchSuite,
    FixtureResult,
    Outcome,
    Summary,
)
from secureclaw.dev.bench.runner import run_bench

__all__ = [
    "BenchDiff",
    "BenchResult",
    "BenchSuite",
    "FixtureResult",
    "Outcome",
    "Summary",
    "diff_bench",
    "load_baseline",
    "run_bench",
    "write_baseline",
]
