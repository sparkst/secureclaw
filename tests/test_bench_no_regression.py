"""CI gate: bench-no-regression vs committed baselines (spec §8 / §9.6).

Re-runs each suite and asserts ``dev bench diff <suite>`` exits 0 (i.e. no
new false-positive or false-negative compared to the committed baseline).

Marked ``@pytest.mark.bench`` so it can be locally skipped via
``pytest -m "not bench"``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_FILE = REPO_ROOT / "secureclaw" / "rules" / "default_rules.json"
CORPUS_ROOT = REPO_ROOT / "tests" / "corpus"
BASELINE_DIR = REPO_ROOT / "tests" / "bench" / "baselines"


@pytest.mark.bench
@pytest.mark.parametrize("suite", ["corpus", "pint-canary", "hackaprompt-canary"])
def test_bench_suite_matches_baseline(suite: str, tmp_path: Path) -> None:
    """For each canonical suite, re-run and diff against the committed baseline."""
    from secureclaw.dev.bench.diff import diff_bench
    from secureclaw.dev.bench.models import BenchResult
    from secureclaw.dev.bench.runner import run_bench

    baseline_path = BASELINE_DIR / f"{suite}.json"
    assert baseline_path.exists(), f"missing baseline: {baseline_path}"

    current = run_bench(
        suite,
        rules_file=RULES_FILE,
        corpus_root=CORPUS_ROOT,
        time_budget_ms=5000,
    )
    baseline = BenchResult.from_dict(json.loads(baseline_path.read_text(encoding="utf-8")))

    diff = diff_bench(baseline, current)
    if diff.is_regression:
        pytest.fail(
            f"bench regression in suite {suite!r}: "
            f"new_fp={list(diff.new_false_positives)}, "
            f"new_fn={list(diff.new_false_negatives)}, "
            f"recall_delta={diff.recall_delta:+.4f}\n"
            f"If this is intentional, run "
            f"`python -m secureclaw dev bench run {suite} && "
            f"python -m secureclaw dev bench baseline {suite} --force` "
            f"and commit the baseline diff alongside the rule change."
        )

    # Also write the run JSON to tmp for easier debugging on failure.
    out = tmp_path / f"{suite}.json"
    out.write_text(json.dumps(current.to_dict(), indent=2), encoding="utf-8")
