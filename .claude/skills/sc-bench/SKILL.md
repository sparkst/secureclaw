---
name: sc-bench
description: "Run SecureClaw benchmark suites and check for regressions. Use when running the scanner against the corpus seed, the vendored PINT canary, or the HackAPrompt canary; recording a new committed baseline; or diffing the current run against the baseline to enforce no-regression gates. Wraps `secureclaw dev bench`."
version: 0.1.0
---

# /sc-bench — SecureClaw Benchmark Runner

## When to invoke

- "run the corpus benchmark"
- "check for regressions vs the baseline"
- "update the bench baseline" (after an intentional rule change)
- "what's the current recall on PINT canary?"

## Verbs

| Intent | Command |
|---|---|
| Run a suite | `secureclaw dev bench run <suite>` where suite ∈ `{corpus, pint-canary, hackaprompt-canary, all}` |
| Diff vs baseline | `secureclaw dev bench diff <suite> [--threshold-recall 0.95] [--threshold-fp 0.05]` |
| Promote latest run to baseline | `secureclaw dev bench baseline <suite> [--from <run-path>] [--force]` |

## Examples

**Run all suites and write per-user run cache:**
```
secureclaw dev bench run all
```
Results land in `~/.secureclaw/runs/<sha>.json`. Always exits 0 — the gate is `bench diff`, not `bench run`.

**Check for regressions (CI invocation):**
```
secureclaw dev bench diff corpus --threshold-recall 0.95 --threshold-fp 0.05
```
Exits 1 if recall drops below 95%, FP-rate exceeds 5%, or any fixture changed outcome vs the committed baseline at `tests/bench/baselines/corpus.json`.

**Update the baseline after an intentional rule tightening:**
```
secureclaw dev bench run corpus
secureclaw dev bench baseline corpus --force
```
The baseline diff appears in your PR; reviewers see exactly which fixtures shifted.

## Notes

- Baselines are canonical in-repo at `tests/bench/baselines/<suite>.json` (committed; reviewable in PRs); the per-user cache at `~/.secureclaw/runs/` is for ergonomics only.
- The CI gate `tests/test_bench_no_regression.py` runs all three suites against committed baselines on every PR (marker: `bench`).
- `bench fetch` for full PINT/HackAPrompt datasets is deferred to v1.3.1; PR-E ships ~50 entries per suite as a vendored canary.
- See `tests/bench/README.md` for the baseline-update procedure.
