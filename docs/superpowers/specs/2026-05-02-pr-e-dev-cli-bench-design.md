# PR-E — `feature/dev-cli-bench` design

**Status:** Draft
**Author:** Claude (under Travis Sparks)
**Date:** 2026-05-02
**Plan reference:** `.review-artifacts/v1.3-plan.md` §D, §J row E, §K, §L
**Branch:** `feature/dev-cli-bench` (off `main`, after PR-D merges)
**Depends on:** PR-C (`secureclaw.dev.corpus`), PR-D (`secureclaw.dev.rule`)

## 1. Purpose

Implement `secureclaw dev bench run|diff|baseline` — the CLI verbs that run the SecureClaw scanner against benchmark suites (the in-corpus seed plus vendored PINT and HackAPrompt subsets), record results as committed baselines, and surface regressions. Per brainstorm Question 2 = A: baselines live **in-repo at `tests/bench/baselines/<name>.json`** as canonical and CI-enforced; per-user run cache lives at `~/.secureclaw/runs/<sha>.json` for `bench diff` ergonomics.

## 2. Authoritative existing scaffolding

| File | Authority for |
|---|---|
| `tests/corpus/benchmarks/{pint,hackaprompt}/` | PR-A skeleton dirs (with `.gitkeep`); PR-E populates with vendored subset fixtures. |
| PR-C public surface | `secureclaw.dev.corpus.{Fixture, load_fixtures, iter_fixtures, KlassType}` — the corpus loader. |
| PR-D public surface | `secureclaw.dev.rule.{validate_rules, RuleValidationError}` — used by `dev bench` to assert rules are well-formed before running. |
| `secureclaw/core/scanner.py` | `scan_file(path, ...)` — used to run the scanner. |
| `secureclaw/rules/default_rules.json` | Canonical rule set. |

## 3. Non-goals

- No fetch from upstream PINT/HackAPrompt repos at run time. PR-E vendors a small canary subset committed in-repo. Full datasets fetched-and-cached in `~/.secureclaw/datasets/` by an opt-in `bench fetch` (deferred to v1.3.1). PR-E ships ~50 PINT + ~50 HackAPrompt vendored entries.
- No federated runs (jarvis/macair). That's plan §E and lands in v1.3.2 (`sc-fed` skill).
- No threshold-based promotion logic. The CI gate is "no regression vs committed baseline." Recall/FP thresholds (≥95% / ≤5%) per plan §K.3 are documented goals but enforced by tooling only via baseline tracking, not by hard threshold gates in PR-E.
- No skill wrappers — those are PR-F.

## 4. Module layout

```
secureclaw/dev/bench/
├── __init__.py        # re-exports: BenchSuite, BenchResult, BenchDiff, run_bench, diff_bench, write_baseline
├── cli.py             # argparse sub-subparsers
├── models.py          # BenchSuite, BenchResult, BenchDiff dataclasses
├── runner.py          # run_bench(suite_name, ...) -> BenchResult
├── baseline.py        # write_baseline, load_baseline
└── pint.py / hackaprompt.py   # dataset loaders for the vendored subsets
```

Tests:
```
tests/
├── test_dev_bench_models.py
├── test_dev_bench_runner.py
├── test_dev_bench_baseline.py
├── test_dev_bench_diff.py
├── test_dev_bench_cli.py
└── bench/
    ├── baselines/
    │   ├── corpus.json         # baseline against tests/corpus/{positive,negative,...}
    │   ├── pint-canary.json    # baseline against the vendored PINT subset
    │   └── hackaprompt-canary.json
    └── README.md               # explains format, update procedure
```

### 4.1 Public surface (`secureclaw.dev.bench.__init__`)

```python
from secureclaw.dev.bench.models import BenchSuite, BenchResult, BenchDiff
from secureclaw.dev.bench.runner import run_bench
from secureclaw.dev.bench.baseline import load_baseline, write_baseline
from secureclaw.dev.bench.diff import diff_bench

__all__ = ["BenchSuite", "BenchResult", "BenchDiff", "run_bench",
           "load_baseline", "write_baseline", "diff_bench"]
```

## 5. Bench result format

`BenchResult` serializes to a JSON object stored at `tests/bench/baselines/<suite>.json` (committed) and at `~/.secureclaw/runs/<sha>.json` (per-user cache):

```json
{
  "schema_version": 1,
  "suite": "corpus",
  "secureclaw_version": "1.3.0",
  "rule_set_version": "1.3.0",
  "rule_set_sha256": "abc123...",
  "fixtures": [
    {
      "path": "positive/instruction_override_basic.md",
      "klass": "positive",
      "expected_pattern_ids": ["PI-001"],
      "forbidden_pattern_ids": [],
      "actual_findings": [
        {"pattern_id": "PI-001", "line": 3, "confidence": 65}
      ],
      "outcome": "true_positive"
    }
  ],
  "summary": {
    "fixtures_total": 15,
    "true_positives": 5,
    "true_negatives": 5,
    "false_positives": 0,
    "false_negatives": 0,
    "borderline": 2,
    "regression_pass": 2,
    "dos_pass": 1,
    "recall": 1.0,
    "precision": 1.0,
    "false_positive_rate": 0.0
  }
}
```

`outcome` is one of `true_positive`, `true_negative`, `false_positive`, `false_negative`, `borderline`, `regression_pass`, `regression_fail`, `dos_pass`, `dos_fail` (timeout). Fixtures with `mode: subset` whose actual findings are within bounds report `borderline`.

## 6. Verbs

### 6.1 `secureclaw dev bench run`

```
secureclaw dev bench run <suite>
    [--rules-file <path>]
    [--corpus-root <path>]
    [--pattern-id <id>]        # restrict to a single pattern
    [--out <path>]             # default: ~/.secureclaw/runs/<sha>.json
    [--time-budget <ms>]       # per-fixture timeout, default 5000
    [--json]
```

`<suite>` is one of:
- `corpus` — runs over `tests/corpus/{positive,negative,borderline,regression,dos}/` (skipping `benchmarks/`).
- `pint-canary` — runs over the vendored PINT subset at `tests/corpus/benchmarks/pint/`.
- `hackaprompt-canary` — vendored HackAPrompt subset.
- `all` — all three above.

Behaviour:
- Loads fixtures via `secureclaw.dev.corpus.load_fixtures(root, klass=...)` for each suite.
- For each fixture, runs `scan_file` on the content with the time-budget (per-fixture timeout via `signal.alarm` on POSIX, threaded watchdog on Windows for cross-platform).
- Compares scanner output against fixture metadata using the `mode` field:
  - `superset` (default for positive): every entry in `expected_findings` must appear in actual findings.
  - `exact` (default for negative): actual findings must equal `expected_findings` (typically empty).
  - `subset` (borderline): actual findings must be a subset of `expected_findings`.
- For all classes, `forbidden_findings` must NOT appear in actual findings ≥ confidence 25.
- Writes a `BenchResult` JSON to `--out` (default: `~/.secureclaw/runs/<sha>.json` where sha = git HEAD).
- Prints a summary table to stdout.
- Exit 0 always (results are not assertions; `bench diff` is the gate).

### 6.2 `secureclaw dev bench baseline`

```
secureclaw dev bench baseline <suite>
    [--from <run-path>]        # default: latest ~/.secureclaw/runs/*.json
    [--baseline-path <path>]   # default: tests/bench/baselines/<suite>.json
    [--force]                  # overwrite existing baseline without prompt
    [--json]
```

Behaviour:
- Loads the source run JSON (`--from`).
- Promotes it to the canonical baseline at `--baseline-path`.
- Refuses overwrite without `--force` (avoid silent drift).
- Writes atomically (temp + `os.replace`).

### 6.3 `secureclaw dev bench diff`

```
secureclaw dev bench diff <suite>
    [--baseline-path <path>]   # default: tests/bench/baselines/<suite>.json
    [--current <run-path>]     # default: latest ~/.secureclaw/runs/*.json
    [--threshold-recall <0..1>]   # exit 1 if recall < this
    [--threshold-fp <0..1>]       # exit 1 if FP-rate > this
    [--json]
```

Behaviour:
- Loads both JSONs.
- Computes a `BenchDiff` summarizing: fixtures that newly false-positive, newly false-negative, recall delta, precision delta, FP-rate delta.
- Prints a unified-diff-style report.
- Exit 0 if (a) no fixtures changed outcome AND (b) thresholds (if provided) satisfied. Exit 1 if any regression. The default invocation (no thresholds) is "any outcome change is a regression."
- For CI use: `dev bench diff corpus --threshold-recall 0.95 --threshold-fp 0.05` is the plan §K.3 gate.

## 7. Vendored benchmark fixtures

**PINT-canary (~50 entries):** Lakera PINT (MIT, https://github.com/lakeraai/pint-benchmark) provides 4314 inputs. PR-E vendors 50 representative entries (5 from each of PINT's 10 categories) at `tests/corpus/benchmarks/pint/<id>.txt` + `<id>.txt.expected.json`. Each `expected.json` declares `mode: subset` (PINT entries don't always have a single canonical pattern_id; subset mode tolerates extra findings) and `source: "Lakera PINT v<sha>"`, `license: "MIT"`, `upstream_url`, `upstream_commit`.

**HackAPrompt-canary (~50 entries):** HackAPrompt (CC-BY, https://github.com/PromptLabs/hackaprompt) provides ~600K prompts. PR-E vendors 50 across categories. Same metadata pattern.

`THIRD_PARTY_NOTICES.md` updated to register both upstream sources.

## 8. CI gate

Add `tests/test_bench_no_regression.py`:
- For each suite in `['corpus', 'pint-canary', 'hackaprompt-canary']`:
  - Runs `secureclaw dev bench run <suite>` to a tmp file.
  - Runs `dev bench diff <suite> --current <tmp>` against the committed baseline.
  - Asserts exit 0.

The test is `@pytest.mark.bench` (a new marker) and runs in CI but can be locally skipped via `pytest -m "not bench"`.

When a rule changes intentionally (e.g., PI-001 regex tightened), the developer:
1. Runs `bench run corpus` and reviews output.
2. If the changes are intended, runs `bench baseline corpus --force` to update the committed baseline.
3. Includes both the rule change and baseline update in the PR; reviewers see the diff in the baseline JSON.

## 9. Test plan (TDD-ordered)

### 9.1 `test_dev_bench_models.py`
- BenchSuite, BenchResult, BenchDiff round-trip to/from JSON.
- `outcome` enum exhaustiveness.
- Summary calculations (recall, precision, FP-rate) match expected math.

### 9.2 `test_dev_bench_runner.py`
- Mock scanner returning various findings → outcome computation correct for each fixture mode.
- `superset` mode: extra findings allowed; missing expected = false_negative.
- `exact` mode for negatives: any actual finding = false_positive.
- `subset` mode for borderline: actual must be ⊆ expected; outcome `borderline` if within bounds.
- `--time-budget` enforcement: simulate slow scan → fixture marked `dos_fail` and overall run continues.
- Forbidden_findings firing ≥ confidence 25 marks the fixture's outcome as a failure type even if expected_findings match.

### 9.3 `test_dev_bench_baseline.py`
- Round-trip: write_baseline → load_baseline returns equal data.
- Refuses overwrite without `--force`.
- Atomic write: simulated failure mid-write leaves baseline unchanged.

### 9.4 `test_dev_bench_diff.py`
- Identical run vs baseline → empty diff, exit 0.
- New false-positive in current → regression, exit 1.
- New false-negative → regression, exit 1.
- Threshold mode: recall drops below `--threshold-recall` → exit 1.
- Improvement (false-positive cleared) → diff shows improvement but exit 0.

### 9.5 `test_dev_bench_cli.py`
- argparse parses each verb's flags; `--help` shows every flag.
- `bench` (no verb) exits 2.
- Integration: `python -m secureclaw dev bench run corpus` produces a JSON file with the right schema.

### 9.6 `test_bench_no_regression.py` (CI gate)
- Per §8.

## 10. Standalone bundler

Update `tools/build_standalone.py` `SECTIONS` (after `("Dev Rule CLI", ...)`, before `("Dev CLI Subcommands", ...)`):
```python
("Dev Bench Models", SRC / "dev" / "bench" / "models.py"),
("Dev Bench Baseline", SRC / "dev" / "bench" / "baseline.py"),
("Dev Bench Runner", SRC / "dev" / "bench" / "runner.py"),
("Dev Bench Diff", SRC / "dev" / "bench" / "diff.py"),
("Dev Bench PINT Loader", SRC / "dev" / "bench" / "pint.py"),
("Dev Bench HackAPrompt Loader", SRC / "dev" / "bench" / "hackaprompt.py"),
("Dev Bench CLI", SRC / "dev" / "bench" / "cli.py"),
```
Verify via `python tools/build_standalone.py && python dist/secureclaw.py dev bench --help`.

## 11. CLI integration

Replace the `bench` stub block in `secureclaw/dev/cli.py` (positional-verb form) with `from secureclaw.dev.bench.cli import attach_bench, dispatch_bench` (no aliases — same standalone-bundler trap PR-C/PR-D avoided). `cmd_dev` dispatches `bench` to `dispatch_bench`.

## 12. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Vendored PINT subset drift from upstream over time. | `expected.json` records `upstream_url` + `upstream_commit`; `bench fetch` (deferred) re-syncs and refreshes baselines. |
| Cross-platform per-fixture time budget: `signal.alarm` not available on Windows. | Implementation uses a threaded watchdog (`threading.Timer` + cooperative cancellation flag) for cross-platform parity; tested on Windows CI. |
| `~/.secureclaw/runs/` cache grows unbounded. | Keep last N runs (default 20), purge oldest on write. Documented in `tests/bench/README.md`. |
| Baseline drift is silent — developer forgets to update after intentional rule change. | The `bench-no-regression` CI gate will fail; PR description must include the baseline update commit. |
| HackAPrompt CC-BY attribution requirements. | `THIRD_PARTY_NOTICES.md` records the upstream license; vendored fixtures include `license: "CC-BY-4.0"` in their `expected.json`. |
| Property-based hypothesis tests on real PINT entries could be slow in CI. | Vendored canary subset is small (50 entries) — full run completes in seconds. |

## 13. Definition of done

- [ ] All §9 tests committed RED before implementation per plan §L.
- [ ] All §6 verbs implemented and pass §9 tests.
- [ ] §7 vendored fixtures committed under `tests/corpus/benchmarks/{pint,hackaprompt}/`.
- [ ] Baselines committed at `tests/bench/baselines/{corpus,pint-canary,hackaprompt-canary}.json`.
- [ ] `secureclaw/dev/cli.py` `bench` block replaced with sub-subparser dispatch (no aliased imports).
- [ ] `tools/build_standalone.py` updated per §10. Verified via local build.
- [ ] `THIRD_PARTY_NOTICES.md` includes Lakera PINT + HackAPrompt entries.
- [ ] `tests/bench/README.md` documents format and update procedure.
- [ ] `pyproject.toml` registers `bench` pytest marker.
- [ ] CI green on Linux/macOS/Windows × Python 3.9-3.13.
- [ ] No new ruff warnings.
- [ ] PR description references plan §J row E and §D CI gates; explicitly notes the deferred `bench fetch` for full datasets.
