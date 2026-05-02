# SecureClaw Benchmarks

This directory holds the **canonical, in-repo** benchmark baselines for the
`secureclaw dev bench` flow (PR-E, spec §5 / §6).

## Layout

```
tests/bench/
├── README.md
└── baselines/
    ├── corpus.json             # baseline against tests/corpus/{positive,...}/
    ├── pint-canary.json        # baseline against tests/corpus/benchmarks/pint/
    └── hackaprompt-canary.json # baseline against tests/corpus/benchmarks/hackaprompt/
```

Per-user run cache lives at `~/.secureclaw/runs/<suite>-<sha8>.json` and is
kept to the most recent 20 runs (older entries auto-purged).

## Schema

Baselines serialize the `BenchResult` dataclass at
`schema_version: 1`:

```json
{
  "schema_version": 1,
  "suite": "corpus",
  "secureclaw_version": "1.2.0",
  "rule_set_version": "1.2.0",
  "rule_set_sha256": "<hex>",
  "fixtures": [
    {
      "path": "positive/instruction_override_basic.md",
      "klass": "positive",
      "expected_pattern_ids": ["PI-001"],
      "forbidden_pattern_ids": [],
      "actual_findings": [{"pattern_id": "PI-001", "line": 1, "confidence": 80}],
      "outcome": "true_positive"
    }
  ],
  "summary": {
    "fixtures_total": 15, "true_positives": 5, "true_negatives": 5,
    "false_positives": 0, "false_negatives": 0, "borderline": 0,
    "regression_pass": 0, "dos_pass": 0,
    "recall": 1.0, "precision": 1.0, "false_positive_rate": 0.0
  }
}
```

The full schema lives at
`secureclaw/dev/bench/models.py` (`BenchResult`).

## Update procedure

Whenever a rule, the corpus, or the engine pipeline changes intentionally
the baselines must be re-promoted. The CI gate (§8) refuses silent drift.

```bash
# 1. Run the suite locally and inspect output.
python -m secureclaw dev bench run corpus
python -m secureclaw dev bench run pint-canary
python -m secureclaw dev bench run hackaprompt-canary

# 2. If the changes are intentional, force-overwrite the canonical baseline.
python -m secureclaw dev bench baseline corpus --force
python -m secureclaw dev bench baseline pint-canary --force
python -m secureclaw dev bench baseline hackaprompt-canary --force

# 3. Commit both the rule/corpus change AND the baseline diff in the same
#    PR so reviewers can audit the recall/precision deltas.
git add tests/bench/baselines/ secureclaw/rules/default_rules.json
git commit -m "feat(rules): tighten PI-001; refresh bench baselines"
```

## CI gate

`tests/test_bench_no_regression.py` (`@pytest.mark.bench`) re-runs each
suite and diffs against the committed baseline. Any new false-positive or
false-negative is a regression and fails CI. Threshold flags
(`--threshold-recall 0.95 --threshold-fp 0.05`) are documented goals per
plan §K.3 but enforced in the dev workflow rather than the gate.

To skip locally: `pytest -m "not bench"`.

## Vendored fixture provenance

The PINT and HackAPrompt canary subsets at
`tests/corpus/benchmarks/{pint,hackaprompt}/` are vendored copies (not
fetched at runtime). Each `expected.json` records the `upstream_url`,
`upstream_commit`, and `license`. The fetch-and-cache flow for the full
upstream datasets is deferred to v1.3.1 (`bench fetch`).
