# SecureClaw Test Corpus

This directory holds labeled test fixtures used by SecureClaw's detection
engine, calibration, regression, and benchmark suites.

## Layout

```
tests/corpus/
├── positive/         # Known injections — every fixture MUST trigger ≥1 finding
├── negative/         # Benign content — every fixture MUST trigger ZERO findings
├── borderline/       # Judgment calls — used for confidence-tier exercises
├── regression/       # Locked test cases per reported bug
│   └── lauren/       # Lauren's customer-test FPs (anonymized)
├── dos/              # Adversarial inputs — must complete within DoS budget
├── benchmarks/
│   ├── pint/         # Lakera PINT — vendored at pinned commit
│   └── hackaprompt/  # HackAPrompt subset — vendored at pinned commit
└── CONTRIBUTING.md   # How to add fixtures
```

## Fixture format

Each fixture file (e.g., `positive/echoleak_ref_markdown.md`) is co-located with
an `expected.json` describing the expected scan outcome:

```json
{
  "schema_version": 2,
  "file": "echoleak_ref_markdown.md",
  "expected_findings": [
    { "pattern_id": "PI-005", "line": 7, "confidence_range": [25, 100] }
  ],
  "forbidden_findings": ["PI-001", "PI-027"],
  "mode": "exact",
  "source": "EchoLeak CVE-2025-32711",
  "license": "MIT (own work)",
  "category": "reference_link_exfil",
  "added_in_pr": "#TBD-C",
  "regression_of": "Issue #99",
  "upstream_url": "https://example.com/cve-page",
  "anonymization": {
    "applied": false
  }
}
```

Optional fields per spec §11:

- `upstream_url` — required when `license` is non-synthetic.
- `upstream_commit` — pinned commit on the upstream repo.
- `derived_from` — name + version of source corpus.
- `regression_of` — required when fixture is under `regression/`.

See `expected-schema.json` for the authoritative schema.

## Privacy invariants

- No real customer paths, names, or business identifiers committed.
- No real credentials. Synthetic test prefixes are explicitly tagged in
  `expected.json` `anonymization` block.
- Anonymization gate enforced by `secureclaw dev corpus add` (PR-C).

## CI gates

- `tests/test_corpus_structure.py` validates layout.
- `tests/test_fixture_schema.py` validates every `expected.json` against
  `expected-schema.json` and rejects committed `#TBD-C` placeholders
  after merge.
- `tests/test_no_real_credentials.py` runs SecureClaw against the corpus and
  fails on any high-confidence credential finding (dogfooding).
- `tests/test_fixture_forbidden_findings.py` runs the scanner over each
  fixture and asserts no `forbidden_findings` pattern fires above
  confidence 25.
- gitleaks + trufflehog as belt-and-suspenders (`@pytest.mark.optional`,
  skipped when binaries are unavailable).

## Verbs

- `secureclaw dev corpus list` — list all fixtures.
- `secureclaw dev corpus validate [--strict]` — validate against schema
  and rules.
- `secureclaw dev corpus add` — add a (cleaned) fixture. See
  `CONTRIBUTING.md`.
- `secureclaw dev corpus anonymize <src> <dst>` — anonymize a tree.
- `secureclaw dev corpus set-pr-number <N>` — replace `#TBD-C`
  placeholders once the PR is open.
