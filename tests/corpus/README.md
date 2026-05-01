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
    { "pattern_id": "PI-N06", "line": 7, "confidence_range": [75, 100] }
  ],
  "forbidden_findings": ["PI-001", "PI-027"],
  "mode": "exact",
  "source": "EchoLeak CVE-2025-32711",
  "license": "MIT (own work)",
  "category": "reference_link_exfil",
  "added_in_pr": "#XXX",
  "anonymization": {
    "applied": false
  }
}
```

See `expected-schema.json` for the authoritative schema.

## Privacy invariants

- No real customer paths, names, or business identifiers committed.
- No real credentials. Synthetic test prefixes are explicitly tagged in
  `expected.json` `anonymization` block.
- Anonymization gate enforced by `secureclaw dev corpus add` (PR-C).

## CI gates

- `tests/test_corpus_structure.py` validates layout.
- `tests/test_fixture_schema.py` validates every `expected.json` against
  `expected-schema.json`.
- `tests/test_no_real_credentials.py` runs SecureClaw against the corpus and
  fails on any high-confidence credential finding (dogfooding).
- gitleaks + trufflehog as belt-and-suspenders.
