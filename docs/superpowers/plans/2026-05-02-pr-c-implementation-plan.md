# PR-C — Implementation plan (TDD-ordered)

**Spec:** `docs/superpowers/specs/2026-05-01-pr-c-dev-cli-corpus-design.md`
**Branch:** `feature/dev-cli-corpus`
**Date:** 2026-05-02

## Build sequence

Each step is a separate commit. Test commits land BEFORE corresponding implementation commits per spec §16.1 (TDD discipline).

### Phase 1 — foundation types (no dependencies)

**S1.0** Branch: `git checkout -b feature/dev-cli-corpus` from `main`.

**S1.1** Add deps to `pyproject.toml` `[project.optional-dependencies] dev`:
- `jsonschema>=4.0` (for `test_fixture_schema.py`)
- Register pytest marker: `[tool.pytest.ini_options] markers = ["optional: skip when external binaries unavailable"]`

**S1.2 [TEST FIRST]** Write `tests/test_dev_corpus_models.py` covering spec §13.1:
- `Fixture` dataclass round-trip from valid expected.json dict.
- `Fixture` rejects unknown extra fields.
- `Fixture` accepts §11 optional fields (`upstream_url`, `upstream_commit`, `derived_from`, `regression_of`).
- `ExpectedFinding` validates `pattern_id` regex, `confidence_range[0] <= [1]`, both in `[0, 100]`, `line >= 1`.
- `ValidationError` carries `(path, severity, message)` tuple.
- `RefusalReason` is a Literal type alias importable from the package.
- `AnonymizeReport` constructs and serializes.

Run: `pytest tests/test_dev_corpus_models.py -v` → expect all FAIL/ERROR (modules don't exist).

**S1.3 [IMPL]** Create `secureclaw/dev/corpus/__init__.py`, `models.py`. Implement `Fixture`, `ExpectedFinding`, `ValidationError`, `AnonymizeReport`, `RefusalReason` per spec §4.1. Tests green.

### Phase 2 — schema & loader

**S2.1 [TEST FIRST]** Write `tests/test_dev_corpus_loader.py` covering spec §13.2 — `load_fixtures`, `iter_fixtures`, filter by class/pattern_id, empty root, missing-expected-json warning.

**S2.2 [IMPL]** `secureclaw/dev/corpus/schema.py` (load `expected-schema.json`, expose `validate_against_schema(data)`) + `loader.py` (`load_fixtures`, `iter_fixtures`). Tests green.

**S2.3** Schema bump: extend `tests/corpus/expected-schema.json` with optional `upstream_url`, `upstream_commit`, `derived_from`, `regression_of` (per spec §11). `schema_version` stays 2. Verify existing `test_corpus_structure.py` still passes.

### Phase 3 — validator

**S3.1 [TEST FIRST]** Write `tests/test_dev_corpus_validator.py` covering spec §13.3 — passes on seed, catches missing fields, GPL/AGPL/CC-BY-SA blocklist, allowlist enforcement, line-out-of-range, conditional `upstream_url`/`regression_of` enforcement, empty corpus passes, `--strict` vs warn behavior.

**S3.2 [IMPL]** `secureclaw/dev/corpus/validator.py`. Tests green.

### Phase 4 — adder

**S4.1 [TEST FIRST]** Write `tests/test_dev_corpus_adder.py` covering spec §13.4 — round-trip, refuse-overwrite-without-force, refuse-positive-without-pattern-id, refuse-regression-without-regression-of, GPL rejection at adder layer, hint output, `--perturb` reservation message.

**S4.2 [IMPL]** `secureclaw/dev/corpus/adder.py` + `set_pr_number.py` (for the `set-pr-number` verb per spec §6). Tests green.

### Phase 5 — anonymizer (split per CLAUDE.md >5 SP rule)

**S5a.1 [TEST FIRST]** `tests/test_dev_corpus_anonymizer_substitute.py` — `_substitute()` unit tests: paths, emails (full-address hash), phones, IPs, MACs, Tailscale, data URIs, API key prefixes, PEM line-count preservation (single + multi-block via property-based test using hypothesis), `{N}` interpolation per §7.2a, `\r\n` preservation, `_residue_check()` entropy gate + shape gate.

**S5a.2 [IMPL]** Substitution and residue layer in `anonymizer.py`. Reuses `secureclaw.core.credentials.REAL_TOKEN_PREFIXES`. Tests green.

**S5b.1 [TEST FIRST]** `tests/test_dev_corpus_anonymizer_orchestrator.py` — subprocess mocks for gitleaks/trufflehog: pass, refuse, error, missing binary, timeout, `--allow-trufflehog-unverified` flag, per-file isolated scan_dir lifecycle, `shutil.which` discovery, exit-code disambiguation.

**S5b.2 [IMPL]** Orchestrator (gitleaks + trufflehog + SecureClaw self-scan + post-substitution gates). Tests green.

**S5c.1 [TEST FIRST]** `tests/test_dev_corpus_anonymizer_tree.py` — `anonymize_tree()` skips (symlinks, hardlinks, binaries, oversized, excluded globs); TOCTOU temp-file lifecycle (write→close handle→scan→atomic-rename or unlink); path-canonical dst guards (`tests/../tests/corpus/x` rejected, dst-inside-src rejected, dst-must-not-exist); empty src-dir; disk-full; permission-error; symlink-loop termination; FAT/exFAT cycle fallback; report JSONL well-formed cross-platform.

**S5c.2 [IMPL]** Tree walk, skip rules, report writer in `anonymizer.py`. Tests green.

### Phase 6 — CLI

**S6.1 [TEST FIRST]** Write `tests/test_dev_corpus_cli.py` covering spec §13.6 in full:
- Argparse parses each verb's flags; `--help` lists every flag from §6; `dev corpus` (no verb) exits 2.
- `set-pr-number 42` updates all `#TBD-C` values to `#42` (round-trip via test corpus).
- `set-pr-number --dry-run` prints would-be-updated files and exits 0 without writing.
- Files lacking `#TBD-C` appear in `skipped` list of the report.
- `set-pr-number` exits 1 if any file is unwritable (chmod-000 simulation).

**S6.2 [IMPL]** `secureclaw/dev/corpus/cli.py` with sub-subparsers per spec §10. Update `secureclaw/dev/cli.py` to dispatch `corpus` to `corpus.cli.dispatch`. Tests green.

**S6.3 [TEST FIRST]** `tests/test_dev_corpus_integration.py` covering spec §13.9 — invokes `python -m secureclaw dev corpus list` via subprocess; asserts exit 0 and 15-fixture-count in stdout. Same for `validate`. (Committed CI-runnable assertion, not manual verify.)

**S6.4 [IMPL]** No new code — these integration tests pass once seed corpus + verbs are present. Sequence: this test stays RED until Phase 6.5 (seed corpus) lands.

### Phase 6.5 — seed corpus + supporting docs (moved earlier so Phase 7 CI gates have something to fail against)

**S6.5.1** Author 15 seed fixtures per spec §8 using only existing PI-001..PI-028 rules.

**S6.5.2** Write `tools/install-anonymizer-deps.sh` — gitleaks≥v8.18.0 and trufflehog≥v3.63.0 install for macOS/Linux/Windows.

**S6.5.3** Update `tests/corpus/CONTRIBUTING.md` (v2 two-step workflow + version pins). Update `tests/corpus/README.md` example with new optional fields.

**S6.5.4** Update `THIRD_PARTY_NOTICES.md` with non-synthetic seed fixture sources.

After S6.5, `test_dev_corpus_integration.py` from S6.3 turns green.

### Phase 7 — CI gate tests (TEST FIRST against existing seed corpus)

**S7.1 [TEST FIRST]** Write `tests/test_fixture_schema.py` (spec §9.1) — walks all `**/expected.json`, validates against `expected-schema.json`, fails on any `#TBD-C` placeholder. Initially RED if any fixture has a schema gap (intended); turns green when fixtures are clean.

**S7.2 [TEST FIRST]** Write `tests/test_no_real_credentials.py` (spec §9.2) — runs `scan_file` over corpus content, asserts no credential-class finding ≥75 confidence (excluding `anonymization.applied: true`).

**S7.3 [TEST FIRST]** Write `tests/test_fixture_forbidden_findings.py` (spec §13.7a) — runs `scan_file` over each fixture, asserts no `forbidden_findings` pattern fires above confidence 25.

These three tests initially RED if the seed corpus is wrong; the iterative fix is to adjust fixtures (not the tests) until green.

### Phase 9 — verify + open PR

**S9.1** Run full test suite: `python -m pytest tests/ -v --tb=short`. All green. Run `ruff check secureclaw/ tests/` and `ruff format --check secureclaw/ tests/`. All green.

**S9.2** Manual smoke (also covered by committed S6.3 integration tests): run `secureclaw dev corpus list` and `validate` against the merged tree.

**S9.3** Commit, push, open PR `feature/dev-cli-corpus` → main with the spec link, fixture list, and the two-person CODEOWNERS attestation per CONTRIBUTING.md.

**S9.4** Wait for CI green. Run `secureclaw dev corpus set-pr-number <N>` once PR number known. Force-push the placeholder-update commit.

**S9.5** Merge PR-C.

## Risk register

- **Anonymizer is the biggest module** — ~800 lines plus ~600 lines of tests. If S5 starts diverging from spec, stop and re-spec rather than improvise.
- **Subprocess tests rely on mocking gitleaks/trufflehog stdout** — the orchestrator parsing logic is the load-bearing part; cover it thoroughly with mock JSON fixtures.
- **Cross-platform TOCTOU/file-handle ordering** is Windows-fragile. Test `os.replace` on Windows in CI matrix early.
- **PEM line-count preservation** test is a known correctness trap (round-5 found an off-by-one). Property-based test via `hypothesis` to fuzz N=2..50.

## Story points

Per CLAUDE.md coding scale (0.05..5):

| Phase | Points |
|---|---|
| S1 (foundation) | 0.5 |
| S2 (schema+loader) | 0.5 |
| S3 (validator) | 0.8 |
| S4 (adder) | 0.8 |
| S5 (anonymizer) | 5 |
| S6 (CLI) | 0.5 |
| S7 (CI gates) | 1 |
| S8 (seeds + tools) | 1 |
| S9 (verify+PR) | 0.3 |
| **Total** | **~10 SP** |

Per CLAUDE.md, anything >5 SP must be broken — phase S5 splits into S5a (substitution + residue), S5b (subprocess orchestrator + temp-file lifecycle), S5c (tree-walk + skip rules + report). Each ~2 SP.

## Definition of done — re-asserted from spec §16

- All §13 tests committed RED before corresponding implementation commits.
- 15 seed fixtures committed; `validate` exits 0; `test_fixture_schema.py`, `test_no_real_credentials.py`, `test_fixture_forbidden_findings.py` pass.
- Argparse subparser-per-verb restructure replaces stub.
- Schema bump applied; `test_corpus_structure.py` still passes.
- `tools/install-anonymizer-deps.sh` exists and is documented in CONTRIBUTING.md.
- `pyproject.toml` registers the `optional` pytest marker.
- CI green on Linux/macOS/Windows × Python 3.9-3.13.
- `THIRD_PARTY_NOTICES.md` updated.
- `#TBD-C` placeholders updated to PR number before merge.
- Two-person CODEOWNERS attestation per CONTRIBUTING.md.
