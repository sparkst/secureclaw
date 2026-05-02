# PR-D — `feature/dev-cli-rule` design

**Status:** Draft
**Author:** Claude (under Travis Sparks)
**Date:** 2026-05-02
**Plan reference:** `.review-artifacts/v1.3-plan.md` §C, §C.3, §J row D, §K, §L
**Branch:** `feature/dev-cli-rule` (off `main`, requires PR-C merged first)
**Depends on:** PR-C (`secureclaw.dev.corpus.{Fixture,load_fixtures,iter_fixtures}`)

## 1. Purpose

Implement `secureclaw dev rule new|test|validate` — the CLI verbs that let SecureClaw maintainers author detection rules with full attribution metadata, run them against the corpus from PR-C, and enforce a schema gate that refuses saving rules without `source`/`license`/positive+negative fixtures.

## 2. Authoritative existing scaffolding

| File | Authority for |
|---|---|
| `secureclaw/rules/default_rules.json` | Canonical rule list (PI-001..PI-028). Rule schema embedded; PR-D uses it as the schema reference. |
| `secureclaw/rules/SOURCING.md` | Per-PR-A: documents attribution rules per plan §C.3. |
| `tests/test_rule_schema.py` (existing) | Already validates schema_version 2 invariants. PR-D extends, doesn't replace. |
| PR-C public surface | `secureclaw.dev.corpus.{Fixture, load_fixtures, iter_fixtures, KlassType}` — the cross-PR contract. |
| `secureclaw/core/scanner.py` | `scan_file(path, ...)` — used by `dev rule test` to actually fire rules against fixtures. |

## 3. Non-goals

- No changes to `default_rules.json` content. PR-D ships the tooling; rule additions land in v1.3.1.
- No grandfathering of attribution gaps in existing rules in PR-D's enforcement. Existing rules with `license_chain_audited: true` are exempt from `--strict-attribution` mode (plan §C.3 acknowledges PI-001..PI-028 predate the new attribution rules).
- No interactive UX. Verbs are non-interactive; users edit JSON files manually.
- No rule promotion/severity-tuning logic. That's tracked separately.
- No skill wrappers — those land in PR-F.

## 4. Module layout

```
secureclaw/dev/rule/
├── __init__.py        # re-exports: scaffold_rule, validate_rules, test_rule, RuleValidationError
├── cli.py             # argparse sub-subparsers
├── models.py          # RuleValidationError, RuleScaffold, RuleTestResult dataclasses
├── schema.py          # load_rule_schema(), validate_rule(rule_dict)
├── scaffolder.py      # scaffold_rule(...) writes JSON entry + fixture stubs via PR-C adder
├── runner.py          # test_rule(rule_id, corpus_root) -> RuleTestResult
└── validator.py       # validate_rules(rules_path, *, strict_attribution=False) -> list[RuleValidationError]
```

Tests:
```
tests/
├── test_dev_rule_models.py
├── test_dev_rule_schema.py
├── test_dev_rule_scaffolder.py
├── test_dev_rule_runner.py
├── test_dev_rule_validator.py
└── test_dev_rule_cli.py
```

### 4.1 Public surface (`secureclaw.dev.rule.__init__`)

```python
from secureclaw.dev.rule.models import (
    RuleScaffold, RuleTestResult, RuleValidationError,
)
from secureclaw.dev.rule.scaffolder import scaffold_rule
from secureclaw.dev.rule.runner import test_rule
from secureclaw.dev.rule.validator import validate_rules

__all__ = [
    "RuleScaffold", "RuleTestResult", "RuleValidationError",
    "scaffold_rule", "test_rule", "validate_rules",
]
```

PR-E will not consume PR-D's surface. PR-F skill wrappers do, indirectly.

## 5. Rule schema (matches existing `default_rules.json`)

The existing rule JSON object has these fields per pattern entry. PR-D treats this as authoritative:

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | str | yes | Format `^PI-[A-Z0-9]+$` |
| `name` | str | yes | Human-readable |
| `regex` | str | yes | Python regex (compiled once at load) |
| `severity` | str | yes | `info`/`low`/`medium`/`high`/`critical` |
| `category` | str | yes | Free text taxonomy |
| `description` | str | yes | Plain-English explanation |
| `remediation` | str | yes | Actionable advice |
| `examples` | list[str] | yes | Sample matches |
| `introduced_in_version` | str | yes | Semver |
| `applies_to` | list[str] | yes | File-type filters |
| `region_kinds` | list[str] | yes | Region filters |
| `applies_in_string_literal` | bool | yes | |
| `applies_in_ai_config` | bool | yes | |
| `requires_same_sentence_with` | list[str] | yes | |
| `boost_on_high_entropy` | bool | yes | |
| `boost_on_invisible_chars` | bool | yes | |
| `large_file_safe` | bool | yes | |
| `sources` | list[obj] | yes | Plan §C.3 attribution; obj has `source`, `license`, `upstream_url`, `upstream_commit`, `derived_from` |
| `license_chain_audited` | bool | yes | |
| `severity_promotion_evidence` | str/null | yes | |
| `owasp` | str/null | yes | |
| `atlas` | str/null | yes | |

### 5.1 Attribution requirements (per plan §C.3)

A rule's `sources` list must contain at least one object with:
- `source` (non-empty string)
- `license` (non-empty string; not `GPL-2.0`, `GPL-3.0`, `AGPL`, `CC-BY-SA`, `CC-BY-NC` per spec PR-C §5.3)
- For non-synthetic licenses: `upstream_url` (URI) AND `upstream_commit` (commit SHA, 7-40 hex)
- For derived works: `derived_from` (string identifying parent project + version)

Validator's `--strict-attribution` mode enforces this on ALL rules. Default mode exempts rules with `license_chain_audited: true` (existing PI-001..PI-028 are grandfathered).

### 5.2 Test-pair requirement

Every NEW rule (added after PR-D merges) must have a paired positive AND negative fixture in `tests/corpus/`. Validator checks via `secureclaw.dev.corpus.load_fixtures(pattern_id=<id>)` that:
- ≥ 1 fixture in `positive/` declares this `pattern_id` in `expected_findings`.
- ≥ 1 fixture in `negative/` declares this `pattern_id` in `forbidden_findings`.

Existing PI-001..PI-028 are grandfathered via `license_chain_audited: true`.

## 6. Verbs

### 6.1 `secureclaw dev rule new`

```
secureclaw dev rule new <id>
    --name "<text>"
    --category <text>
    --severity {info|low|medium|high|critical}
    --regex "<pattern>"
    --description "<text>"
    --remediation "<text>"
    --source "<text>"             # provenance
    --license "<text>"            # license string
    [--upstream-url <URI>]
    [--upstream-commit <sha>]
    [--derived-from <text>]
    [--applies-to <comma>]        # default: any
    [--region-kinds <comma>]      # default: any
    [--rules-file <path>]         # default: secureclaw/rules/default_rules.json
    [--corpus-root <path>]        # default: tests/corpus
    [--examples "<text>;<text>"]
    [--dry-run]
    [--json]
```

Behaviour:
- Refuses if `<id>` already exists in the rules file (exit 2).
- Refuses if `<id>` does not match `^PI-[A-Z0-9]+$` (exit 2).
- Refuses if license matches the PR-C blocklist (exit 2).
- For non-synthetic licenses, requires `--upstream-url` AND `--upstream-commit` (exit 2 if missing).
- Compiles the `--regex` to confirm it's a valid Python regex (exit 1 with the `re.error` message if not).
- Appends the new rule object to `secureclaw/rules/default_rules.json` (atomic write — temp + rename).
- Scaffolds two fixtures:
  - **Positive:** `tests/corpus/positive/<rule-id-slug>_canonical.md` written via `secureclaw.dev.corpus.add_fixture` with `pattern_id=<id>`, `mode='superset'`, `confidence_low=25`, `confidence_high=100`.
  - **Negative:** `tests/corpus/negative/<rule-id-slug>_benign.md` written via a new helper `scaffolder._scaffold_negative(content_path, *, forbidden_findings, source_attestation, license, root)` which writes the content file and the paired `expected.json` directly (because `add_fixture` does not accept `forbidden_findings`; PR-C's adder rejects negatives passed with a `pattern_id`). The helper's emitted `expected.json` matches `expected-schema.json` and validates via `validate_against_schema` before write.
- Prints next-step hint: "Edit the scaffolded fixtures in tests/corpus/{positive,negative}/<slug>_*.md to be realistic, then run `secureclaw dev rule test <id>`."
- `--dry-run` prints what would be added without writing.

### 6.2 `secureclaw dev rule test`

```
secureclaw dev rule test <id-or-all>
    [--rules-file <path>]
    [--corpus-root <path>]
    [--json]
```

Behaviour:
- For a single `<id>`: load the rule and locate its fixtures:
  - **Positive fixtures:** `load_fixtures(klass='positive', pattern_id=<id>)` (PR-C's `pattern_id` filter matches `expected_findings[*].pattern_id`).
  - **Negative fixtures:** `load_fixtures(klass='negative')` post-filtered in PR-D's runner by `<id> in fixture.forbidden_findings`. The PR-C `pattern_id` filter is NOT used for negatives because it only inspects `expected_findings`.
- Run `scan_file` on each fixture's content and report:
  - For each positive fixture: PASS if scanner produced a finding with this pattern_id, FAIL otherwise.
  - For each negative fixture: PASS if scanner produced NO finding with this pattern_id (and no `forbidden_findings` pattern fired above confidence 25), FAIL otherwise.
- For `all`: walks every rule in `--rules-file`, runs the same per-rule test loop.
- Exits 0 if all PASS; exit 1 if any FAIL.
- Output (default text): `RULE PI-N06: 1 positive PASS, 1 negative PASS`. JSON: `{rule_id, positives: [...], negatives: [...], passed: bool}`.

### 6.3 `secureclaw dev rule validate`

```
secureclaw dev rule validate
    [--rules-file <path>]
    [--corpus-root <path>]
    [--strict-attribution]
    [--json]
```

Behaviour: per-rule asserts:
1. Rule object matches the schema in §5 (every required field present, types correct).
2. `id` matches `^PI-[A-Z0-9]+$`.
3. `regex` compiles cleanly.
4. `severity` is a known value.
5. `applies_to` and `region_kinds` are non-empty lists.
6. `sources` is a non-empty list, each object with `source` and `license`.
7. License does not match the PR-C blocklist.
8. **Attribution** (rule-by-rule):
   - If `license_chain_audited: false` (i.e., new rule post-PR-D): `sources[0]` must have `upstream_url` AND `upstream_commit` for non-synthetic licenses.
   - If `--strict-attribution`: same check applied to ALL rules regardless of `license_chain_audited`.
9. **Test pair** (rule-by-rule):
   - For rules with `license_chain_audited: false`: at least one fixture from `load_fixtures(klass='positive', pattern_id=<id>)` AND at least one fixture from `load_fixtures(klass='negative')` post-filtered by `<id> in fixture.forbidden_findings`. Negatives use the post-filter, not PR-C's `pattern_id` filter, because that only inspects `expected_findings`.
   - For rules with `license_chain_audited: true`: skip (grandfathered).

Returns ALL errors before exiting (no bail-on-first). Exit 0 if no errors; 1 otherwise. Warnings (non-strict missing attribution on grandfathered rules) surface but don't change exit code.

## 7. CLI integration

Replace the existing `rule` stub block in `secureclaw/dev/cli.py:35-41` (positional `verb` form) with sub-subparsers via `from secureclaw.dev.rule.cli import attach_rule, dispatch_rule` (parallel to PR-C's `corpus` pattern). `cmd_dev` dispatches `rule` to `dispatch_rule`.

The `rule` subparser uses `attach_rule(rule_parser)` to add `new`, `test`, `validate` sub-subparsers per §6.

## 8. CI gate

Add `tests/test_rule_attribution_gate.py` that runs `validate_rules(strict=False)` on the committed `default_rules.json` and asserts no errors. This locks the attribution invariant for new rules; PR-D itself does NOT modify rules and grandfathered rules pass.

## 9. Test plan (TDD-ordered)

### 9.1 `test_dev_rule_models.py`
- `RuleScaffold` constructs from inputs; required fields enforced.
- `RuleTestResult` summarizes per-fixture PASS/FAIL; `passed` property is `all(positives) and all(negatives)`.
- `RuleValidationError` carries `(rule_id, severity, message)` tuple; severity is `error` or `warning`.

### 9.2 `test_dev_rule_schema.py`
- Validates a known-good rule object.
- Rejects: missing required field, wrong type, unknown severity, blocklisted license, malformed pattern_id.

### 9.3 `test_dev_rule_scaffolder.py`
- Round-trip: scaffold → reload → rule present in JSON, fixtures present in corpus.
- Refuses duplicate `<id>`.
- Refuses without source/license/upstream-url-when-non-synthetic.
- `--dry-run` does not write.
- Atomic write: simulated mid-write failure leaves rules JSON unchanged.

### 9.4 `test_dev_rule_runner.py`
- Mock `scan_file` returning a finding for a positive fixture's pattern_id → PASS.
- Mock `scan_file` returning no finding → FAIL with diagnostic.
- Mock `scan_file` returning a finding for a negative fixture's pattern_id → FAIL.
- `test_rule("all", ...)` walks every rule.
- Returns non-zero exit when any rule FAILs.

### 9.5 `test_dev_rule_validator.py`
- Passes on the existing `default_rules.json` (in default mode).
- `--strict-attribution` flags every grandfathered rule lacking `upstream_url`.
- Catches: blocklisted license, missing attribution on a non-grandfathered rule, malformed regex (re.error), missing test-pair on a non-grandfathered rule.
- Lists ALL errors before exiting.

### 9.6 `test_dev_rule_cli.py`
- argparse parses each verb's flags; `--help` lists every flag from §6.
- `dev rule` (no verb) exits 2.
- Integration: `python -m secureclaw dev rule validate` returns exit 0 against committed rules.

### 9.7 `test_rule_attribution_gate.py` (CI gate)
- Runs `validate_rules(strict_attribution=False)` over committed `default_rules.json`. Exits 0.

## 10. Error handling
Same conventions as PR-C: no silent failures, all errors enumerated before exit, structured stderr messages.

## 11. Dependencies on PR-C
- `secureclaw.dev.corpus.add_fixture` for `dev rule new` fixture scaffolding.
- `secureclaw.dev.corpus.load_fixtures` (with `pattern_id` filter) for `dev rule test` and validator's test-pair check.
- `secureclaw.dev.corpus.Fixture` type used in return values.

## 12. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Grandfathering 28 existing rules without attribution creates permanent debt. | `--strict-attribution` mode lets users audit the gap; future PRs can backfill `upstream_url` per rule. Documented as plan §C.3 deferral. |
| Atomic write to `default_rules.json` could corrupt the file mid-write. | Use temp-file-then-`os.replace` pattern (same as PR-C anonymizer). |
| Scaffolded fixture content is generic placeholder; users may forget to edit. | Hint output reminds them; `dev rule test <id>` will FAIL the positive fixture if the placeholder doesn't actually trigger the rule, surfacing the issue. |
| Regex compilation in `dev rule new` may pass but the rule fires unexpected matches. | The mandatory test-pair requirement + `dev rule test` runs the full scanner on the fixtures, so unexpected matches surface immediately. |

## 13. Definition of done

- [ ] All §9 tests committed RED before implementation per plan §L.
- [ ] All §6 verbs implemented and pass §9 tests.
- [ ] `secureclaw/dev/cli.py` `rule` block replaced with sub-subparser dispatch.
- [ ] `tests/test_rule_attribution_gate.py` passes against committed `default_rules.json`.
- [ ] `python -m secureclaw dev rule validate` exits 0.
- [ ] CI green on Linux/macOS/Windows × Python 3.9-3.13.
- [ ] No new ruff warnings; `from __future__ import annotations` in every new module.
- [ ] PR description references plan §J row D.
- [ ] Standalone bundler (`tools/build_standalone.py`) `SECTIONS` list updated with the following entries (in dependency order, AFTER `("Dev Corpus CLI", SRC / "dev" / "corpus" / "cli.py")` and BEFORE `("Dev CLI Subcommands", SRC / "dev" / "cli.py")`):
  ```python
  ("Dev Rule Models", SRC / "dev" / "rule" / "models.py"),
  ("Dev Rule Schema", SRC / "dev" / "rule" / "schema.py"),
  ("Dev Rule Scaffolder", SRC / "dev" / "rule" / "scaffolder.py"),
  ("Dev Rule Runner", SRC / "dev" / "rule" / "runner.py"),
  ("Dev Rule Validator", SRC / "dev" / "rule" / "validator.py"),
  ("Dev Rule CLI", SRC / "dev" / "rule" / "cli.py"),
  ```
  PR-C's first CI run failed for exactly this reason (missing module bundling); local repro: `python tools/build_standalone.py && python dist/secureclaw.py --version`. Add a smoke-test commit that imports `secureclaw.dev.rule` from the standalone build before opening the PR.
