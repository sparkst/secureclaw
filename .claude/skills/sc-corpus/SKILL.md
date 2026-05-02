---
name: sc-corpus
description: "Manage SecureClaw fixture corpus. Use when adding new positive/negative/borderline/regression/dos fixtures, listing what's in the corpus, validating fixture metadata, anonymizing input files before committing as fixtures, or updating added_in_pr placeholders post-merge. Wraps `secureclaw dev corpus`."
version: 0.1.0
---

# /sc-corpus — SecureClaw Fixture Corpus

## When to invoke

- "add a fixture for [pattern]"
- "list corpus fixtures" / "what's in the corpus"
- "validate the corpus"
- "anonymize [dir] before committing as fixtures"
- "set the PR number on the seed fixtures"

## Verbs

| Intent | Command |
|---|---|
| Add a fixture | `secureclaw dev corpus add <path> --class {positive\|negative\|borderline\|regression\|dos} --source-attestation "..." --license "..." [--pattern-id <id>]` |
| List | `secureclaw dev corpus list [--class X] [--pattern-id Y] [--root <path>]` |
| Validate | `secureclaw dev corpus validate [--strict]` |
| Anonymize | `secureclaw dev corpus anonymize <src-dir> <dst-dir>` |
| Set PR number | `secureclaw dev corpus set-pr-number <N> [--dry-run]` |

## Examples

**Add a Lauren-persona negative:**
```
secureclaw dev corpus add ~/draft.md --class negative \
    --source-attestation "synthetic — Lauren-style marketing prose" \
    --license "MIT (own work)"
```

**Validate before commit:**
```
secureclaw dev corpus validate
```
Exits 0 if every `expected.json` matches the schema, references real pattern IDs, and licenses are not on the blocklist (GPL/AGPL/CC-BY-SA/CC-BY-NC).

**Anonymize a real-machine directory before vendoring:**
```
secureclaw dev corpus anonymize ~/my-test-files /tmp/anonymized-out
```
Orchestrates SecureClaw self-scan + gitleaks + trufflehog + entropy/shape residue checks. Output goes to a scratch directory for human review before commit (never directly into `tests/corpus/`).

## Notes

- `dev corpus validate` runs as a CI gate (`tests/test_fixture_schema.py`); invoke locally before commit.
- `anonymize` requires `gitleaks >= v8.18.0` and `trufflehog >= v3.63.0` — install via `tools/install-anonymizer-deps.sh`.
- See `tests/corpus/CONTRIBUTING.md` for the two-person CODEOWNERS attestation requirement on every corpus PR.
