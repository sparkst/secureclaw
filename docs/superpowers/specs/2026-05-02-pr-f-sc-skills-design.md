# PR-F — `feature/sc-skills` design

**Status:** Draft
**Author:** Claude (under Travis Sparks)
**Date:** 2026-05-02
**Plan reference:** `.review-artifacts/v1.3-plan.md` §F, §J row F, §K
**Branch:** `feature/sc-skills` (off `main`, after PR-E merges)
**Depends on:** PR-C, PR-D, PR-E (all merged into main)

## 1. Purpose

Ship three thin Claude Code skills that wrap the now-landed `secureclaw dev` CLI verbs for ergonomic invocation from a Claude conversation. Per brainstorm Question 3 = A: **pure-thin skills**. Each is a single SKILL.md file describing when to invoke and which CLI verbs to call. No scripts, no embedded prompt logic, no workflow choreography (the schema/attribution/test-pair gates already live in `dev rule validate`).

If we hit friction in real usage, scripts can be added in a follow-up — this PR keeps PR-F small per plan §J row F ("thin wrappers").

## 2. Scope

Three skills in `.claude/skills/`:

| Skill | Wraps | Purpose |
|---|---|---|
| `sc-corpus` | `secureclaw dev corpus add/list/validate/anonymize/set-pr-number` | Fixture management |
| `sc-rule` | `secureclaw dev rule new/test/validate` | Rule authoring + test |
| `sc-bench` | `secureclaw dev bench run/baseline/diff` | Benchmark management |

## 3. Non-goals

- No `sc-fed`, `sc-sync`, `sc-triage`. Plan §F lists those for v1.3.2 after the federated runners and upstream-sync infrastructure land.
- No interactive flows beyond what the CLI already exposes.
- No script helpers in `scripts/` subdirs (would make these "thin + scripted" per brainstorm Question 3 = B; user picked A).
- No automatic fixture-author labeling, source-attestation prompt-walks, or schema-conformance hand-holding inside the skill content (the `dev rule validate` and `dev corpus validate` verbs already enforce these; duplicating in skills is redundant).

## 4. Module layout

```
.claude/skills/
├── sc-corpus/SKILL.md
├── sc-rule/SKILL.md
└── sc-bench/SKILL.md
```

Each SKILL.md is 30-60 lines (frontmatter + when-to-invoke + verb table + 2-3 examples).

## 5. SKILL.md format

Match the existing skill convention used by `qreview`/`qloop` etc.:

```markdown
---
name: sc-corpus
description: "Manage SecureClaw fixture corpus. Use when adding new positive/negative/borderline/regression/dos fixtures, listing what's in the corpus, validating fixture metadata, anonymizing input files, or setting added_in_pr placeholders post-merge."
version: 0.1.0
---

# /sc-corpus — SecureClaw Fixture Corpus

## When to invoke

- "add a fixture for ..."
- "list corpus fixtures"
- "validate the corpus"
- "anonymize this directory before committing as fixtures"
- "set the PR number on the seed fixtures"

## Verbs

| Intent | Command |
|---|---|
| Add a fixture | `secureclaw dev corpus add <path> --class {positive\|negative\|borderline\|regression\|dos} --source-attestation "..." --license "..."` |
| List | `secureclaw dev corpus list [--class X] [--pattern-id Y]` |
| Validate | `secureclaw dev corpus validate [--strict]` |
| Anonymize | `secureclaw dev corpus anonymize <src-dir> <dst-dir>` |
| Set PR number | `secureclaw dev corpus set-pr-number <N>` |

## Examples

[2-3 worked examples]

## Notes

- `dev corpus validate` runs as a CI gate already; invoke locally before commit.
- `anonymize` orchestrates SecureClaw self-scan + gitleaks + trufflehog. Install via `tools/install-anonymizer-deps.sh`.
- See `tests/corpus/CONTRIBUTING.md` for the two-person CODEOWNERS attestation requirement.
```

Same shape for `sc-rule` and `sc-bench` with the appropriate verb tables.

## 6. CI gate

Add `tests/test_skills_present.py`:
- Asserts `.claude/skills/sc-corpus/SKILL.md`, `sc-rule/SKILL.md`, `sc-bench/SKILL.md` all exist.
- Each has the required frontmatter fields (`name`, `description`, `version`).
- Each `name` field matches its directory name.
- The verb table mentions every verb listed in §4 (regex match against the markdown).

Lightweight, prevents regression.

## 7. Test plan (TDD-ordered)

### 7.1 `test_skills_present.py`
- Each SKILL.md exists.
- Each has frontmatter with `name`, `description`, `version`.
- The `name` matches the directory.
- Every verb in §5 verb table appears in the markdown.

### 7.2 No-op for the implementation modules — these are markdown files, not code. The TDD pair is "tests-first → markdown-first" — the test asserts file existence and structure, then the SKILL.md content lands.

## 8. CLI integration

None. PR-F adds files under `.claude/skills/` only. No changes to `secureclaw/dev/cli.py`, no standalone bundler updates.

## 9. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Skill descriptions drift from the underlying CLI surface as PR-D/PR-E evolve. | The CI gate in §6 asserts every documented verb exists in the verb table. Future PRs that add a verb update both the CLI and the skill. |
| User invokes a skill but doesn't have the SecureClaw CLI installed. | SKILL.md's "Setup" subsection links to `pip install secureclaw[dev]`. |
| Skills could grow into thick orchestrators. | Plan §F.6 explicitly says "thin wrappers"; brainstorm Q3=A re-affirmed. PR-F keeps that constraint. |

## 10. Definition of done

- [ ] `.claude/skills/sc-corpus/SKILL.md`, `sc-rule/SKILL.md`, `sc-bench/SKILL.md` all created.
- [ ] Each is 30-60 lines and matches the §5 format.
- [ ] `tests/test_skills_present.py` committed and passing.
- [ ] `python -m pytest tests/test_skills_present.py` exits 0.
- [ ] `ruff check`, `ruff format --check` clean.
- [ ] CI green.
- [ ] PR description references plan §J row F and the brainstorm Q3=A scope decision.
- [ ] PR closes the v1.3 Foundation phase (PR-A, B, C, D, E, F all merged).
