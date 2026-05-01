<!--
Release sign-off template per v1.3-plan-v10 §K.10.

Open this template when tagging vX.Y.Z. Every box must be checked AND every
"Evidence:" link must resolve before the release-signoff-evidence-check CI
job allows merge. Merging this PR triggers the tag and release-build
workflow.

To regenerate this checklist from the current Section N DoD, run:
    python tools/gen_release_signoff.py vX.Y.Z > /tmp/signoff.md
-->

# Release Sign-Off — v_VERSION_

> Generated: _DATE_
> Generator: tools/gen_release_signoff.py vX.Y.Z

## Summary

One paragraph: what changed in this release? Reference the CHANGELOG entry.

## Foundation

- [ ] All Foundation PRs merged. — *Evidence: <links>*
- [ ] `secureclaw/legacy/v1_engine.py` snapshot committed before A3 decomp. — *Evidence: <PR-A4 URL>*
- [ ] `regex==2024.11.6` + `send2trash>=1.8` pinned in pyproject.toml. — *Evidence: <PR-J URL>*
- [ ] `.github/CODEOWNERS` covers critical paths. — *Evidence: <M-PR URL>*
- [ ] Branch protection requires CODEOWNERS approving review on main. — *Evidence: <repo settings screenshot>*
- [ ] `tests/quality_gates.json` baseline_commit matches `^[a-f0-9]{40}$`; `baseline_recorded_date` is non-placeholder ISO date; baseline_metrics populated. — *Evidence: <PR-G URL>*
- [ ] `tests/benchmarks/baseline.json` committed with measured PINT + HackAPrompt numbers. — *Evidence: <file URL>*
- [ ] All risks have non-placeholder owners. — *Evidence: <docs/risk-register.md URL>*

## Engine

- [ ] Pipeline order P1→P2→P3→P4→P3.5→P5→P6 verified by integration test. — *Evidence: <CI URL>*
- [ ] B.6.1 `commitment_modifier` lives in path heuristics; property test "no content match → Minor" passes. — *Evidence: <test URL>*
- [ ] B.3 streaming-lite covers v1.3.0 critical patterns; audit table committed. — *Evidence: <docs/architecture.md URL>*
- [ ] Sentence-boundary segmenter Unicode-aware; multilingual property tests green. — *Evidence: <CI URL>*
- [ ] Composite scoring two-tier veto enforced. — *Evidence: <test URL>*
- [ ] Score decomposition complete (`match_quality.py` + `path_heuristics.py` are pure functions). — *Evidence: <PR-A3 URL>*
- [ ] Calibration weights fit + reproducibility test green; both jarvis-class and ubuntu-class baselines committed. — *Evidence: <PR-G URL>*

## Patterns

- [ ] All 5 v1.3.0 critical patterns landed with positive + negative + regression fixtures: PI-014, PI-013 (class/attr), PI-N06 (orphan ref-def at HIGH), PI-N05 (MCP variants + applies_in_string_literal=true), PI-N01 (all 4 ChatML tokens). — *Evidence: <PR URLs>*
- [ ] Severity grandfathering preserved (PR-A6 hard gate green). — *Evidence: <CI URL>*
- [ ] PR-A6 covers all pre-v1.2 rules; baseline frozen. — *Evidence: <fixture URL>*
- [ ] Every new-category rule has `severity: advisory` AND null `severity_promotion_evidence`. — *Evidence: <test URL>*
- [ ] `THIRD_PARTY_NOTICES.md` regenerated; `test_third_party_notices_drift` green. — *Evidence: <CI URL>*
- [ ] No GPL/AGPL/LGPL/EUPL/SSPL spdx_id in any rule's sources[]. — *Evidence: <CI URL>*

## UX

- [ ] Plain-language vocab user-test (REQ-9.19) completed with ≥3 non-technical readers. — *Evidence: <tests/ux/vocab-comprehension.md URL>*
- [ ] `docs/first-run-ux.md` complete; ≥1 non-technical reader sign-off on landing-page copy + permission-denied per-folder copy + Gatekeeper first-launch copy. — *Evidence: <reader sign-off comment URL>*
- [ ] Vocab CI lint green; no banned terms in rendered HTML output OR rule descriptions. — *Evidence: <CI URL>*
- [ ] `/glossary` endpoint linked from every category-display-name in the report. — *Evidence: <screenshot>*
- [ ] Folder picker: macOS `osascript` / Linux `zenity` (kdialog fallback) / Windows PowerShell + typed-path fallback prominently exposed. — *Evidence: <screenshot per OS>*
- [ ] Pre-scan file count + progress bar + 250ms throttle + ETA moving avg. — *Evidence: <demo recording>*
- [ ] First-run, zero-findings, permission-denied, mid-run-error, huge-folder UX states implemented per `docs/first-run-ux.md`. — *Evidence: <manual walkthrough record>*
- [ ] Move-to-trash affordance per finding; symlink-walk pre-trash. — *Evidence: <test URL>*
- [ ] Mark-as-reviewed / Mark-as-safe distinct semantics; allowlist.json schema documented. — *Evidence: <docs/state.md URL>*

## Security

- [ ] H.4 `/view` 12-check security spec implemented; tests/test_view_security.py covers all 12. — *Evidence: <CI URL>*
- [ ] `/api/rescan-file` uses `validate_view_path_for_rescan`; arbitrary-read tests negative. — *Evidence: <CI URL>*
- [ ] `/api/preferences` validates against config-schema.json; whitelist of writable fields enforced. — *Evidence: <CI URL>*
- [ ] GUI server: 127.0.0.1 binding asserted at startup; Bearer token; Host header validated; Origin check on POSTs; rate limit; Content-Length cap; Referrer-Policy: no-referrer. — *Evidence: <tests/test_gui_security.py CI URL>*
- [ ] Auto-fix lstat-walks full path chain; atomic write via O_EXCL+fsync+rename; TOCTOU pre/post inode compare. — *Evidence: <CI URL>*
- [ ] `SECURECLAW_ENGINE=v1` emits stderr banner + GUI red banner + JSON `legacy_engine_active: true` in all 5 reporters. — *Evidence: <CI URL + manual record>*
- [ ] sc-sync upstream fetch verifies SHA256 against `.upstream` lockfile; SLSA attestation policy documented. — *Evidence: <CI URL>*
- [ ] Backup files chmod 0600 on POSIX; restrictive ACL on Windows; shred-on-undo verified. — *Evidence: <CI URL>*

## Process

- [ ] GitHub Merge Queue enabled on main with all K.1 required status checks. — *Evidence: <repo settings screenshot>*
- [ ] `auto-merge-on-green` label gated by CODEOWNERS; pattern PRs ineligible. — *Evidence: <K2-PR URL>*
- [ ] PR template includes `## Depends-on`; CI parser passes. — *Evidence: <CI URL>*
- [ ] PR summary auto-mirrors to `docs/CHANGELOG-INTERNAL.md` AND GitHub Discussions Release Log. — *Evidence: <Discussion URL>*
- [ ] `.github/EMERGENCY_AUTHORIZED.md` committed (named alternate OR "no alternate"). — *Evidence: <file URL>*
- [ ] In-flight PR cap = 3; Merge Queue concurrency confirmed. — *Evidence: <repo settings screenshot>*
- [ ] All risks reviewed within last 30 days. — *Evidence: <risk register update timestamp>*

## Tests

- [ ] L.3 ReDoS harness (CI + runtime quarantine) green. — *Evidence: <CI URL>*
- [ ] L.7 legacy snapshot pinned-test green; `tests/legacy_baseline.json` byte-identical via `tools/canonicalize_findings.py`. — *Evidence: <CI URL>*
- [ ] PINT shard + HackAPrompt subset green; no regression vs baseline. — *Evidence: <CI URL>*
- [ ] Cross-platform CI green per quorum rule on 4 self-hosted + GH-hosted Linux. — *Evidence: <CI URL>*
- [ ] PyInstaller bundle smoke test green for engine PRs; bundle size ≤ 50 MB. — *Evidence: <CI URL>*
- [ ] Standalone single-file build smoke test green. — *Evidence: <CI URL>*
- [ ] Accessibility CI (pa11y/axe) green on report + /view + /backups + /glossary. — *Evidence: <CI URL>*

## Release

- [ ] `docs/architecture.md`, `docs/contributing-rules.md`, `docs/runners.md`, `docs/state.md`, `docs/dev-cli.md`, `docs/release.md`, `docs/manual-test-plan.md`, `docs/security.md`, `docs/first-run-ux.md` complete to K.7 minimums. — *Evidence: <doc PR URLs>*
- [ ] All Lauren-reported FPs locked in regression corpus and pass with new engine. — *Evidence: <tests/corpus/regression/lauren/ + CI URL>*
- [ ] Lauren OR ≥2 non-technical readers retest internal release; feedback recorded. — *Evidence: <feedback note URL>*
- [ ] Rollback path exercised: `SECURECLAW_ENGINE=v1` runs old engine cleanly. — *Evidence: <smoke test URL>*
- [ ] CHANGELOG.md updated with version bump + summary. — *Evidence: <CHANGELOG entry>*
- [ ] PyPI yank procedure + DMG recall procedure documented in `docs/release.md`. — *Evidence: <docs/release.md URL>*

## Risks

List any open risks (R1–R29 in the risk register) that are still active. Note status changes since last release.

## Notes for the next release

Anything we want to remember for vX.Y.(Z+1) or vX.(Y+1).0.

---

🤖 Generated by `tools/gen_release_signoff.py`. The
`release-signoff-evidence-check` workflow validates that every checkbox is
ticked AND every `Evidence:` link resolves (HTTP 2xx/3xx) before merge.
