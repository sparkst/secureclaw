---
name: sc-rule
description: "Author and validate SecureClaw detection rules. Use when adding a new PI-* rule with full attribution metadata, running an existing rule against the corpus to confirm positive/negative behavior, or validating the rules file against the schema and attribution gate. Wraps `secureclaw dev rule`."
version: 0.1.0
---

# /sc-rule — SecureClaw Detection Rules

## When to invoke

- "add a rule for [attack pattern]"
- "test rule PI-* against the corpus"
- "validate the rules file"
- "check attribution on the rules"

## Verbs

| Intent | Command |
|---|---|
| Scaffold a new rule | `secureclaw dev rule new <id> --name "..." --category <cat> --severity {info\|low\|medium\|high\|critical} --regex "..." --description "..." --remediation "..." --source "..." --license "..." [--upstream-url <URI>] [--upstream-commit <sha>] [--derived-from <text>]` |
| Test a rule against corpus | `secureclaw dev rule test <id-or-all>` |
| Validate the rules file | `secureclaw dev rule validate [--strict-attribution]` |

## Examples

**Scaffold a new rule (creates rule entry + paired positive/negative fixtures):**
```
secureclaw dev rule new PI-N06 \
    --name "Reference-link Markdown Exfiltration" \
    --category reference_link_exfil --severity high \
    --regex '\\[[^\\]]+\\]:\\s*https?://[^\\s]+' \
    --description "Markdown reference-style image link to external host" \
    --remediation "Remove the reference link or block external image fetch in your AI tool." \
    --source "EchoLeak CVE-2025-32711" \
    --license "MIT" \
    --upstream-url "https://github.com/sparkst/secureclaw" \
    --upstream-commit "abc1234"
```
Then edit the scaffolded fixtures in `tests/corpus/{positive,negative}/pi_n06_*.md` and run `secureclaw dev rule test PI-N06`.

**Test all rules against the corpus:**
```
secureclaw dev rule test all
```

**Validate with strict attribution (flags grandfathered rules lacking upstream_url):**
```
secureclaw dev rule validate --strict-attribution
```

## Notes

- Default `validate` mode grandfathers existing PI-001..PI-028 (they predate the attribution rules). New rules are always strict-mode-enforced regardless of flag.
- The CI gate `tests/test_rule_attribution_gate.py` runs `validate` on every PR.
- Licenses on the blocklist (GPL/AGPL/CC-BY-SA/CC-BY-NC) are rejected by both `new` and `validate`.
- See `secureclaw/rules/SOURCING.md` for the v1.3-plan §C.3 attribution rationale.
