# Pattern Sourcing & Attribution Schema

Every rule in `default_rules.json` MUST carry full attribution metadata so we can
(a) credit upstream authors, (b) audit license compatibility, (c) sync upstream
updates, and (d) prove provenance during compliance reviews.

## Required schema fields

```json
{
  "id": "PI-NXX",
  "introduced_in_version": "1.3.0",
  "sources": [
    {
      "role": "derived-from | inspired-by | identical",
      "url": "https://github.com/<org>/<repo>/blob/<sha>/<path>",
      "spdx_id": "Apache-2.0",
      "commit": "abc123def456...",
      "fetched_date": "2026-04-30"
    }
  ],
  "license_chain_audited": true
}
```

### Field meanings

- **`role`**: how this pattern relates to the upstream content.
  - `identical`: the rule is a verbatim copy of upstream regex/logic.
  - `derived-from`: substantially based on upstream, with documented modifications.
  - `inspired-by`: independent re-derivation from the same primary source upstream cites.
- **`url`**: stable URL to the exact upstream artifact at a known commit.
- **`spdx_id`**: must be a valid SPDX license identifier from the
  [SPDX License List](https://spdx.org/licenses/). CI validates against the official list.
- **`commit`**: 40-char SHA of the upstream commit fetched.
- **`fetched_date`**: ISO 8601 date the upstream was last pulled/verified.

### `sources` is an array

A pattern may have multiple sources to model graph-shaped lineage (e.g., a
rule we re-derived from upstream A, which itself credits upstream B, which we
also reviewed). Use multiple `sources[]` entries with appropriate roles.

## License compatibility

CI gate `secureclaw dev rule validate` (PR-D) refuses any rule whose
`sources[].spdx_id` matches the project's denylist. See `THIRD_PARTY_NOTICES.md`
for the current allowlist + denylist.

**Promptmap (GPL-3.0)**: never copy. Rules conceptually similar to promptmap
must list the clean upstream they re-derive from (e.g., `alexalbertt/jailbreakchat`
which promptmap itself cites).

## Updating from upstream

The `sc-sync` skill (PR-D-followup) periodically:
1. Fetches each upstream URL at the latest commit.
2. Compares against the pinned `commit` in `sources[]`.
3. Translates upstream changes through an adapter to our IR.
4. Opens an attributed PR with diff.

Manual upstream pulls follow the same template; commit + sha256 update is
required atomically with content changes.

## Compound license expressions

When upstream uses an SPDX expression (e.g., `MIT AND Apache-2.0`,
`GPL-3.0 OR Apache-2.0`), it is parsed by `license-expression` library and
checked term-by-term. If any disjunct or conjunct is denied, the rule is
rejected.
