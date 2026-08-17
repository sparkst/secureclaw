# Third-Party Notices

This file lists upstream sources from which SecureClaw rules and code are
derived, along with their licenses and version pins. It is **generated** by
``tools/gen_third_party_notices.py``.

**DO NOT EDIT MANUALLY.** Drift between this file and rule metadata is a CI
failure (``test_third_party_notices_drift``).

## Generation

```bash
python tools/gen_third_party_notices.py            # write
python tools/gen_third_party_notices.py --check    # diff against committed
```

## Allowed Licenses

Rules and runtime dependencies must carry permissive licenses compatible with
SecureClaw's MIT release.

**Allowed**: ``MIT``, ``Apache-2.0``, ``BSD-2-Clause``, ``BSD-3-Clause``,
``ISC``, ``Unlicense``, ``CC0-1.0``, ``MPL-2.0``, ``BSD-3-Clause-Clear``,
``0BSD``. ``Llama-3.3-Community`` allowed for ``[ml]`` extras only.

**Denied**: ``GPL-*``, ``AGPL-*``, ``LGPL-*``, ``EUPL-*``, ``SSPL-*``.
Patterns inspired by GPL-licensed upstreams (notably ``utkusen/promptmap``)
are re-derived from clean upstream sources cited in the rule's ``sources[]``.


## Runtime Dependencies

| Package | Version | License | Role |
|---|---|---|---|
| `regex` | `==2024.11.6` | Apache-2.0 | Unicode property classes + per-match timeout |
| `send2trash` | `>=1.8,<3.0` | BSD-3-Clause | Cross-platform recoverable delete |

## Development Dependencies

| Package | Version | License | Role |
|---|---|---|---|
| `PyYAML` | `>=6.0` | MIT | YAML parsing (dev only — workflow tests) |
| `hypothesis` | `>=6.0` | MPL-2.0 | Property-based PEM line-count tests (dev only) |
| `jsonschema` | `>=4.0` | MIT | Validate corpus expected.json against schema (dev only) |
| `packaging` | `>=23.0` | Apache-2.0 OR BSD-2-Clause | Semver parsing for REQ-15 (dev only) |
| `pytest` | `>=7.0` | MIT | Test framework (dev only) |
| `ruff` | `>=0.4` | MIT | Lint + format (dev only) |

## Pattern Catalog

_Generated from `secureclaw/rules/default_rules.json` `sources[]` metadata._

| Rule ID | Source | License | Upstream Commit | Fetched | Role |
|---|---|---|---|---|---|
| _28 rules_ | (own work — `MIT`) | MIT | n/a | n/a | identical |

## Vendored Benchmark Fixtures

_Generated from ``tests/corpus/benchmarks/*/*.expected.json``._

| Suite | Upstream | License | Commit | Fixtures |
|---|---|---|---|---|
| `hackaprompt` | <https://github.com/PromptLabs/hackaprompt> | CC-BY-4.0 | `b2d4c91` | 50 |
| `pint` | <https://github.com/lakeraai/pint-benchmark> | MIT | `v8a3f5e7` | 50 |

---

For corrections, open a PR that updates the rule's ``sources[]`` field in ``secureclaw/rules/default_rules.json`` (or the ``DEP_LICENSE_TABLE`` in this generator), then re-run the generator and commit the diff.
