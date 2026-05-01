#!/usr/bin/env python3
"""One-time migration: rules schema v1 → v2.

Per v1.3-plan-v10 §B.7 + REQ-15: every rule must carry
``introduced_in_version`` for the grandfathering check, plus the new schema
v2 routing/scoring fields. This script reads ``default_rules.json``,
adds the missing fields with conservative defaults, and writes the file
back in canonical form (sorted keys per pattern, deterministic ordering).

After this PR-A5 lands, schema v2 is the only supported format. PR-A6
adds CI enforcement (``test_grandfather_no_drift``) so future rule edits
that change pre-v1.2 severities are rejected.

Usage:
    python tools/migrate_rules_v1_to_v2.py            # migrate in place
    python tools/migrate_rules_v1_to_v2.py --check    # dry-run; exit 1 on drift
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).parent.parent
RULES_PATH = ROOT / "secureclaw" / "rules" / "default_rules.json"

# Defaults for v1 rules being migrated to v2 (all pre-v1.2 rules):
#   - introduced_in_version: collapsed to "1.2.0" per REQ-15 (R6-REQ001 fix).
#     Rationale: REQ-15 grandfathering only checks <= "1.2.0", so distinguishing
#     1.0.0 from 1.1.0 from 1.2.0 has no functional effect.
#   - applies_to: ["any"] — pre-existing rules ran against all file types.
#   - region_kinds: ["any"] — no structural region routing yet.
#   - applies_in_string_literal / applies_in_ai_config: false — conservative.
#   - large_file_safe: false — pre-existing rules assumed full parse.
#   - boost_on_invisible_chars / boost_on_high_entropy: false — opt-in.
#   - sources: empty list ("own work, MIT" — covered in THIRD_PARTY_NOTICES.md).
#   - license_chain_audited: true (own work).
#   - severity_promotion_evidence: null (no promotion evidence needed for
#     pre-v1.2 rules; they retain their existing severity).
#   - owasp / atlas: null — populated per-rule in follow-up PRs.

V2_DEFAULTS: Dict[str, Any] = {
    "introduced_in_version": "1.2.0",
    "applies_to": ["any"],
    "region_kinds": ["any"],
    "applies_in_string_literal": False,
    "applies_in_ai_config": False,
    "requires_same_sentence_with": [],
    "boost_on_high_entropy": False,
    "boost_on_invisible_chars": False,
    "large_file_safe": False,
    "sources": [],
    "license_chain_audited": True,
    "severity_promotion_evidence": None,
    "owasp": None,
    "atlas": None,
}

# Field order for canonical output. Keys present on a rule are emitted in this
# order; any extras come after, sorted alphabetically.
PREFERRED_ORDER = (
    "id",
    "name",
    "regex",
    "regex_flags",
    "regex_engine",
    "severity",
    "category",
    "description",
    "remediation",
    "examples",
    "case_sensitive",
    "introduced_in_version",
    "applies_to",
    "region_kinds",
    "applies_in_string_literal",
    "applies_in_ai_config",
    "requires_same_sentence_with",
    "boost_on_high_entropy",
    "boost_on_invisible_chars",
    "large_file_safe",
    "sources",
    "license_chain_audited",
    "severity_promotion_evidence",
    "owasp",
    "atlas",
)


def _migrate_pattern(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Apply v2 defaults to a pattern entry without overriding existing fields."""
    out: Dict[str, Any] = dict(entry)
    for key, default in V2_DEFAULTS.items():
        if key not in out:
            # Use a copy so future mutations don't leak across entries.
            out[key] = json.loads(json.dumps(default))
    return out


def _canonical_pattern(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Return a new dict with keys ordered per PREFERRED_ORDER."""
    ordered: Dict[str, Any] = {}
    for key in PREFERRED_ORDER:
        if key in entry:
            ordered[key] = entry[key]
    # Append any keys not in PREFERRED_ORDER, sorted, so future additions are stable.
    extras = sorted(k for k in entry.keys() if k not in PREFERRED_ORDER)
    for key in extras:
        ordered[key] = entry[key]
    return ordered


def migrate(data: Dict[str, Any]) -> Dict[str, Any]:
    """Migrate the full rules document v1 → v2."""
    out: Dict[str, Any] = dict(data)
    out["schema_version"] = 2
    new_patterns: List[Dict[str, Any]] = []
    for entry in data.get("patterns", []):
        migrated = _migrate_pattern(entry)
        new_patterns.append(_canonical_pattern(migrated))
    out["patterns"] = new_patterns
    return out


def _serialize(data: Dict[str, Any]) -> str:
    """Serialize with stable formatting: 2-space indent, no trailing whitespace."""
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="Dry-run; exit 1 on drift.")
    args = ap.parse_args()

    raw = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    migrated = migrate(raw)
    rendered = _serialize(migrated)

    if args.check:
        existing = RULES_PATH.read_text(encoding="utf-8")
        if existing != rendered:
            sys.stderr.write(
                "DRIFT: default_rules.json is not in canonical v2 form. "
                "Run `python tools/migrate_rules_v1_to_v2.py` and commit the diff.\n"
            )
            return 1
        return 0

    RULES_PATH.write_text(rendered, encoding="utf-8")
    print(f"Migrated {RULES_PATH} → schema v2 ({len(migrated['patterns'])} patterns).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
