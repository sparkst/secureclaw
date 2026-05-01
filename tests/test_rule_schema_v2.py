"""Schema v2 invariants for default_rules.json.

Per v1.3-plan-v10 §B.7 + §D.6 + REQ-15:

- Every rule carries ``introduced_in_version`` (semver string).
- Pre-v1.2 rules have severity exactly equal to the frozen
  ``tests/fixtures/v1.2-severities.json`` snapshot — drift is rejected.
- New v2 fields (applies_to, region_kinds, sources[], etc.) have
  conservative defaults applied.
- Migration script is idempotent (running twice produces identical output).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from packaging.version import Version

ROOT = Path(__file__).parent.parent
RULES = json.loads(
    (ROOT / "secureclaw" / "rules" / "default_rules.json").read_text(encoding="utf-8")
)
V12_BASELINE = json.loads(
    (ROOT / "tests" / "fixtures" / "v1.2-severities.json").read_text(encoding="utf-8")
)
MIGRATE_SCRIPT = ROOT / "tools" / "migrate_rules_v1_to_v2.py"

REQUIRED_V2_FIELDS = (
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
)


def test_schema_version_is_2() -> None:
    assert RULES.get("schema_version") == 2


def test_every_rule_has_required_v2_fields() -> None:
    for entry in RULES["patterns"]:
        missing = [f for f in REQUIRED_V2_FIELDS if f not in entry]
        assert not missing, f"rule {entry['id']} missing v2 fields: {missing}"


def test_every_rule_has_valid_introduced_in_version() -> None:
    """Per REQ-15: must be a parseable semver."""
    for entry in RULES["patterns"]:
        v = entry["introduced_in_version"]
        # Should not raise
        parsed = Version(v)
        assert parsed >= Version("1.0.0"), f"rule {entry['id']} version too old: {v}"


def test_pre_v12_severities_match_baseline() -> None:
    """REQ-15 grandfathering: every pre-v1.2 rule retains its v1.2 severity.

    The baseline lives at tests/fixtures/v1.2-severities.json; PR-A6
    will add CI enforcement that rejects pattern PRs which change a
    pre-v1.2 rule's severity.
    """
    baseline_ids = set(V12_BASELINE.keys())
    for entry in RULES["patterns"]:
        rid = entry["id"]
        if rid not in baseline_ids:
            continue  # post-v1.2 rule; not under grandfathering rule
        assert Version(entry["introduced_in_version"]) <= Version("1.2.0"), (
            f"rule {rid} is in v1.2 baseline but introduced_in_version > 1.2.0"
        )
        assert entry["severity"] == V12_BASELINE[rid], (
            f"rule {rid} severity drift: baseline={V12_BASELINE[rid]!r}, "
            f"current={entry['severity']!r}. "
            f"Pre-v1.2 severities are grandfathered (REQ-15)."
        )


def test_v12_baseline_covers_all_pre_v12_rules() -> None:
    """Sanity: every pre-v1.2 rule in the current file appears in the baseline."""
    pre_v12 = {
        e["id"]
        for e in RULES["patterns"]
        if Version(e["introduced_in_version"]) <= Version("1.2.0")
    }
    baseline_ids = set(V12_BASELINE.keys())
    missing = pre_v12 - baseline_ids
    assert not missing, f"baseline missing rules: {missing}"


def test_migration_is_idempotent() -> None:
    """Running the migration script on already-migrated rules is a no-op."""
    result = subprocess.run(
        [sys.executable, str(MIGRATE_SCRIPT), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0, (
        f"default_rules.json is not in canonical v2 form. "
        f"Run `python tools/migrate_rules_v1_to_v2.py` and commit.\n"
        f"stderr: {result.stderr}"
    )


def test_sources_is_list_per_rule() -> None:
    """sources[] is an array (graph-shaped lineage per SOURCING.md)."""
    for entry in RULES["patterns"]:
        assert isinstance(entry["sources"], list)


def test_no_disallowed_severity_for_post_v12_rules() -> None:
    """REQ-15 (corrected): new categories default to advisory unless
    severity_promotion_evidence is non-null. Currently no post-v1.2 rules
    exist; this test will become load-bearing once PI-N* rules ship.
    """
    for entry in RULES["patterns"]:
        if Version(entry["introduced_in_version"]) > Version("1.2.0"):
            sev = entry["severity"]
            evidence = entry.get("severity_promotion_evidence")
            if sev != "advisory":
                assert evidence is not None, (
                    f"post-v1.2 rule {entry['id']} has severity={sev!r} "
                    f"but no severity_promotion_evidence (REQ-15)"
                )
