"""Hard CI gate enforcing the REQ-15 grandfathering invariant.

Per v1.3-plan-v10 REQ-15 + §D.6 + R6-REQ001:

Pre-v1.2 rules (those with ``introduced_in_version <= "1.2.0"``) MUST
retain the severity recorded in ``tests/fixtures/v1.2-severities.json``.
This file is frozen; PRs that change a pre-v1.2 severity are rejected.

The schema v2 invariants (every rule has the field, semver parses, etc.)
live in ``test_rule_schema_v2.py``. This module is the dedicated drift
gate — separate so failures here are unambiguous: "you changed a
pre-v1.2 severity; that violates grandfathering."

PR-A5 introduced the baseline + a soft test. PR-A6 (this file) is the
hard gate. CODEOWNERS protects ``tests/fixtures/v1.2-severities.json``;
loosening the baseline requires an explicit CODEOWNERS-approved PR.
"""

from __future__ import annotations

import json
from pathlib import Path

from packaging.version import Version

ROOT = Path(__file__).parent.parent
RULES = json.loads(
    (ROOT / "secureclaw" / "rules" / "default_rules.json").read_text(encoding="utf-8")
)
V12_BASELINE = json.loads(
    (ROOT / "tests" / "fixtures" / "v1.2-severities.json").read_text(encoding="utf-8")
)


def test_grandfather_no_drift_strict() -> None:
    """REQ-15 hard gate: zero drift permitted on pre-v1.2 severities."""
    drift: list[str] = []
    for entry in RULES["patterns"]:
        rid = entry["id"]
        if rid not in V12_BASELINE:
            continue  # post-v1.2 rule
        introduced = Version(entry["introduced_in_version"])
        if introduced > Version("1.2.0"):
            iv = entry["introduced_in_version"]
            drift.append(f"  {rid}: in v1.2 baseline but introduced_in_version={iv!r}")
            continue
        baseline_sev = V12_BASELINE[rid]
        actual_sev = entry["severity"]
        if actual_sev != baseline_sev:
            drift.append(f"  {rid}: baseline={baseline_sev!r}, current={actual_sev!r}")

    if drift:
        msg = (
            "REQ-15 GRANDFATHERING VIOLATION — pre-v1.2 severities cannot change.\n"
            "Drift:\n" + "\n".join(drift) + "\n\n"
            "If you intend to change a pre-v1.2 severity, you MUST update "
            "tests/fixtures/v1.2-severities.json in a dedicated PR labeled "
            "'gates-change' with rationale, AND that PR requires CODEOWNERS "
            "approval (currently @sparkst). Bundling this with rule/engine "
            "changes is forbidden by the merge gate."
        )
        raise AssertionError(msg)


def test_baseline_is_complete() -> None:
    """Every rule with introduced_in_version<=1.2.0 must be in the baseline."""
    pre_v12 = {
        e["id"]
        for e in RULES["patterns"]
        if Version(e["introduced_in_version"]) <= Version("1.2.0")
    }
    baseline_ids = set(V12_BASELINE.keys())
    missing = pre_v12 - baseline_ids
    extra = baseline_ids - pre_v12
    assert not missing, (
        f"v1.2-severities.json is missing pre-v1.2 rules: {missing}. "
        f"Run a controlled re-snapshot via a dedicated PR with rationale."
    )
    assert not extra, (
        f"v1.2-severities.json has entries that aren't pre-v1.2: {extra}. "
        f"Either the rule was retroactively reclassified or the baseline is stale."
    )


def test_baseline_severities_are_valid_values() -> None:
    """Sanity: every baseline severity is one of the allowed values."""
    allowed = {"critical", "high", "advisory"}
    for rid, sev in V12_BASELINE.items():
        assert sev in allowed, f"{rid}: invalid severity {sev!r} in baseline"


def test_baseline_count_matches_documented() -> None:
    """The baseline was sized at 28 rules at the Foundation cut."""
    # If this changes legitimately (e.g., a v1.2 rule was deleted or split),
    # update this count + the rationale in the PR description.
    assert len(V12_BASELINE) == 28, (
        f"baseline size changed: {len(V12_BASELINE)} (was 28). "
        f"This may be intentional (rule deletion/split) but requires a "
        f"dedicated PR explaining the change."
    )
