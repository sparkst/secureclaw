"""CI attribution gate for ``secureclaw/rules/default_rules.json`` (spec §9.7).

Runs ``validate_rules(strict_attribution=False)`` against the committed
rules file. This locks the attribution invariant for new rules — anyone
adding a new rule (license_chain_audited=False) must include upstream_url
+ upstream_commit for non-synthetic licenses, and matching positive +
negative fixtures.

PI-001..PI-028 are grandfathered via ``license_chain_audited: true`` and
pass this gate (their attribution gaps surface only under
``--strict-attribution``).
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMITTED_RULES = REPO_ROOT / "secureclaw" / "rules" / "default_rules.json"
COMMITTED_CORPUS = REPO_ROOT / "tests" / "corpus"


def test_committed_rules_pass_attribution_gate() -> None:
    """The CI gate: zero errors against committed rules in default mode."""
    from secureclaw.dev.rule.validator import validate_rules

    errors = validate_rules(
        COMMITTED_RULES,
        corpus_root=COMMITTED_CORPUS,
        strict_attribution=False,
    )
    real_errors = [e for e in errors if e.severity == "error"]
    assert real_errors == [], (
        f"committed default_rules.json must have zero validate errors in "
        f"default mode (existing PI-001..PI-028 are grandfathered via "
        f"license_chain_audited: true). Got {len(real_errors)} errors:\n"
        + "\n".join(f"  {e.rule_id}: {e.message}" for e in real_errors[:20])
    )
