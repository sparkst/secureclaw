"""Tests for ``secureclaw.dev.rule.validator`` (spec §9.5).

TDD red phase: lands BEFORE the validator module.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parent.parent
COMMITTED_RULES = REPO_ROOT / "secureclaw" / "rules" / "default_rules.json"


def _good_rule(**overrides: Any) -> Dict[str, Any]:
    rule: Dict[str, Any] = {
        "id": "PI-N06",
        "name": "Test",
        "regex": r"\bfoo\b",
        "severity": "advisory",
        "category": "instruction_override",
        "description": "x",
        "remediation": "x",
        "examples": [],
        "introduced_in_version": "1.3.1",
        "applies_to": ["any"],
        "region_kinds": ["any"],
        "applies_in_string_literal": False,
        "applies_in_ai_config": False,
        "requires_same_sentence_with": [],
        "boost_on_high_entropy": False,
        "boost_on_invisible_chars": False,
        "large_file_safe": False,
        "sources": [{"source": "own work", "license": "MIT (own work)"}],
        "license_chain_audited": False,
        "severity_promotion_evidence": None,
        "owasp": None,
        "atlas": None,
    }
    rule.update(overrides)
    return rule


def _write_rules(path: Path, patterns: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "pattern_version": "1.3.1",
                "min_tool_version": "1.3.0",
                "description": "test",
                "patterns": patterns,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _write_positive(corpus: Path, rule_id: str, name: str = "canon") -> Path:
    pos = corpus / "positive"
    pos.mkdir(parents=True, exist_ok=True)
    (pos / f"{name}.md").write_text("foo bar\n", encoding="utf-8")
    (pos / f"{name}.md.expected.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "file": f"{name}.md",
                "mode": "superset",
                "expected_findings": [
                    {"pattern_id": rule_id, "confidence_range": [25, 100]}
                ],
                "source": "own work",
                "license": "MIT (own work)",
            }
        ),
        encoding="utf-8",
    )
    return pos / f"{name}.md"


def _write_negative(corpus: Path, rule_id: str, name: str = "benign") -> Path:
    neg = corpus / "negative"
    neg.mkdir(parents=True, exist_ok=True)
    (neg / f"{name}.md").write_text("benign\n", encoding="utf-8")
    (neg / f"{name}.md.expected.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "file": f"{name}.md",
                "mode": "exact",
                "expected_findings": [],
                "forbidden_findings": [rule_id],
                "source": "own work",
                "license": "MIT (own work)",
            }
        ),
        encoding="utf-8",
    )
    return neg / f"{name}.md"


# --- Existing committed rules pass in default mode ------------------------


def test_validator_passes_committed_rules_default_mode() -> None:
    """Committed default_rules.json must pass with strict_attribution=False
    (existing rules are grandfathered via license_chain_audited: true)."""
    from secureclaw.dev.rule.validator import validate_rules

    errors = validate_rules(
        COMMITTED_RULES,
        corpus_root=REPO_ROOT / "tests" / "corpus",
        strict_attribution=False,
    )
    real_errors = [e for e in errors if e.severity == "error"]
    assert real_errors == [], (
        f"committed rules should pass default validate; got {real_errors!r}"
    )


# --- Strict mode flags grandfathered rules ---------------------------------


def test_validator_strict_flags_committed_rules_lacking_upstream() -> None:
    """In strict mode, every grandfathered rule lacking upstream_url is flagged.

    All 28 PI-001..PI-028 rules have empty sources[], so strict mode should
    produce many errors.
    """
    from secureclaw.dev.rule.validator import validate_rules

    errors = validate_rules(
        COMMITTED_RULES,
        corpus_root=REPO_ROOT / "tests" / "corpus",
        strict_attribution=True,
    )
    real_errors = [e for e in errors if e.severity == "error"]
    assert real_errors, "strict mode should flag grandfathered rules"


# --- Catches blocklisted license -------------------------------------------


def test_validator_catches_blocklisted_license(tmp_path: Path) -> None:
    from secureclaw.dev.rule.validator import validate_rules

    rules = tmp_path / "rules.json"
    rule = _good_rule()
    rule["sources"] = [{"source": "x", "license": "GPL-3.0"}]
    _write_rules(rules, [rule])

    errors = validate_rules(rules, corpus_root=tmp_path / "corpus")
    msgs = " ".join(e.message for e in errors)
    assert "license" in msgs.lower()


# --- Catches missing attribution on non-grandfathered rule -----------------


def test_validator_catches_missing_attribution_on_new_rule(tmp_path: Path) -> None:
    """license_chain_audited=False (new rule) + non-synthetic license without
    upstream_url -> error in DEFAULT mode (no need for --strict)."""
    from secureclaw.dev.rule.validator import validate_rules

    rules = tmp_path / "rules.json"
    rule = _good_rule()
    rule["sources"] = [{"source": "Lakera Guard", "license": "Apache-2.0"}]
    rule["license_chain_audited"] = False
    _write_rules(rules, [rule])

    # Provide test pair so the missing-pair check doesn't dominate.
    _write_positive(tmp_path / "corpus", rule["id"])
    _write_negative(tmp_path / "corpus", rule["id"])

    errors = validate_rules(rules, corpus_root=tmp_path / "corpus")
    real = [e for e in errors if e.severity == "error"]
    assert real, "expected an error for missing attribution"
    assert any("upstream" in e.message.lower() for e in real)


# --- Catches malformed regex -----------------------------------------------


def test_validator_catches_malformed_regex(tmp_path: Path) -> None:
    from secureclaw.dev.rule.validator import validate_rules

    rules = tmp_path / "rules.json"
    rule = _good_rule(regex="[")
    _write_rules(rules, [rule])

    errors = validate_rules(rules, corpus_root=tmp_path / "corpus")
    assert any("regex" in e.message.lower() for e in errors)


# --- Catches missing test-pair on a non-grandfathered rule -----------------


def test_validator_catches_missing_positive_pair(tmp_path: Path) -> None:
    """Non-grandfathered rule with no positive fixture -> error."""
    from secureclaw.dev.rule.validator import validate_rules

    rules = tmp_path / "rules.json"
    _write_rules(rules, [_good_rule()])

    # Only negative — no positive.
    _write_negative(tmp_path / "corpus", "PI-N06")

    errors = validate_rules(rules, corpus_root=tmp_path / "corpus")
    real = [e for e in errors if e.severity == "error"]
    assert any("positive" in e.message.lower() for e in real)


def test_validator_catches_missing_negative_pair(tmp_path: Path) -> None:
    """Non-grandfathered rule with no negative fixture (using the corrected
    forbidden_findings post-filter) -> error.

    This test fails if the validator queries negatives via
    load_fixtures(pattern_id=<id>) (the broken approach), because that filter
    only inspects expected_findings.
    """
    from secureclaw.dev.rule.validator import validate_rules

    rules = tmp_path / "rules.json"
    _write_rules(rules, [_good_rule()])

    # Only positive — no negative.
    _write_positive(tmp_path / "corpus", "PI-N06")

    errors = validate_rules(rules, corpus_root=tmp_path / "corpus")
    real = [e for e in errors if e.severity == "error"]
    assert any("negative" in e.message.lower() for e in real)


def test_validator_passes_when_pair_present_via_forbidden_findings(
    tmp_path: Path,
) -> None:
    """If a negative fixture declares the rule in forbidden_findings, the
    validator's pair-check must accept it."""
    from secureclaw.dev.rule.validator import validate_rules

    rules = tmp_path / "rules.json"
    _write_rules(rules, [_good_rule()])
    _write_positive(tmp_path / "corpus", "PI-N06")
    _write_negative(tmp_path / "corpus", "PI-N06")

    errors = validate_rules(rules, corpus_root=tmp_path / "corpus")
    real = [e for e in errors if e.severity == "error"]
    assert real == [], f"unexpected errors: {real}"


# --- ALL errors returned (no bail-on-first) --------------------------------


def test_validator_returns_all_errors(tmp_path: Path) -> None:
    """If a rule has multiple problems, all should appear in the error list."""
    from secureclaw.dev.rule.validator import validate_rules

    rules = tmp_path / "rules.json"
    rule = _good_rule(regex="[", severity="bogus")
    rule["sources"] = [{"source": "x", "license": "GPL-3.0"}]
    _write_rules(rules, [rule])

    errors = validate_rules(rules, corpus_root=tmp_path / "corpus")
    msgs = "\n".join(e.message for e in errors)
    assert "regex" in msgs.lower()
    assert "severity" in msgs.lower()
    assert "license" in msgs.lower()
