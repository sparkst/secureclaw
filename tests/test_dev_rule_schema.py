"""Tests for ``secureclaw.dev.rule.schema`` (spec §9.2).

TDD red phase: lands BEFORE the schema module.
"""

from __future__ import annotations

from typing import Any, Dict


def _good_rule(**overrides: Any) -> Dict[str, Any]:
    """Build a known-good rule dict matching the existing default_rules.json shape."""
    rule: Dict[str, Any] = {
        "id": "PI-N06",
        "name": "Test Rule",
        "regex": r"\bfoo\b",
        "severity": "advisory",
        "category": "instruction_override",
        "description": "Test description",
        "remediation": "Delete this text",
        "examples": ["foo bar"],
        "introduced_in_version": "1.3.1",
        "applies_to": ["any"],
        "region_kinds": ["any"],
        "applies_in_string_literal": False,
        "applies_in_ai_config": False,
        "requires_same_sentence_with": [],
        "boost_on_high_entropy": False,
        "boost_on_invisible_chars": False,
        "large_file_safe": False,
        "sources": [
            {
                "source": "own work",
                "license": "MIT (own work)",
            }
        ],
        "license_chain_audited": False,
        "severity_promotion_evidence": None,
        "owasp": None,
        "atlas": None,
    }
    rule.update(overrides)
    return rule


# --- load_rule_schema ------------------------------------------------------


def test_load_rule_schema_returns_field_requirements() -> None:
    """load_rule_schema() returns a dict describing required fields."""
    from secureclaw.dev.rule.schema import load_rule_schema

    schema = load_rule_schema()
    assert isinstance(schema, dict)
    required = schema.get("required_fields")
    assert required is not None
    # Must include the canonical fields from §5.
    for f in (
        "id",
        "name",
        "regex",
        "severity",
        "category",
        "description",
        "remediation",
        "examples",
        "introduced_in_version",
        "applies_to",
        "region_kinds",
        "sources",
        "license_chain_audited",
    ):
        assert f in required


# --- validate_rule (good case) --------------------------------------------


def test_validate_rule_passes_known_good() -> None:
    from secureclaw.dev.rule.schema import validate_rule

    errors = validate_rule(_good_rule())
    assert errors == [], f"unexpected errors: {errors}"


# --- validate_rule (bad cases) --------------------------------------------


def test_validate_rule_rejects_missing_required_field() -> None:
    from secureclaw.dev.rule.schema import validate_rule

    rule = _good_rule()
    del rule["regex"]
    errors = validate_rule(rule)
    assert errors, "expected error for missing 'regex'"
    assert any("regex" in e for e in errors)


def test_validate_rule_rejects_wrong_type() -> None:
    from secureclaw.dev.rule.schema import validate_rule

    rule = _good_rule()
    rule["applies_to"] = "any"  # should be list
    errors = validate_rule(rule)
    assert errors, "expected error for wrong type"


def test_validate_rule_rejects_unknown_severity() -> None:
    from secureclaw.dev.rule.schema import validate_rule

    errors = validate_rule(_good_rule(severity="bogus"))
    assert errors, "expected error for unknown severity"
    assert any("severity" in e.lower() for e in errors)


def test_validate_rule_rejects_blocklisted_license() -> None:
    from secureclaw.dev.rule.schema import validate_rule

    rule = _good_rule()
    rule["sources"] = [{"source": "x", "license": "GPL-3.0"}]
    errors = validate_rule(rule)
    assert errors
    assert any("license" in e.lower() for e in errors)


def test_validate_rule_rejects_malformed_pattern_id() -> None:
    from secureclaw.dev.rule.schema import validate_rule

    errors = validate_rule(_good_rule(id="bad-id"))
    assert errors
    assert any("id" in e.lower() or "PI-" in e for e in errors)


def test_validate_rule_rejects_malformed_regex() -> None:
    from secureclaw.dev.rule.schema import validate_rule

    errors = validate_rule(_good_rule(regex="["))
    assert errors
    assert any("regex" in e.lower() for e in errors)


def test_validate_rule_rejects_empty_applies_to() -> None:
    from secureclaw.dev.rule.schema import validate_rule

    errors = validate_rule(_good_rule(applies_to=[]))
    assert errors
    assert any("applies_to" in e for e in errors)


def test_validate_rule_rejects_empty_region_kinds() -> None:
    from secureclaw.dev.rule.schema import validate_rule

    errors = validate_rule(_good_rule(region_kinds=[]))
    assert errors


def test_validate_rule_rejects_empty_sources() -> None:
    from secureclaw.dev.rule.schema import validate_rule

    errors = validate_rule(_good_rule(sources=[]))
    assert errors
    assert any("sources" in e for e in errors)


def test_validate_rule_rejects_source_missing_license() -> None:
    from secureclaw.dev.rule.schema import validate_rule

    rule = _good_rule()
    rule["sources"] = [{"source": "own work"}]  # no license
    errors = validate_rule(rule)
    assert errors


# --- strict_attribution ----------------------------------------------------


def test_validate_rule_strict_requires_upstream_for_non_synthetic() -> None:
    from secureclaw.dev.rule.schema import validate_rule

    rule = _good_rule()
    rule["sources"] = [{"source": "Lakera Guard", "license": "Apache-2.0"}]
    errors = validate_rule(rule, strict_attribution=True)
    assert errors
    assert any("upstream" in e.lower() for e in errors)


def test_validate_rule_strict_passes_with_upstream_url_and_commit() -> None:
    from secureclaw.dev.rule.schema import validate_rule

    rule = _good_rule()
    rule["sources"] = [
        {
            "source": "Lakera Guard",
            "license": "Apache-2.0",
            "upstream_url": "https://github.com/lakera-ai/guard",
            "upstream_commit": "abc1234",
        }
    ]
    errors = validate_rule(rule, strict_attribution=True)
    assert errors == [], f"unexpected: {errors}"


def test_validate_rule_strict_skips_upstream_for_synthetic() -> None:
    from secureclaw.dev.rule.schema import validate_rule

    rule = _good_rule()
    rule["sources"] = [{"source": "own work", "license": "MIT (own work)"}]
    errors = validate_rule(rule, strict_attribution=True)
    assert errors == [], f"unexpected: {errors}"
