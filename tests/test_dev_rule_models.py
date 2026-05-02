"""Tests for ``secureclaw.dev.rule.models`` (spec §9.1).

TDD red phase: lands BEFORE the models module.
"""

from __future__ import annotations

import pytest


# --- RuleScaffold ----------------------------------------------------------


def test_rule_scaffold_constructs_with_all_fields() -> None:
    from secureclaw.dev.rule.models import RuleScaffold

    scaf = RuleScaffold(
        rule_id="PI-N06",
        name="Some Rule",
        category="instruction_override",
        severity="advisory",
        regex=r"\bfoo\b",
        description="desc",
        remediation="remed",
        source="own work",
        license="MIT (own work)",
    )
    assert scaf.rule_id == "PI-N06"
    assert scaf.name == "Some Rule"
    assert scaf.severity == "advisory"


def test_rule_scaffold_optional_fields_default_none_or_empty() -> None:
    from secureclaw.dev.rule.models import RuleScaffold

    scaf = RuleScaffold(
        rule_id="PI-N06",
        name="x",
        category="cat",
        severity="advisory",
        regex="x",
        description="d",
        remediation="r",
        source="own work",
        license="MIT (own work)",
    )
    assert scaf.upstream_url is None
    assert scaf.upstream_commit is None
    assert scaf.derived_from is None
    assert scaf.examples == ()
    assert scaf.applies_to == ("any",)
    assert scaf.region_kinds == ("any",)


def test_rule_scaffold_required_fields_missing_raises() -> None:
    from secureclaw.dev.rule.models import RuleScaffold

    with pytest.raises(TypeError):
        RuleScaffold()  # type: ignore[call-arg]


# --- RuleTestResult --------------------------------------------------------


def test_rule_test_result_passed_when_all_positives_and_negatives_pass() -> None:
    from secureclaw.dev.rule.models import RuleTestResult

    r = RuleTestResult(
        rule_id="PI-001",
        positives=(("path1", True, ""),),
        negatives=(("path2", True, ""),),
    )
    assert r.passed is True


def test_rule_test_result_passed_false_when_a_positive_fails() -> None:
    from secureclaw.dev.rule.models import RuleTestResult

    r = RuleTestResult(
        rule_id="PI-001",
        positives=(("path1", False, "no fire"),),
        negatives=(("path2", True, ""),),
    )
    assert r.passed is False


def test_rule_test_result_passed_false_when_a_negative_fails() -> None:
    from secureclaw.dev.rule.models import RuleTestResult

    r = RuleTestResult(
        rule_id="PI-001",
        positives=(("path1", True, ""),),
        negatives=(("path2", False, "fired"),),
    )
    assert r.passed is False


def test_rule_test_result_passed_true_when_no_fixtures() -> None:
    """No fixtures = vacuously passed (validator handles missing-pair complaint)."""
    from secureclaw.dev.rule.models import RuleTestResult

    r = RuleTestResult(rule_id="PI-001", positives=(), negatives=())
    assert r.passed is True


# --- RuleValidationError ---------------------------------------------------


def test_rule_validation_error_constructs_error_severity() -> None:
    from secureclaw.dev.rule.models import RuleValidationError

    err = RuleValidationError(rule_id="PI-001", severity="error", message="bad")
    assert err.rule_id == "PI-001"
    assert err.severity == "error"
    assert err.message == "bad"


def test_rule_validation_error_accepts_warning_severity() -> None:
    from secureclaw.dev.rule.models import RuleValidationError

    warn = RuleValidationError(rule_id="PI-001", severity="warning", message="meh")
    assert warn.severity == "warning"


def test_rule_validation_error_rejects_unknown_severity() -> None:
    from secureclaw.dev.rule.models import RuleValidationError

    with pytest.raises(ValueError):
        RuleValidationError(rule_id="PI-001", severity="critical", message="x")
