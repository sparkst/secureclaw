"""Tests for secureclaw.dev.corpus.models — foundation types for PR-C.

Spec §13.1. TDD red phase: this file lands BEFORE any implementation in
secureclaw/dev/corpus/models.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def test_imports_exist() -> None:
    """All public types are importable from secureclaw.dev.corpus."""
    from secureclaw.dev.corpus import (
        AnonymizeReport,
        ExpectedFinding,
        Fixture,
        KlassType,
        RefusalReason,
        ValidationError,
    )

    # Smoke: types exist and are usable as type hints (deferred via __future__).
    assert ExpectedFinding is not None
    assert Fixture is not None
    assert ValidationError is not None
    assert AnonymizeReport is not None
    # KlassType and RefusalReason are typing.Literal aliases — truthy.
    assert KlassType is not None
    assert RefusalReason is not None


def test_expected_finding_constructs_with_required_fields() -> None:
    from secureclaw.dev.corpus import ExpectedFinding

    f = ExpectedFinding(pattern_id="PI-005", line=7, confidence_range=(75, 100))
    assert f.pattern_id == "PI-005"
    assert f.line == 7
    assert f.confidence_range == (75, 100)


def test_expected_finding_allows_omitted_optional_fields() -> None:
    from secureclaw.dev.corpus import ExpectedFinding

    f = ExpectedFinding(pattern_id="PI-005")
    assert f.pattern_id == "PI-005"
    assert f.line is None
    assert f.confidence_range is None


def test_expected_finding_rejects_bad_pattern_id() -> None:
    from secureclaw.dev.corpus import ExpectedFinding

    with pytest.raises(ValueError, match="pattern_id"):
        ExpectedFinding(pattern_id="not-a-real-id")


def test_expected_finding_rejects_line_below_one() -> None:
    from secureclaw.dev.corpus import ExpectedFinding

    with pytest.raises(ValueError, match="line"):
        ExpectedFinding(pattern_id="PI-005", line=0)


def test_expected_finding_rejects_inverted_confidence_range() -> None:
    from secureclaw.dev.corpus import ExpectedFinding

    with pytest.raises(ValueError, match="confidence_range"):
        ExpectedFinding(pattern_id="PI-005", confidence_range=(80, 50))


def test_expected_finding_rejects_out_of_bounds_confidence() -> None:
    from secureclaw.dev.corpus import ExpectedFinding

    with pytest.raises(ValueError):
        ExpectedFinding(pattern_id="PI-005", confidence_range=(-1, 50))
    with pytest.raises(ValueError):
        ExpectedFinding(pattern_id="PI-005", confidence_range=(50, 101))


def _valid_fixture_dict() -> dict:
    return {
        "schema_version": 2,
        "file": "echoleak_ref_markdown.md",
        "mode": "exact",
        "expected_findings": [{"pattern_id": "PI-005", "line": 7, "confidence_range": [75, 100]}],
        "forbidden_findings": ["PI-001"],
        "source": "EchoLeak CVE-2025-32711 (synthetic reproduction)",
        "license": "MIT (own work)",
        "category": "reference_link_exfil",
        "added_in_pr": "#TBD-C",
        "anonymization": {"applied": False},
    }


def test_fixture_from_dict_round_trip() -> None:
    from secureclaw.dev.corpus import Fixture

    d = _valid_fixture_dict()
    f = Fixture.from_dict(d, path=Path("positive/echoleak_ref_markdown.md.expected.json"))
    assert f.schema_version == 2
    assert f.file == "echoleak_ref_markdown.md"
    assert f.mode == "exact"
    assert len(f.expected_findings) == 1
    assert f.expected_findings[0].pattern_id == "PI-005"
    assert f.forbidden_findings == ("PI-001",)
    assert f.source.startswith("EchoLeak")
    assert f.license == "MIT (own work)"
    assert f.category == "reference_link_exfil"
    assert f.added_in_pr == "#TBD-C"
    assert f.anonymization == {"applied": False}


def test_fixture_round_trip_to_dict() -> None:
    from secureclaw.dev.corpus import Fixture

    d = _valid_fixture_dict()
    f = Fixture.from_dict(d, path=Path("x/y.expected.json"))
    out = f.to_dict()
    # Round-trip preserves all fields (no extras introduced or required-field loss).
    assert out["schema_version"] == 2
    assert out["file"] == d["file"]
    assert out["mode"] == d["mode"]
    assert out["source"] == d["source"]
    assert out["license"] == d["license"]


def test_fixture_accepts_optional_attribution_fields() -> None:
    """Spec §11 schema bump — these optional fields are valid."""
    from secureclaw.dev.corpus import Fixture

    d = _valid_fixture_dict()
    d["upstream_url"] = "https://github.com/example/repo"
    d["upstream_commit"] = "abc1234567"
    d["derived_from"] = "Vigil v1.2.0"
    d["regression_of"] = "#42"

    f = Fixture.from_dict(d, path=Path("x.expected.json"))
    assert f.upstream_url == "https://github.com/example/repo"
    assert f.upstream_commit == "abc1234567"
    assert f.derived_from == "Vigil v1.2.0"
    assert f.regression_of == "#42"


def test_fixture_rejects_unknown_extra_field() -> None:
    from secureclaw.dev.corpus import Fixture

    d = _valid_fixture_dict()
    d["foo_bar"] = "should not be accepted"

    with pytest.raises(ValueError, match="unknown field"):
        Fixture.from_dict(d, path=Path("x.expected.json"))


def test_fixture_rejects_missing_required_field() -> None:
    from secureclaw.dev.corpus import Fixture

    d = _valid_fixture_dict()
    del d["mode"]

    with pytest.raises(ValueError, match="mode"):
        Fixture.from_dict(d, path=Path("x.expected.json"))


def test_fixture_rejects_wrong_schema_version() -> None:
    from secureclaw.dev.corpus import Fixture

    d = _valid_fixture_dict()
    d["schema_version"] = 99

    with pytest.raises(ValueError, match="schema_version"):
        Fixture.from_dict(d, path=Path("x.expected.json"))


def test_fixture_rejects_invalid_mode() -> None:
    from secureclaw.dev.corpus import Fixture

    d = _valid_fixture_dict()
    d["mode"] = "fuzzy"

    with pytest.raises(ValueError, match="mode"):
        Fixture.from_dict(d, path=Path("x.expected.json"))


def test_validation_error_carries_path_severity_message() -> None:
    from secureclaw.dev.corpus import ValidationError

    e = ValidationError(
        path=Path("tests/corpus/positive/x.expected.json"),
        severity="error",
        message="missing required field 'mode'",
    )
    assert e.path == Path("tests/corpus/positive/x.expected.json")
    assert e.severity == "error"
    assert "missing required field" in e.message


def test_validation_error_severity_must_be_error_or_warning() -> None:
    from secureclaw.dev.corpus import ValidationError

    with pytest.raises(ValueError, match="severity"):
        ValidationError(path=Path("x"), severity="critical", message="x")


def test_anonymize_report_constructs_with_processed_and_refused_lists() -> None:
    from secureclaw.dev.corpus import AnonymizeReport

    r = AnonymizeReport(
        src_root=Path("/tmp/src"),
        dst_root=Path("/tmp/dst"),
        processed=2,
        refused=1,
        skipped=3,
        errors=0,
    )
    assert r.processed == 2
    assert r.refused == 1
    assert r.skipped == 3
    assert r.errors == 0
    assert r.exit_code() == 1  # any refused/error → non-zero


def test_anonymize_report_exit_code_zero_when_all_clean() -> None:
    from secureclaw.dev.corpus import AnonymizeReport

    r = AnonymizeReport(
        src_root=Path("/tmp/src"),
        dst_root=Path("/tmp/dst"),
        processed=5,
        refused=0,
        skipped=0,
        errors=0,
    )
    assert r.exit_code() == 0


def test_refusal_reason_values_match_spec() -> None:
    """Spec §4.1 — RefusalReason Literal includes these values."""
    from typing import get_args

    from secureclaw.dev.corpus import RefusalReason

    expected = {
        "secureclaw",
        "gitleaks",
        "trufflehog",
        "entropy_gate",
        "shape_check",
        "permission_error",
        "unicode_error",
        "disk_full",
    }
    assert set(get_args(RefusalReason)) == expected
