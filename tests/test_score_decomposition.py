"""Property tests for the PR-A3 score decomposition.

Per v1.3-plan-v10 §B.5: ``match_quality.py`` is content-only;
``path_heuristics.py`` is path-only. These tests assert the purity
invariants — moving a finding to a different file path must not change
the match-quality adjustment, and changing the matched text must not
change the path-heuristics adjustment.

Failures here mean the decomposition leaked a content signal into the
path layer (or vice versa) — which would break the v1.3 calibration
phase that fits weights independently per layer.
"""

from __future__ import annotations

from pathlib import Path

from secureclaw.core import confidence
from secureclaw.core.match_quality import ScoreAdjustment, score_match_content
from secureclaw.core.models import (
    FileContext,
    Finding,
    PatternCategory,
    Severity,
)
from secureclaw.core.path_heuristics import score_path_heuristics


def _make_finding(
    pattern_id: str = "PI-001",
    matched_text: str = "ignore previous instructions",
    path: str = "/tmp/test.md",
    file_context: FileContext = FileContext.USER_CONTENT,
) -> Finding:
    return Finding(
        file_path=Path(path),
        line_number=1,
        pattern_id=pattern_id,
        pattern_name="Test",
        severity=Severity.HIGH,
        category=PatternCategory.INSTRUCTION_OVERRIDE,
        matched_text=matched_text,
        description="",
        remediation="",
        context_before="",
        context_after="",
        file_context=file_context,
    )


def test_match_quality_returns_score_adjustment() -> None:
    f = _make_finding()
    adj = score_match_content(f)
    assert isinstance(adj, ScoreAdjustment)


def test_path_heuristics_returns_score_adjustment() -> None:
    f = _make_finding()
    adj = score_path_heuristics(f)
    assert isinstance(adj, ScoreAdjustment)


def test_match_quality_ignores_path() -> None:
    """Property: changing only the file path must not change match_quality."""
    f1 = _make_finding(path="/Users/alice/Documents/test.md")
    f2 = _make_finding(path="/var/log/archive/old/test.md")
    f3 = _make_finding(path="C:\\Users\\bob\\.env")

    a1 = score_match_content(f1)
    a2 = score_match_content(f2)
    a3 = score_match_content(f3)

    assert a1.delta == a2.delta == a3.delta, (
        f"match_quality must be path-invariant; got {a1.delta=} {a2.delta=} {a3.delta=}"
    )
    assert a1.reasons == a2.reasons == a3.reasons


def test_path_heuristics_ignores_match_text() -> None:
    """Property: changing only the matched text must not change path_heuristics."""
    f1 = _make_finding(matched_text="ignore previous instructions")
    f2 = _make_finding(matched_text="some completely different content")
    f3 = _make_finding(matched_text="")

    a1 = score_path_heuristics(f1)
    a2 = score_path_heuristics(f2)
    a3 = score_path_heuristics(f3)

    assert a1.delta == a2.delta == a3.delta, (
        f"path_heuristics must be match-text-invariant; got {a1.delta=} {a2.delta=} {a3.delta=}"
    )
    assert a1.reasons == a2.reasons == a3.reasons


def test_path_heuristics_ignores_file_context() -> None:
    """Property: file_context is content-derived; path_heuristics ignores it."""
    f1 = _make_finding(file_context=FileContext.USER_CONTENT)
    f2 = _make_finding(file_context=FileContext.AI_CONFIG)
    f3 = _make_finding(file_context=FileContext.TEST_FIXTURE)

    a1 = score_path_heuristics(f1)
    a2 = score_path_heuristics(f2)
    a3 = score_path_heuristics(f3)

    assert a1.delta == a2.delta == a3.delta


def test_match_quality_pi022_token_prefix() -> None:
    """PI-022 with sk-ant- prefix → +40 from match_quality."""
    f = _make_finding(
        pattern_id="PI-022",
        matched_text="ANTHROPIC_KEY=sk-ant-api03-abcdef1234567890",
    )
    adj = score_match_content(f)
    assert adj.delta == 40
    assert adj.fix_action == "redact_credential"
    assert adj.auto_fixable


def test_match_quality_pi022_placeholder_value() -> None:
    """PI-022 with placeholder text → -45 from match_quality (negative)."""
    f = _make_finding(
        pattern_id="PI-022",
        matched_text="API_KEY=YOUR_TOKEN_HERE",
    )
    adj = score_match_content(f)
    assert adj.delta == -45
    assert adj.fix_action == "allowlist"


def test_match_quality_test_fixture_demotion() -> None:
    f = _make_finding(file_context=FileContext.TEST_FIXTURE)
    adj = score_match_content(f)
    assert adj.delta == -30
    assert "Test fixture" in adj.reasons


def test_path_heuristics_archive_demotion() -> None:
    f = _make_finding(path="/Users/alice/archive/old-file.md")
    adj = score_path_heuristics(f)
    # archive: -20
    assert adj.delta == -20
    assert any("Archive" in r for r in adj.reasons)


def test_path_heuristics_active_env_boost() -> None:
    f = _make_finding(pattern_id="PI-022", path="/Users/alice/.env")
    adj = score_path_heuristics(f)
    assert adj.delta == 15
    assert any("Active environment" in r for r in adj.reasons)


def test_path_heuristics_active_env_in_archive_no_boost() -> None:
    """An .env file inside /archive/ does NOT get the active-env boost."""
    f = _make_finding(pattern_id="PI-022", path="/Users/alice/archive/.env")
    adj = score_path_heuristics(f)
    # archive (-20); no active-env boost
    assert adj.delta == -20


def test_path_heuristics_secureclaw_self_reference() -> None:
    """secureclaw self-ref demotes by -35; PI-022 exempt from self-ref penalty.

    Note: ``secureclaw`` also appears in SECURITY_RESEARCH_INDICATORS, so
    paths under ``/repo/secureclaw/`` get -25 (research) + -35 (self-ref) =
    -60 for non-PI-022 patterns. PI-022 only takes the -25 research demotion.
    """
    f = _make_finding(pattern_id="PI-001", path="/repo/secureclaw/rules/x.json")
    adj = score_path_heuristics(f)
    # research (-25) + self-ref (-35) = -60
    assert adj.delta == -60

    f2 = _make_finding(pattern_id="PI-022", path="/repo/secureclaw/rules/x.json")
    adj2 = score_path_heuristics(f2)
    # PI-022 exempt from self-ref; research demotion still applies (-25)
    assert adj2.delta == -25


def test_composite_score_is_sum() -> None:
    """confidence.score_finding = baseline(50) + content_delta + path_delta, clamped."""
    f = _make_finding(
        pattern_id="PI-022",
        matched_text="STRIPE_KEY=sk-ant-api03-abc",
        path="/Users/alice/.env",
    )
    confidence.score_finding(f)
    # 50 baseline + 40 (PI-022 prefix) + 15 (active env) = 105 → clamp to 100
    assert f.confidence == 100


def test_composite_score_clamps_at_zero() -> None:
    f = _make_finding(
        pattern_id="PI-022",
        matched_text="API_KEY=YOUR_TOKEN_HERE",  # placeholder: -45
        path="/Users/alice/archive/secureclaw/test.json",  # archive: -20
        file_context=FileContext.TEST_FIXTURE,  # -30
    )
    confidence.score_finding(f)
    # 50 + (-45) + (-20) + (-30) = -45 → clamp to 0
    assert f.confidence == 0
    assert f.triage.value == "suppressed"


def test_fix_action_content_takes_precedence_over_path() -> None:
    """When both layers set a fix_action, content layer wins."""
    f = _make_finding(
        pattern_id="PI-022",
        matched_text="API_KEY=YOUR_TOKEN_HERE",  # placeholder → allowlist
        path="/Users/alice/archive/.env",  # archive → redact_credential (PI-022)
    )
    confidence.score_finding(f)
    # Content layer (placeholder → allowlist) takes precedence
    assert f.fix_action == "allowlist"
