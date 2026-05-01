"""Tests for the legacy engine snapshot + dispatcher (PR-A4).

Covers:
- secureclaw/legacy/v1_engine.py exists and exports score_findings.
- _canonical_engine_setting handles all aliases and unknown values.
- get_active_engine reads SECURECLAW_ENGINE and applies precedence.
- The Tier A banner emits to stderr when legacy is active at import time.
- score_findings result-equality between confidence.py and v1_engine.py
  (proves the snapshot is faithful at the Foundation cut).
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import secureclaw
from secureclaw import _canonical_engine_setting, get_active_engine
from secureclaw.core import confidence
from secureclaw.core.models import (
    FileContext,
    Finding,
    PatternCategory,
    Severity,
)
from secureclaw.legacy import v1_engine


def test_legacy_module_exists() -> None:
    path = Path(secureclaw.__file__).parent / "legacy" / "v1_engine.py"
    assert path.is_file(), "legacy/v1_engine.py snapshot missing"


def test_legacy_module_exports_score_findings() -> None:
    assert callable(v1_engine.score_findings)
    assert callable(v1_engine.score_finding)


def test_canonicalizer_aliases() -> None:
    assert _canonical_engine_setting("v1") == "legacy"
    assert _canonical_engine_setting("V1") == "legacy"
    assert _canonical_engine_setting("legacy") == "legacy"
    assert _canonical_engine_setting("LEGACY") == "legacy"
    assert _canonical_engine_setting("1") == "legacy"
    assert _canonical_engine_setting(" v1 ") == "legacy"


def test_canonicalizer_default_aliases() -> None:
    assert _canonical_engine_setting("default") == "default"
    assert _canonical_engine_setting("v2") == "default"
    assert _canonical_engine_setting("2") == "default"
    assert _canonical_engine_setting("") == "default"
    assert _canonical_engine_setting(None) == "default"


def test_canonicalizer_unknown_failsafe() -> None:
    """REQ-18 fail-safe: unknown values normalize to default."""
    assert _canonical_engine_setting("garbage") == "default"
    assert _canonical_engine_setting("v9999") == "default"


def test_get_active_engine_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURECLAW_ENGINE", "v1")
    assert get_active_engine() == "legacy"
    monkeypatch.setenv("SECURECLAW_ENGINE", "default")
    assert get_active_engine() == "default"
    monkeypatch.delenv("SECURECLAW_ENGINE", raising=False)
    assert get_active_engine() == "default"


def test_banner_emits_at_import_when_legacy_active(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """Re-import secureclaw with SECURECLAW_ENGINE=v1 and capture banner."""
    monkeypatch.setenv("SECURECLAW_ENGINE", "v1")
    # Force re-import so the banner logic runs again
    importlib.reload(secureclaw)
    captured = capsys.readouterr()
    assert "LEGACY ENGINE ACTIVE" in captured.err
    assert "PI-N01..PI-N14" in captured.err


def test_no_banner_when_default_engine(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.delenv("SECURECLAW_ENGINE", raising=False)
    importlib.reload(secureclaw)
    captured = capsys.readouterr()
    assert "LEGACY ENGINE" not in captured.err


def _make_finding(pattern_id: str = "PI-001", path: str = "/tmp/test.md") -> Finding:
    return Finding(
        file_path=Path(path),
        line_number=1,
        pattern_id=pattern_id,
        pattern_name="Test",
        severity=Severity.HIGH,
        category=PatternCategory.INSTRUCTION_OVERRIDE,
        matched_text="ignore previous instructions",
        description="",
        remediation="",
        context_before="",
        context_after="",
        file_context=FileContext.USER_CONTENT,
    )


def test_legacy_snapshot_matches_confidence_py_at_foundation_cut(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """At Foundation cut, legacy/v1_engine.py and core/confidence.py produce
    identical scoring. PR-A3 will diverge them; this test will need to track
    only the legacy snapshot from then on.
    """
    monkeypatch.delenv("SECURECLAW_ENGINE", raising=False)
    f1 = _make_finding()
    f2 = _make_finding()
    confidence.score_findings([f1])
    v1_engine.score_findings([f2])
    assert f1.confidence == f2.confidence
    assert f1.triage == f2.triage
    assert f1.confidence_reason == f2.confidence_reason
