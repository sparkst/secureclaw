"""Tests for ``secureclaw.dev.rule.runner`` (spec §9.4).

Mocks ``scan_file`` to make per-fixture PASS/FAIL deterministic. Verifies
that the negative-fixture lookup uses ``load_fixtures(klass='negative')``
followed by a post-filter on ``fixture.forbidden_findings`` (the P1 fix —
PR-C's ``pattern_id`` filter only inspects ``expected_findings``, so it
won't surface negative fixtures that forbid the rule).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List

import pytest


# --- helpers ---------------------------------------------------------------


def _make_rules_file(path: Path, ids: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    patterns = []
    for rid in ids:
        patterns.append(
            {
                "id": rid,
                "name": rid,
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
        )
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


def _write_positive(corpus: Path, rule_id: str, name: str) -> Path:
    pos = corpus / "positive"
    pos.mkdir(parents=True, exist_ok=True)
    content = pos / f"{name}.md"
    content.write_text("foo bar\n", encoding="utf-8")
    meta_path = pos / f"{name}.md.expected.json"
    meta_path.write_text(
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
    return content


def _write_negative(corpus: Path, rule_id: str, name: str) -> Path:
    neg = corpus / "negative"
    neg.mkdir(parents=True, exist_ok=True)
    content = neg / f"{name}.md"
    content.write_text("benign\n", encoding="utf-8")
    meta_path = neg / f"{name}.md.expected.json"
    meta_path.write_text(
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
    return content


class _StubFinding:
    """Minimal finding shape used by the runner."""

    def __init__(self, pattern_id: str, confidence: int = 80):
        self.pattern_id = pattern_id
        self.confidence = confidence


class _StubFileResult:
    def __init__(self, findings: List[_StubFinding]):
        self.findings = findings


def _patch_scan(monkeypatch, mapping: dict) -> None:
    """Patch ``secureclaw.dev.rule.runner.scan_file`` to return a stub keyed by path name."""

    def fake_scan_file(path: Path, *args: Any, **kwargs: Any) -> _StubFileResult:
        finds = mapping.get(path.name, [])
        return _StubFileResult(finds)

    import secureclaw.dev.rule.runner as runner_module

    monkeypatch.setattr(runner_module, "scan_file", fake_scan_file)


# --- positive fixture pass / fail ------------------------------------------


def test_positive_pass_when_scanner_fires(tmp_path: Path, monkeypatch) -> None:
    from secureclaw.dev.rule.runner import test_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_rules_file(rules, ["PI-N06"])
    _write_positive(corpus, "PI-N06", "canon")

    _patch_scan(monkeypatch, {"canon.md": [_StubFinding("PI-N06")]})

    result = test_rule("PI-N06", rules_file=rules, corpus_root=corpus)
    assert result.rule_id == "PI-N06"
    assert len(result.positives) == 1
    assert result.positives[0][1] is True
    assert result.passed is True


def test_positive_fail_when_scanner_does_not_fire(
    tmp_path: Path, monkeypatch
) -> None:
    from secureclaw.dev.rule.runner import test_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_rules_file(rules, ["PI-N06"])
    _write_positive(corpus, "PI-N06", "canon")

    _patch_scan(monkeypatch, {"canon.md": []})

    result = test_rule("PI-N06", rules_file=rules, corpus_root=corpus)
    assert result.positives[0][1] is False
    assert "did not fire" in result.positives[0][2].lower() or result.positives[0][2]
    assert result.passed is False


# --- negative fixture pass / fail ------------------------------------------


def test_negative_pass_when_rule_does_not_fire(
    tmp_path: Path, monkeypatch
) -> None:
    from secureclaw.dev.rule.runner import test_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_rules_file(rules, ["PI-N06"])
    _write_positive(corpus, "PI-N06", "canon")
    _write_negative(corpus, "PI-N06", "benign")

    _patch_scan(
        monkeypatch,
        {
            "canon.md": [_StubFinding("PI-N06")],
            "benign.md": [],  # no findings on negative
        },
    )

    result = test_rule("PI-N06", rules_file=rules, corpus_root=corpus)
    assert len(result.negatives) == 1
    assert result.negatives[0][1] is True
    assert result.passed is True


def test_negative_fail_when_rule_fires(tmp_path: Path, monkeypatch) -> None:
    from secureclaw.dev.rule.runner import test_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_rules_file(rules, ["PI-N06"])
    _write_positive(corpus, "PI-N06", "canon")
    _write_negative(corpus, "PI-N06", "benign")

    _patch_scan(
        monkeypatch,
        {
            "canon.md": [_StubFinding("PI-N06")],
            "benign.md": [_StubFinding("PI-N06", confidence=80)],
        },
    )

    result = test_rule("PI-N06", rules_file=rules, corpus_root=corpus)
    assert result.negatives[0][1] is False
    assert result.passed is False


# --- The P1 fix: negative lookup must use post-filter ----------------------


def test_negative_lookup_uses_post_filter_not_pattern_id_filter(
    tmp_path: Path, monkeypatch
) -> None:
    """If the runner used ``load_fixtures(pattern_id=<id>)`` for negatives,
    it would find ZERO negatives because that filter only matches
    ``expected_findings``. Our negative fixtures declare PI-N06 in
    ``forbidden_findings``, never in ``expected_findings``.

    By asserting we DO see the negative (and it passes), we verify the
    runner correctly uses the post-filter on ``forbidden_findings``.
    """
    from secureclaw.dev.rule.runner import test_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_rules_file(rules, ["PI-N06"])
    _write_positive(corpus, "PI-N06", "canon")
    _write_negative(corpus, "PI-N06", "benign")

    _patch_scan(
        monkeypatch,
        {"canon.md": [_StubFinding("PI-N06")], "benign.md": []},
    )

    result = test_rule("PI-N06", rules_file=rules, corpus_root=corpus)
    # If the runner used pattern_id filter, len(negatives) would be 0.
    assert len(result.negatives) == 1, (
        f"runner must locate the negative via forbidden_findings post-filter, "
        f"got {result.negatives!r}"
    )


# --- test_all_rules --------------------------------------------------------


def test_test_all_rules_walks_every_rule(tmp_path: Path, monkeypatch) -> None:
    from secureclaw.dev.rule.runner import test_all_rules

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_rules_file(rules, ["PI-N06", "PI-N07"])
    _write_positive(corpus, "PI-N06", "canon6")
    _write_negative(corpus, "PI-N06", "benign6")
    _write_positive(corpus, "PI-N07", "canon7")
    _write_negative(corpus, "PI-N07", "benign7")

    _patch_scan(
        monkeypatch,
        {
            "canon6.md": [_StubFinding("PI-N06")],
            "canon7.md": [_StubFinding("PI-N07")],
            "benign6.md": [],
            "benign7.md": [],
        },
    )

    results = test_all_rules(rules_file=rules, corpus_root=corpus)
    ids = {r.rule_id for r in results}
    assert ids == {"PI-N06", "PI-N07"}
    assert all(r.passed for r in results)


def test_test_all_rules_reports_failures(tmp_path: Path, monkeypatch) -> None:
    from secureclaw.dev.rule.runner import test_all_rules

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_rules_file(rules, ["PI-N06"])
    _write_positive(corpus, "PI-N06", "canon")
    _write_negative(corpus, "PI-N06", "benign")

    _patch_scan(
        monkeypatch,
        {"canon.md": [], "benign.md": []},  # positive does not fire -> FAIL
    )

    results = test_all_rules(rules_file=rules, corpus_root=corpus)
    assert len(results) == 1
    assert results[0].passed is False


# --- unknown rule ----------------------------------------------------------


def test_test_rule_unknown_id_raises(tmp_path: Path) -> None:
    from secureclaw.dev.rule.runner import test_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_rules_file(rules, ["PI-N06"])

    with pytest.raises(ValueError, match="not found|unknown"):
        test_rule("PI-NOPE", rules_file=rules, corpus_root=corpus)
