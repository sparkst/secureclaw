"""Tests for ``secureclaw.dev.rule.scaffolder`` (spec §9.3).

TDD red phase: lands BEFORE the scaffolder module.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest


def _make_empty_rules_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "pattern_version": "1.3.0",
                "min_tool_version": "1.3.0",
                "description": "test rules",
                "patterns": [],
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _kwargs(**overrides: Any) -> Dict[str, Any]:
    base = dict(
        rule_id="PI-N06",
        name="Test Rule",
        category="instruction_override",
        severity="advisory",
        regex=r"\bfoo\b",
        description="Test description",
        remediation="Delete this text",
        source="own work",
        license="MIT (own work)",
    )
    base.update(overrides)
    return base


# --- Round trip: scaffold creates rule + fixtures --------------------------


def test_scaffold_appends_rule_to_json(tmp_path: Path) -> None:
    from secureclaw.dev.rule.scaffolder import scaffold_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_empty_rules_file(rules)

    scaffold_rule(rules_file=rules, corpus_root=corpus, **_kwargs())

    data = json.loads(rules.read_text(encoding="utf-8"))
    ids = [p["id"] for p in data["patterns"]]
    assert "PI-N06" in ids


def test_scaffold_creates_positive_fixture(tmp_path: Path) -> None:
    from secureclaw.dev.rule.scaffolder import scaffold_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_empty_rules_file(rules)

    scaffold_rule(rules_file=rules, corpus_root=corpus, **_kwargs())

    pos_dir = corpus / "positive"
    assert pos_dir.is_dir()
    # Must have at least one expected.json AND its content sibling.
    metas = list(pos_dir.glob("*.expected.json"))
    assert metas, "positive expected.json not created"
    meta = json.loads(metas[0].read_text(encoding="utf-8"))
    pids = [ef["pattern_id"] for ef in meta.get("expected_findings", [])]
    assert "PI-N06" in pids


def test_scaffold_creates_negative_fixture_with_forbidden_findings(
    tmp_path: Path,
) -> None:
    """The P1 fix: negative scaffolding writes expected.json directly with
    forbidden_findings listing the new rule id.
    """
    from secureclaw.dev.rule.scaffolder import scaffold_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_empty_rules_file(rules)

    scaffold_rule(rules_file=rules, corpus_root=corpus, **_kwargs())

    neg_dir = corpus / "negative"
    assert neg_dir.is_dir()
    metas = list(neg_dir.glob("*.expected.json"))
    assert metas, "negative expected.json not created"
    meta = json.loads(metas[0].read_text(encoding="utf-8"))
    forbidden = meta.get("forbidden_findings", [])
    assert "PI-N06" in forbidden, (
        f"negative fixture must declare PI-N06 in forbidden_findings, got {meta!r}"
    )
    # Negatives must not have expected_findings declaring this id.
    expected_ids = [ef.get("pattern_id") for ef in meta.get("expected_findings", [])]
    assert "PI-N06" not in expected_ids


# --- Refusals --------------------------------------------------------------


def test_scaffold_refuses_duplicate_id(tmp_path: Path) -> None:
    from secureclaw.dev.rule.scaffolder import scaffold_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_empty_rules_file(rules)

    scaffold_rule(rules_file=rules, corpus_root=corpus, **_kwargs())
    with pytest.raises(ValueError, match="already exists|duplicate"):
        scaffold_rule(rules_file=rules, corpus_root=corpus, **_kwargs())


def test_scaffold_refuses_blocklisted_license(tmp_path: Path) -> None:
    from secureclaw.dev.rule.scaffolder import scaffold_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_empty_rules_file(rules)

    with pytest.raises(ValueError, match="license"):
        scaffold_rule(
            rules_file=rules,
            corpus_root=corpus,
            **_kwargs(license="GPL-3.0"),
        )


def test_scaffold_refuses_malformed_id(tmp_path: Path) -> None:
    from secureclaw.dev.rule.scaffolder import scaffold_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_empty_rules_file(rules)

    with pytest.raises(ValueError):
        scaffold_rule(
            rules_file=rules,
            corpus_root=corpus,
            **_kwargs(rule_id="bogus"),
        )


def test_scaffold_refuses_malformed_regex(tmp_path: Path) -> None:
    from secureclaw.dev.rule.scaffolder import scaffold_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_empty_rules_file(rules)

    with pytest.raises(ValueError, match="regex"):
        scaffold_rule(
            rules_file=rules,
            corpus_root=corpus,
            **_kwargs(regex="["),
        )


def test_scaffold_refuses_non_synthetic_without_upstream(tmp_path: Path) -> None:
    """Non-synthetic license + no upstream_url -> reject in strict (new rule)."""
    from secureclaw.dev.rule.scaffolder import scaffold_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_empty_rules_file(rules)

    # source: 'Lakera Guard', license: 'Apache-2.0' triggers strict_attribution.
    with pytest.raises(ValueError, match="upstream"):
        scaffold_rule(
            rules_file=rules,
            corpus_root=corpus,
            **_kwargs(source="Lakera Guard", license="Apache-2.0"),
        )


def test_scaffold_passes_with_upstream_for_non_synthetic(tmp_path: Path) -> None:
    from secureclaw.dev.rule.scaffolder import scaffold_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_empty_rules_file(rules)

    scaffold_rule(
        rules_file=rules,
        corpus_root=corpus,
        upstream_url="https://github.com/lakera-ai/guard",
        upstream_commit="abc1234",
        **_kwargs(source="Lakera Guard", license="Apache-2.0"),
    )
    data = json.loads(rules.read_text(encoding="utf-8"))
    assert any(p["id"] == "PI-N06" for p in data["patterns"])


# --- Dry run ---------------------------------------------------------------


def test_scaffold_dry_run_does_not_write(tmp_path: Path) -> None:
    from secureclaw.dev.rule.scaffolder import scaffold_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_empty_rules_file(rules)
    before = rules.read_text(encoding="utf-8")

    scaffold_rule(rules_file=rules, corpus_root=corpus, dry_run=True, **_kwargs())

    after = rules.read_text(encoding="utf-8")
    assert before == after, "dry-run must not modify rules file"
    assert not (corpus / "positive").exists() or not list(
        (corpus / "positive").glob("*")
    )
    assert not (corpus / "negative").exists() or not list(
        (corpus / "negative").glob("*")
    )


# --- Atomic write ----------------------------------------------------------


def test_scaffold_atomic_write_on_validation_failure(
    tmp_path: Path, monkeypatch
) -> None:
    """If schema validation fails AFTER file mutation begins, no partial write."""
    from secureclaw.dev.rule.scaffolder import scaffold_rule

    rules = tmp_path / "rules.json"
    corpus = tmp_path / "corpus"
    _make_empty_rules_file(rules)
    before = rules.read_text(encoding="utf-8")

    # Force validate_rule to fail by injecting an invalid severity.
    with pytest.raises(ValueError):
        scaffold_rule(
            rules_file=rules,
            corpus_root=corpus,
            **_kwargs(severity="bogus"),
        )

    # Rules file unchanged.
    assert rules.read_text(encoding="utf-8") == before


# --- Helper directly --------------------------------------------------------


def test_scaffold_negative_helper_writes_expected_json_directly(
    tmp_path: Path,
) -> None:
    """The new private helper writes the negative expected.json directly,
    not via add_fixture (which rejects negative + pattern_id).
    """
    from secureclaw.dev.rule.scaffolder import _scaffold_negative

    corpus = tmp_path / "corpus"
    content = tmp_path / "src" / "benign.md"
    content.parent.mkdir(parents=True)
    content.write_text("benign content\n", encoding="utf-8")

    _scaffold_negative(
        content,
        forbidden_findings=("PI-N06",),
        source_attestation="own work",
        license="MIT (own work)",
        root=corpus,
    )

    neg_dir = corpus / "negative"
    assert (neg_dir / "benign.md").exists()
    meta_path = neg_dir / "benign.md.expected.json"
    assert meta_path.exists()
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["forbidden_findings"] == ["PI-N06"]
    assert meta["mode"] == "exact"
    assert meta["expected_findings"] == [] or "expected_findings" not in meta
