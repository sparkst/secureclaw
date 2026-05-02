"""Tests for secureclaw.dev.corpus.adder (spec §13.4).

TDD red phase: lands BEFORE adder.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _make_content(tmp_path: Path, name: str = "fixture.md", body: str = "synthetic\n") -> Path:
    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    p = src / name
    p.write_text(body, encoding="utf-8")
    return p


# --- happy path -------------------------------------------------------------


def test_add_fixture_round_trip_positive(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.adder import add_fixture

    src = _make_content(tmp_path)
    root = tmp_path / "corpus"
    fix = add_fixture(
        src,
        klass="positive",
        source_attestation="own work",
        license="MIT (own work)",
        pattern_id="PI-001",
        line=1,
        root=root,
    )
    # File copied into root/positive/.
    expected_content = root / "positive" / "fixture.md"
    assert expected_content.exists()
    expected_meta = root / "positive" / "fixture.md.expected.json"
    assert expected_meta.exists()
    data = json.loads(expected_meta.read_text(encoding="utf-8"))
    assert data["schema_version"] == 2
    assert data["file"] == "fixture.md"
    assert data["mode"] == "superset"  # default for positive
    assert data["expected_findings"][0]["pattern_id"] == "PI-001"
    assert data["added_in_pr"] == "#TBD-C"
    assert fix.file == "fixture.md"


def test_add_fixture_negative_without_pattern_id_succeeds(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.adder import add_fixture

    src = _make_content(tmp_path)
    root = tmp_path / "corpus"
    add_fixture(
        src,
        klass="negative",
        source_attestation="own work",
        license="MIT (own work)",
        root=root,
    )
    meta = root / "negative" / "fixture.md.expected.json"
    data = json.loads(meta.read_text(encoding="utf-8"))
    assert data["mode"] == "exact"  # default for negative
    assert data.get("expected_findings", []) == []


# --- refusals ---------------------------------------------------------------


def test_add_fixture_refuses_overwrite_without_force(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.adder import add_fixture

    src = _make_content(tmp_path)
    root = tmp_path / "corpus"
    add_fixture(
        src,
        klass="negative",
        source_attestation="own work",
        license="MIT (own work)",
        root=root,
    )
    with pytest.raises(FileExistsError):
        add_fixture(
            src,
            klass="negative",
            source_attestation="own work",
            license="MIT (own work)",
            root=root,
        )


def test_add_fixture_force_allows_overwrite(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.adder import add_fixture

    src = _make_content(tmp_path, body="first\n")
    root = tmp_path / "corpus"
    add_fixture(
        src,
        klass="negative",
        source_attestation="own work",
        license="MIT (own work)",
        root=root,
    )
    src.write_text("second\n", encoding="utf-8")
    add_fixture(
        src,
        klass="negative",
        source_attestation="own work",
        license="MIT (own work)",
        root=root,
        force=True,
    )
    assert (root / "negative" / "fixture.md").read_text(encoding="utf-8") == "second\n"


def test_add_fixture_refuses_positive_without_pattern_id(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.adder import add_fixture

    src = _make_content(tmp_path)
    root = tmp_path / "corpus"
    with pytest.raises(ValueError, match="pattern_id|pattern-id"):
        add_fixture(
            src,
            klass="positive",
            source_attestation="own work",
            license="MIT (own work)",
            root=root,
        )


def test_add_fixture_refuses_negative_with_pattern_id(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.adder import add_fixture

    src = _make_content(tmp_path)
    root = tmp_path / "corpus"
    with pytest.raises(ValueError, match="negative"):
        add_fixture(
            src,
            klass="negative",
            source_attestation="own work",
            license="MIT (own work)",
            pattern_id="PI-001",
            root=root,
        )


def test_add_fixture_refuses_regression_without_regression_of(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.adder import add_fixture

    src = _make_content(tmp_path)
    root = tmp_path / "corpus"
    with pytest.raises(ValueError, match="regression_of|--regression-of"):
        add_fixture(
            src,
            klass="regression",
            source_attestation="own work",
            license="MIT (own work)",
            root=root,
        )


def test_add_fixture_regression_with_regression_of_succeeds(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.adder import add_fixture

    src = _make_content(tmp_path)
    root = tmp_path / "corpus"
    add_fixture(
        src,
        klass="regression",
        source_attestation="own work",
        license="MIT (own work)",
        regression_of="#42",
        root=root,
    )
    meta = root / "regression" / "fixture.md.expected.json"
    data = json.loads(meta.read_text(encoding="utf-8"))
    assert data["regression_of"] == "#42"


def test_add_fixture_regression_group_subdir(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.adder import add_fixture

    src = _make_content(tmp_path)
    root = tmp_path / "corpus"
    add_fixture(
        src,
        klass="regression",
        source_attestation="own work",
        license="MIT (own work)",
        regression_of="#42",
        regression_group="lauren",
        root=root,
    )
    placed = root / "regression" / "lauren" / "fixture.md"
    assert placed.exists()
    assert (root / "regression" / "lauren" / "fixture.md.expected.json").exists()


# --- license gates ----------------------------------------------------------


def test_add_fixture_refuses_blocklist_license(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.adder import add_fixture

    src = _make_content(tmp_path)
    root = tmp_path / "corpus"
    with pytest.raises(ValueError, match="license"):
        add_fixture(
            src,
            klass="negative",
            source_attestation="own work",
            license="GPL-3.0",
            root=root,
        )


def test_add_fixture_refuses_share_alike_license(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.adder import add_fixture

    src = _make_content(tmp_path)
    root = tmp_path / "corpus"
    with pytest.raises(ValueError, match="license"):
        add_fixture(
            src,
            klass="negative",
            source_attestation="own work",
            license="CC-BY-SA-4.0",
            root=root,
        )


def test_add_fixture_refuses_unknown_license(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.adder import add_fixture

    src = _make_content(tmp_path)
    root = tmp_path / "corpus"
    with pytest.raises(ValueError, match="legal review|approved"):
        add_fixture(
            src,
            klass="negative",
            source_attestation="own work",
            license="Some Custom License Without Review",
            root=root,
        )


# --- generated meta validates against the schema ----------------------------


def test_add_fixture_generated_meta_validates(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.adder import add_fixture
    from secureclaw.dev.corpus.schema import validate_against_schema

    src = _make_content(tmp_path)
    root = tmp_path / "corpus"
    add_fixture(
        src,
        klass="positive",
        source_attestation="own work",
        license="MIT (own work)",
        pattern_id="PI-001",
        root=root,
    )
    data = json.loads((root / "positive" / "fixture.md.expected.json").read_text("utf-8"))
    assert validate_against_schema(data) == []


# --- next-step hint ---------------------------------------------------------


def test_add_fixture_prints_next_step_hint(tmp_path: Path, capsys) -> None:
    from secureclaw.dev.corpus.adder import add_fixture

    src = _make_content(tmp_path)
    root = tmp_path / "corpus"
    add_fixture(
        src,
        klass="positive",
        source_attestation="own work",
        license="MIT (own work)",
        pattern_id="PI-001",
        root=root,
    )
    captured = capsys.readouterr()
    assert "secureclaw dev corpus validate" in (captured.out + captured.err)


# --- set_pr_number ----------------------------------------------------------


def test_set_pr_number_updates_tbd_placeholder(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.adder import set_pr_number

    root = tmp_path / "corpus"
    (root / "positive").mkdir(parents=True)
    meta_a = root / "positive" / "a.md.expected.json"
    meta_a.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "file": "a.md",
                "mode": "exact",
                "source": "own work",
                "license": "MIT (own work)",
                "added_in_pr": "#TBD-C",
            }
        ),
        encoding="utf-8",
    )

    report = set_pr_number(root, 42)
    assert "updated" in report
    assert any("a.md.expected.json" in str(p) for p in report["updated"])
    data = json.loads(meta_a.read_text(encoding="utf-8"))
    assert data["added_in_pr"] == "#42"


def test_set_pr_number_dry_run_no_writes(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.adder import set_pr_number

    root = tmp_path / "corpus"
    (root / "positive").mkdir(parents=True)
    meta = root / "positive" / "a.md.expected.json"
    meta.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "file": "a.md",
                "mode": "exact",
                "source": "own work",
                "license": "MIT (own work)",
                "added_in_pr": "#TBD-C",
            }
        ),
        encoding="utf-8",
    )

    set_pr_number(root, 42, dry_run=True)
    data = json.loads(meta.read_text(encoding="utf-8"))
    assert data["added_in_pr"] == "#TBD-C"  # unchanged on dry run


def test_set_pr_number_skips_files_without_placeholder(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.adder import set_pr_number

    root = tmp_path / "corpus"
    (root / "negative").mkdir(parents=True)
    meta = root / "negative" / "no_placeholder.md.expected.json"
    meta.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "file": "no_placeholder.md",
                "mode": "exact",
                "source": "own work",
                "license": "MIT (own work)",
                "added_in_pr": "#7",
            }
        ),
        encoding="utf-8",
    )

    report = set_pr_number(root, 42)
    assert "skipped" in report
    assert any("no_placeholder" in str(p) for p in report["skipped"])
