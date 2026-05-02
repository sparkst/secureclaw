"""Tests for secureclaw.dev.corpus.loader and .schema (spec §13.2).

TDD red phase: this file lands BEFORE loader.py / schema.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


# --- helpers ----------------------------------------------------------------


def _write_fixture(
    root: Path,
    klass: str,
    name: str,
    *,
    content: str = "synthetic content\n",
    expected: dict = None,  # type: ignore[assignment]
    sub: str = "",
) -> Path:
    """Write a content file plus its .expected.json into root/klass[/sub]/."""
    target_dir = root / klass / sub if sub else root / klass
    target_dir.mkdir(parents=True, exist_ok=True)
    content_path = target_dir / name
    content_path.write_text(content, encoding="utf-8")

    expected_data = expected or {
        "schema_version": 2,
        "file": name,
        "mode": "exact",
        "expected_findings": [],
        "source": "own work",
        "license": "MIT (own work)",
    }
    expected_path = target_dir / f"{name}.expected.json"
    expected_path.write_text(json.dumps(expected_data, indent=2), encoding="utf-8")
    return content_path


# --- schema ------------------------------------------------------------------


def test_load_schema_returns_dict_with_schema_version_2() -> None:
    from secureclaw.dev.corpus.schema import load_schema

    schema = load_schema()
    assert isinstance(schema, dict)
    # The schema is a JSON Schema; schema_version is enforced via const: 2.
    assert schema["properties"]["schema_version"]["const"] == 2


def test_validate_against_schema_passes_valid_data() -> None:
    from secureclaw.dev.corpus.schema import validate_against_schema

    valid = {
        "schema_version": 2,
        "file": "x.md",
        "mode": "exact",
        "source": "own work",
        "license": "MIT (own work)",
    }
    # Returns None or list-of-errors; passing data → empty error list.
    errors = validate_against_schema(valid)
    assert errors == []


def test_validate_against_schema_rejects_missing_required_field() -> None:
    from secureclaw.dev.corpus.schema import validate_against_schema

    invalid = {
        "schema_version": 2,
        "file": "x.md",
        # missing mode, source, license
    }
    errors = validate_against_schema(invalid)
    assert len(errors) >= 1


def test_validate_against_schema_rejects_unknown_property() -> None:
    from secureclaw.dev.corpus.schema import validate_against_schema

    invalid = {
        "schema_version": 2,
        "file": "x.md",
        "mode": "exact",
        "source": "own work",
        "license": "MIT (own work)",
        "extraneous_property": "not allowed",
    }
    errors = validate_against_schema(invalid)
    assert len(errors) >= 1


def test_validate_against_schema_accepts_upstream_url_after_bump(tmp_path: Path) -> None:
    """Spec §11 schema bump — upstream_url is optional and accepted."""
    from secureclaw.dev.corpus.schema import validate_against_schema

    valid = {
        "schema_version": 2,
        "file": "x.md",
        "mode": "exact",
        "source": "Vigil",
        "license": "Apache-2.0",
        "upstream_url": "https://github.com/example/repo",
        "upstream_commit": "abc1234",
        "derived_from": "Vigil v1.2.0",
        "regression_of": "#42",
    }
    errors = validate_against_schema(valid)
    assert errors == []


# --- loader ------------------------------------------------------------------


def test_load_fixtures_empty_root_returns_empty_list(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.loader import load_fixtures

    fixtures = load_fixtures(tmp_path)
    assert fixtures == []


def test_load_fixtures_returns_all_fixtures_under_root(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.loader import load_fixtures

    _write_fixture(tmp_path, "positive", "a.md")
    _write_fixture(tmp_path, "negative", "b.md")
    _write_fixture(tmp_path, "borderline", "c.md")

    fixtures = load_fixtures(tmp_path)
    assert len(fixtures) == 3
    files = {f.file for f in fixtures}
    assert files == {"a.md", "b.md", "c.md"}


def test_load_fixtures_filter_by_class(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.loader import load_fixtures

    _write_fixture(tmp_path, "positive", "a.md")
    _write_fixture(tmp_path, "negative", "b.md")

    only_positive = load_fixtures(tmp_path, klass="positive")
    assert len(only_positive) == 1
    assert only_positive[0].file == "a.md"


def test_load_fixtures_filter_by_pattern_id(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.loader import load_fixtures

    _write_fixture(
        tmp_path,
        "positive",
        "a.md",
        expected={
            "schema_version": 2,
            "file": "a.md",
            "mode": "superset",
            "expected_findings": [{"pattern_id": "PI-001"}],
            "source": "own work",
            "license": "MIT (own work)",
        },
    )
    _write_fixture(
        tmp_path,
        "positive",
        "b.md",
        expected={
            "schema_version": 2,
            "file": "b.md",
            "mode": "superset",
            "expected_findings": [{"pattern_id": "PI-005"}],
            "source": "own work",
            "license": "MIT (own work)",
        },
    )

    only_pi001 = load_fixtures(tmp_path, pattern_id="PI-001")
    assert len(only_pi001) == 1
    assert only_pi001[0].file == "a.md"


def test_load_fixtures_handles_regression_subgroup(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.loader import load_fixtures

    _write_fixture(
        tmp_path,
        "regression",
        "lauren_email.md",
        sub="lauren",
        expected={
            "schema_version": 2,
            "file": "lauren_email.md",
            "mode": "exact",
            "source": "own work",
            "license": "MIT (own work)",
            "regression_of": "#42",
        },
    )

    fixtures = load_fixtures(tmp_path)
    assert len(fixtures) == 1
    assert fixtures[0].file == "lauren_email.md"
    # klass() correctly identifies "regression" even with subgroup nesting.
    assert fixtures[0].klass() == "regression"


def test_load_fixtures_warns_on_orphan_content_file(tmp_path: Path, capsys) -> None:
    """A content file without a sibling .expected.json triggers a stderr warning."""
    from secureclaw.dev.corpus.loader import load_fixtures

    (tmp_path / "positive").mkdir(parents=True, exist_ok=True)
    (tmp_path / "positive" / "orphan.md").write_text("hello", encoding="utf-8")

    fixtures = load_fixtures(tmp_path)
    assert fixtures == []  # orphan is skipped
    captured = capsys.readouterr()
    assert "orphan" in captured.err.lower() or "expected.json" in captured.err.lower()


def test_iter_fixtures_is_an_iterator(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.loader import iter_fixtures

    _write_fixture(tmp_path, "positive", "a.md")
    _write_fixture(tmp_path, "positive", "b.md")

    it = iter_fixtures(tmp_path)
    # next() proves it's a true iterator (generator), not just a list.
    first = next(it)
    assert first.file in {"a.md", "b.md"}
    second = next(it)
    assert second.file in {"a.md", "b.md"}
    with pytest.raises(StopIteration):
        next(it)


def test_load_fixtures_skips_non_corpus_directories(tmp_path: Path) -> None:
    """Files outside the 5 valid class directories are ignored."""
    from secureclaw.dev.corpus.loader import load_fixtures

    _write_fixture(tmp_path, "positive", "a.md")
    # File in a non-class directory should be ignored.
    (tmp_path / "benchmarks").mkdir(parents=True, exist_ok=True)
    (tmp_path / "benchmarks" / "stuff.md").write_text("x", encoding="utf-8")

    fixtures = load_fixtures(tmp_path)
    assert len(fixtures) == 1
    assert fixtures[0].file == "a.md"
