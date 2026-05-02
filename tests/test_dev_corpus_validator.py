"""Tests for secureclaw.dev.corpus.validator (spec §13.3).

TDD red phase: this lands BEFORE validator.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _write(
    root: Path,
    klass: str,
    name: str,
    *,
    content: str = "synthetic\n",
    expected: dict = None,  # type: ignore[assignment]
    sub: str = "",
) -> tuple[Path, Path]:
    target = root / klass / sub if sub else root / klass
    target.mkdir(parents=True, exist_ok=True)
    cpath = target / name
    cpath.write_text(content, encoding="utf-8")
    epath = target / f"{name}.expected.json"
    epath.write_text(json.dumps(expected or {}, indent=2), encoding="utf-8")
    return cpath, epath


def _good_fixture(name: str = "x.md") -> dict:
    return {
        "schema_version": 2,
        "file": name,
        "mode": "exact",
        "source": "own work",
        "license": "MIT (own work)",
    }


# --- happy path -------------------------------------------------------------


def test_validate_corpus_passes_on_clean_seed(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.validator import validate_corpus

    _write(tmp_path, "positive", "a.md", expected=_good_fixture("a.md"))
    _write(tmp_path, "negative", "b.md", expected=_good_fixture("b.md"))

    errors = validate_corpus(tmp_path)
    # Filter out warnings; this fixture is clean.
    real_errors = [e for e in errors if e.severity == "error"]
    assert real_errors == []


def test_validate_corpus_passes_on_empty_root(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.validator import validate_corpus

    errors = validate_corpus(tmp_path)
    assert errors == []


# --- schema-level errors ----------------------------------------------------


def test_validate_corpus_catches_missing_required_field(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.validator import validate_corpus

    bad = _good_fixture("a.md")
    del bad["mode"]
    _write(tmp_path, "positive", "a.md", expected=bad)

    errors = validate_corpus(tmp_path)
    assert any(e.severity == "error" for e in errors)


def test_validate_corpus_catches_filename_mismatch(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.validator import validate_corpus

    bad = _good_fixture("not-on-disk.md")  # filename in metadata != actual
    _write(tmp_path, "positive", "actually.md", expected=bad)

    errors = validate_corpus(tmp_path)
    assert any("file" in e.message.lower() or "filename" in e.message.lower() for e in errors)


def test_validate_corpus_catches_bad_schema_version(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.validator import validate_corpus

    bad = _good_fixture("a.md")
    bad["schema_version"] = 99
    _write(tmp_path, "positive", "a.md", expected=bad)

    errors = validate_corpus(tmp_path)
    assert any(e.severity == "error" for e in errors)


# --- license blocklist ------------------------------------------------------


@pytest.mark.parametrize(
    "license_str",
    [
        "GPL-3.0",
        "GPL-2.0-only",
        "AGPL-3.0",
        "CC-BY-SA-4.0",
        "CC-BY-NC-4.0",
    ],
)
def test_validate_corpus_rejects_blocklist_license(tmp_path: Path, license_str: str) -> None:
    from secureclaw.dev.corpus.validator import validate_corpus

    bad = _good_fixture("a.md")
    bad["license"] = license_str
    bad["source"] = "Some Project"
    _write(tmp_path, "positive", "a.md", expected=bad)

    errors = validate_corpus(tmp_path)
    assert any("license" in e.message.lower() for e in errors)


# --- license allowlist ------------------------------------------------------


def test_validate_corpus_rejects_unknown_license(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.validator import validate_corpus

    bad = _good_fixture("a.md")
    bad["license"] = "Some weird custom license"
    _write(tmp_path, "positive", "a.md", expected=bad)

    errors = validate_corpus(tmp_path)
    assert any(
        "legal review" in e.message.lower() or "approved" in e.message.lower() for e in errors
    )


@pytest.mark.parametrize(
    "license_str",
    [
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "CC0-1.0",
        "CC-BY-4.0",
        "ISC",
        "synthetic",
        "Synthetic test data",
        "MIT (own work)",
        "MIT (derived)",
    ],
)
def test_validate_corpus_accepts_allowlist_license(tmp_path: Path, license_str: str) -> None:
    from secureclaw.dev.corpus.validator import validate_corpus

    good = _good_fixture("a.md")
    good["license"] = license_str
    # If license is non-synthetic & non-(own work), validator requires upstream_url
    if "synthetic" not in license_str.lower() and "(own work)" not in license_str.lower():
        good["upstream_url"] = "https://example.com/repo"
        good["source"] = "Some Public Source"
    _write(tmp_path, "positive", "a.md", expected=good)

    errors = validate_corpus(tmp_path)
    real_errors = [e for e in errors if e.severity == "error"]
    assert real_errors == []


# --- conditional upstream_url ----------------------------------------------


def test_validate_corpus_requires_upstream_url_for_non_synthetic_license(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.validator import validate_corpus

    bad = _good_fixture("a.md")
    bad["license"] = "Apache-2.0"
    bad["source"] = "Vigil"
    # upstream_url intentionally omitted
    _write(tmp_path, "positive", "a.md", expected=bad)

    errors = validate_corpus(tmp_path)
    assert any("upstream_url" in e.message for e in errors)


def test_validate_corpus_accepts_synthetic_without_upstream(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.validator import validate_corpus

    good = _good_fixture("a.md")
    good["license"] = "MIT (own work)"
    _write(tmp_path, "positive", "a.md", expected=good)

    errors = validate_corpus(tmp_path)
    real_errors = [e for e in errors if e.severity == "error"]
    assert real_errors == []


# --- conditional regression_of ---------------------------------------------


def test_validate_corpus_requires_regression_of_for_regression_class(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.validator import validate_corpus

    bad = _good_fixture("lauren.md")
    # Place under regression/ but omit regression_of
    _write(tmp_path, "regression", "lauren.md", expected=bad, sub="lauren")

    errors = validate_corpus(tmp_path)
    assert any("regression_of" in e.message for e in errors)


def test_validate_corpus_accepts_regression_with_regression_of(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.validator import validate_corpus

    good = _good_fixture("lauren.md")
    good["regression_of"] = "#42"
    _write(tmp_path, "regression", "lauren.md", expected=good, sub="lauren")

    errors = validate_corpus(tmp_path)
    real_errors = [e for e in errors if e.severity == "error"]
    assert real_errors == []


# --- expected_findings line/confidence checks -------------------------------


def test_validate_corpus_catches_line_out_of_range(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.validator import validate_corpus

    bad = _good_fixture("a.md")
    bad["expected_findings"] = [{"pattern_id": "PI-001", "line": 999}]
    _write(tmp_path, "positive", "a.md", content="line1\nline2\n", expected=bad)

    errors = validate_corpus(tmp_path)
    assert any("line" in e.message.lower() for e in errors)


# --- strict vs warn behavior on missing rule IDs ----------------------------


def test_validate_corpus_warns_on_unknown_pattern_id_non_strict(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.validator import validate_corpus

    bad = _good_fixture("a.md")
    bad["expected_findings"] = [{"pattern_id": "PI-N99"}]  # syntactically valid; doesn't exist yet
    _write(tmp_path, "positive", "a.md", expected=bad)

    errors = validate_corpus(tmp_path, strict=False)
    # In non-strict mode, this is a warning, not an error.
    assert any(e.severity == "warning" and "PI-N99" in e.message for e in errors)
    assert all(e.severity != "error" for e in errors if "PI-N99" in e.message)


def test_validate_corpus_errors_on_unknown_pattern_id_strict(tmp_path: Path) -> None:
    from secureclaw.dev.corpus.validator import validate_corpus

    bad = _good_fixture("a.md")
    bad["expected_findings"] = [{"pattern_id": "PI-N99"}]
    _write(tmp_path, "positive", "a.md", expected=bad)

    errors = validate_corpus(tmp_path, strict=True)
    assert any(e.severity == "error" and "PI-N99" in e.message for e in errors)


# --- error enumeration (no bail-on-first) -----------------------------------


def test_validate_corpus_lists_all_errors(tmp_path: Path) -> None:
    """Multiple bad fixtures: validator returns ALL errors."""
    from secureclaw.dev.corpus.validator import validate_corpus

    bad1 = _good_fixture("a.md")
    bad1["license"] = "GPL-3.0"
    _write(tmp_path, "positive", "a.md", expected=bad1)

    bad2 = _good_fixture("b.md")
    bad2["license"] = "AGPL-3.0"
    _write(tmp_path, "negative", "b.md", expected=bad2)

    errors = validate_corpus(tmp_path)
    error_paths = {e.path for e in errors if e.severity == "error"}
    # Both fixtures are present in the error list.
    assert len(error_paths) >= 2
