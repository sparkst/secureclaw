"""Validates that tests/corpus/ has the expected directory layout.

Foundation PR-A scaffolding test. Each subdirectory must exist and have a
.gitkeep so the empty dir is committed.
"""

from __future__ import annotations

from pathlib import Path

CORPUS_ROOT = Path(__file__).parent / "corpus"

EXPECTED_DIRS = [
    "positive",
    "negative",
    "borderline",
    "regression/lauren",
    "dos",
    "benchmarks/pint",
    "benchmarks/hackaprompt",
]

EXPECTED_FILES = [
    "README.md",
    "CONTRIBUTING.md",
    "expected-schema.json",
]


def test_corpus_directories_exist() -> None:
    for relpath in EXPECTED_DIRS:
        d = CORPUS_ROOT / relpath
        assert d.is_dir(), f"missing corpus directory: {d}"


def test_corpus_top_files_exist() -> None:
    for name in EXPECTED_FILES:
        f = CORPUS_ROOT / name
        assert f.is_file(), f"missing top-level corpus file: {f}"


def test_corpus_dirs_have_gitkeep() -> None:
    for relpath in EXPECTED_DIRS:
        gk = CORPUS_ROOT / relpath / ".gitkeep"
        assert gk.exists(), f"missing .gitkeep in {gk.parent}"
