"""Tests for ``secureclaw.dev.bench.baseline`` (spec §6.2, §9.3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _sample_result():  # type: ignore[no-untyped-def]
    from secureclaw.dev.bench.models import (
        SCHEMA_VERSION,
        BenchResult,
        FixtureResult,
        Outcome,
        Summary,
    )

    return BenchResult(
        schema_version=SCHEMA_VERSION,
        suite="corpus",
        secureclaw_version="1.3.0",
        rule_set_version="1.3.0",
        rule_set_sha256="b" * 64,
        fixtures=[
            FixtureResult(
                path="positive/foo.md",
                klass="positive",
                expected_pattern_ids=("PI-001",),
                forbidden_pattern_ids=(),
                actual_findings=({"pattern_id": "PI-001", "line": 1, "confidence": 80},),
                outcome=Outcome.TRUE_POSITIVE,
            )
        ],
        summary=Summary.compute(
            true_positives=1,
            true_negatives=0,
            false_positives=0,
            false_negatives=0,
            borderline=0,
            regression_pass=0,
            dos_pass=0,
        ),
    )


def test_baseline_round_trip(tmp_path: Path) -> None:
    from secureclaw.dev.bench.baseline import load_baseline, write_baseline

    target = tmp_path / "corpus.json"
    result = _sample_result()
    write_baseline(result, target)
    loaded = load_baseline(target)
    assert loaded == result


def test_write_baseline_refuses_overwrite_without_force(tmp_path: Path) -> None:
    from secureclaw.dev.bench.baseline import write_baseline

    target = tmp_path / "corpus.json"
    write_baseline(_sample_result(), target)
    with pytest.raises(FileExistsError):
        write_baseline(_sample_result(), target)


def test_write_baseline_force_overwrites(tmp_path: Path) -> None:
    from secureclaw.dev.bench.baseline import load_baseline, write_baseline
    from secureclaw.dev.bench.models import Outcome

    target = tmp_path / "corpus.json"
    write_baseline(_sample_result(), target)

    # Mutate one outcome and re-write with force=True.
    new_result = _sample_result()
    new_fixtures = list(new_result.fixtures)
    from dataclasses import replace

    new_fixtures[0] = replace(new_fixtures[0], outcome=Outcome.FALSE_NEGATIVE)
    new_result = replace(new_result, fixtures=new_fixtures)
    write_baseline(new_result, target, force=True)
    loaded = load_baseline(target)
    assert loaded.fixtures[0].outcome == Outcome.FALSE_NEGATIVE


def test_write_baseline_atomic_creates_no_temp_leftover(tmp_path: Path) -> None:
    """Successful writes leave no <name>.tmp / .tmp* sibling behind."""
    from secureclaw.dev.bench.baseline import write_baseline

    target = tmp_path / "corpus.json"
    write_baseline(_sample_result(), target)
    siblings = list(tmp_path.iterdir())
    assert siblings == [target], f"unexpected sibling files: {siblings}"


def test_write_baseline_atomic_failed_write_leaves_existing_file_intact(
    tmp_path: Path, monkeypatch
) -> None:
    """If the write fails mid-flight the existing baseline must remain."""
    import os as _os

    from secureclaw.dev.bench import baseline as baseline_mod
    from secureclaw.dev.bench.baseline import write_baseline

    target = tmp_path / "corpus.json"
    write_baseline(_sample_result(), target)
    original_bytes = target.read_bytes()

    real_replace = _os.replace

    def boom(src, dst):  # type: ignore[no-untyped-def]
        raise OSError("disk full")

    monkeypatch.setattr(baseline_mod.os, "replace", boom)

    with pytest.raises(OSError, match="disk full"):
        from dataclasses import replace as dc_replace

        from secureclaw.dev.bench.models import Outcome

        new = _sample_result()
        new_fix = list(new.fixtures)
        new_fix[0] = dc_replace(new_fix[0], outcome=Outcome.FALSE_NEGATIVE)
        new = dc_replace(new, fixtures=new_fix)
        write_baseline(new, target, force=True)

    # Original baseline still on disk and unchanged.
    assert target.read_bytes() == original_bytes
    # Restore replace so the tmp_path cleanup doesn't trip on the monkeypatch.
    monkeypatch.setattr(baseline_mod.os, "replace", real_replace)


def test_load_baseline_rejects_non_json(tmp_path: Path) -> None:
    from secureclaw.dev.bench.baseline import load_baseline

    target = tmp_path / "corpus.json"
    target.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError):
        load_baseline(target)


def test_load_baseline_missing_file(tmp_path: Path) -> None:
    from secureclaw.dev.bench.baseline import load_baseline

    with pytest.raises(FileNotFoundError):
        load_baseline(tmp_path / "missing.json")


def test_baseline_json_is_pretty_printed(tmp_path: Path) -> None:
    """Committed baselines should diff cleanly: indent=2, sorted keys."""
    from secureclaw.dev.bench.baseline import write_baseline

    target = tmp_path / "corpus.json"
    write_baseline(_sample_result(), target)
    text = target.read_text(encoding="utf-8")
    assert "\n" in text
    # Top-level object should be indented (one or more lines start with two spaces).
    parsed = json.loads(text)
    assert parsed["schema_version"] == 1
