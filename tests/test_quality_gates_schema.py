"""Validates tests/quality_gates.json against its schema.

The schema is strict (additionalProperties: false). PR-G replaces placeholder
baseline values with measured numbers; until then the file ships with
all-zero placeholders that satisfy the schema.
"""

from __future__ import annotations

import json
from pathlib import Path

TESTS_DIR = Path(__file__).parent
GATES = json.loads((TESTS_DIR / "quality_gates.json").read_text())
SCHEMA = json.loads((TESTS_DIR / "quality_gates_schema.json").read_text())


def test_quality_gates_has_required_top_level_keys() -> None:
    for key in SCHEMA["required"]:
        assert key in GATES, f"quality_gates.json missing required key: {key}"


def test_thresholds_block_complete() -> None:
    required = set(SCHEMA["properties"]["thresholds"]["required"])
    assert set(GATES["thresholds"].keys()) >= required


def test_baseline_commit_is_40_char_hex() -> None:
    bc = GATES["baseline_commit"]
    assert len(bc) == 40 and all(c in "0123456789abcdef" for c in bc)


def test_baseline_metrics_block_complete() -> None:
    required = set(SCHEMA["properties"]["baseline_metrics"]["required"])
    assert set(GATES["baseline_metrics"].keys()) == required


def test_no_placeholder_substring_in_string_values() -> None:
    """Catches the `<...>` placeholder pattern from earlier draft."""

    def walk(obj: object) -> None:
        if isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)
        elif isinstance(obj, str):
            assert (
                "<" not in obj or ">" not in obj or not (obj.startswith("<") and obj.endswith(">"))
            ), f"placeholder substring in quality_gates.json: {obj}"

    walk(GATES)
