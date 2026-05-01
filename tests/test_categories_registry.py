"""Validates secureclaw/rules/categories.json schema.

Each existing pattern category in default_rules.json must appear in the
registry. Foundation PR-A only validates structure; later PRs add CI gates.
"""

from __future__ import annotations

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
CATEGORIES_PATH = PROJECT_ROOT / "secureclaw" / "rules" / "categories.json"
DEFAULT_RULES_PATH = PROJECT_ROOT / "secureclaw" / "rules" / "default_rules.json"

REQUIRED_FIELDS = {"display_name", "friendly_name", "friendly_explanation", "color_tier"}
ALLOWED_TIERS = {"red", "gold", "gray"}


def test_categories_has_schema_version() -> None:
    data = json.loads(CATEGORIES_PATH.read_text())
    assert data.get("schema_version") == 2


def test_every_category_has_required_fields() -> None:
    data = json.loads(CATEGORIES_PATH.read_text())
    for cat_id, cat in data["categories"].items():
        missing = REQUIRED_FIELDS - set(cat.keys())
        assert not missing, f"category {cat_id} missing fields: {missing}"
        assert cat["color_tier"] in ALLOWED_TIERS, (
            f"category {cat_id} has invalid color_tier: {cat['color_tier']}"
        )


def test_every_default_rule_category_is_in_registry() -> None:
    """Existing rules in default_rules.json reference the categories registry."""
    rules = json.loads(DEFAULT_RULES_PATH.read_text())
    registry = json.loads(CATEGORIES_PATH.read_text())
    known = set(registry["categories"].keys())

    for entry in rules.get("patterns", []):
        cat = entry.get("category", "")
        assert cat in known, (
            f"rule {entry.get('id')} references unknown category {cat!r}; "
            f"add it to secureclaw/rules/categories.json"
        )
