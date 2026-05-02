"""JSON-Schema loading and validation for corpus fixtures (spec §6.3, §11).

Loads ``tests/corpus/expected-schema.json`` and validates fixture metadata
dicts against it. Used by the loader, validator, and CLI gate.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def _schema_path() -> Path:
    """Path to the canonical fixture schema (committed in PR-A)."""
    # secureclaw/dev/corpus/schema.py -> secureclaw/dev/corpus -> ... -> repo root
    repo_root = Path(__file__).resolve().parents[3]
    return repo_root / "tests" / "corpus" / "expected-schema.json"


def load_schema() -> Dict[str, Any]:
    """Read and parse the JSON Schema."""
    with _schema_path().open("r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_against_schema(data: Dict[str, Any]) -> List[str]:
    """Validate ``data`` against the corpus schema.

    Returns a list of error messages (empty list = valid). The implementation
    uses ``jsonschema`` from the ``[dev]`` extras. We collect ALL errors before
    returning per spec §6.3 ("no bail-on-first").
    """
    import jsonschema

    schema = load_schema()
    validator = jsonschema.Draft7Validator(schema)
    return [
        f"{'.'.join(str(p) for p in err.absolute_path)}: {err.message}"
        if err.absolute_path
        else err.message
        for err in sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    ]
