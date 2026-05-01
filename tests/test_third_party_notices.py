"""Drift detection for THIRD_PARTY_NOTICES.md.

Per v1.3-plan-v10 PR-A7: the file is generated, never hand-edited. Every
PR that modifies ``secureclaw/rules/default_rules.json`` (especially
``sources[]`` arrays) or ``pyproject.toml`` deps MUST re-run the
generator and commit the diff. CI fails if the committed file doesn't
match the regenerated output.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
GENERATOR = ROOT / "tools" / "gen_third_party_notices.py"
NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"


def test_generator_exists() -> None:
    assert GENERATOR.is_file()


def test_notices_file_exists() -> None:
    assert NOTICES.is_file()


def test_notices_drift_check_passes() -> None:
    """Re-run the generator with --check; assert no drift."""
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0, (
        f"THIRD_PARTY_NOTICES.md is out of date. "
        f"Run `python tools/gen_third_party_notices.py` and commit the diff.\n"
        f"stderr: {result.stderr}"
    )


def test_notices_contains_runtime_deps_section() -> None:
    text = NOTICES.read_text(encoding="utf-8")
    assert "## Runtime Dependencies" in text


def test_notices_contains_dev_deps_section() -> None:
    text = NOTICES.read_text(encoding="utf-8")
    assert "## Development Dependencies" in text


def test_notices_contains_pattern_catalog_section() -> None:
    text = NOTICES.read_text(encoding="utf-8")
    assert "## Pattern Catalog" in text


def test_notices_documents_license_allowlist() -> None:
    """Allowed-licenses statement is part of the audit chain."""
    text = NOTICES.read_text(encoding="utf-8")
    for spdx in ("MIT", "Apache-2.0", "BSD-2-Clause"):
        assert spdx in text, f"allowed license {spdx} should be listed"


def test_notices_documents_denylist() -> None:
    text = NOTICES.read_text(encoding="utf-8")
    for spdx_prefix in ("GPL", "AGPL", "LGPL"):
        assert spdx_prefix in text, f"denied family {spdx_prefix} should be listed"


def test_notices_mentions_promptmap_rederivation_policy() -> None:
    """Promptmap (GPL-3.0) rules must be re-derived from clean upstream."""
    text = NOTICES.read_text(encoding="utf-8")
    assert "promptmap" in text.lower()
    assert "re-derive" in text.lower() or "rederiv" in text.lower()
