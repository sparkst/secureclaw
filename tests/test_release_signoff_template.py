"""Shape tests for the release sign-off PR template + generator.

Per v1.3-plan-v10 §K.10: the template is the source of truth for what's
checked at every release. CI verifies the template covers all 8 K.11
sections (Foundation/Engine/Patterns/UX/Security/Process/Tests/Release)
and that the generator interpolates {version, date} correctly.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
TEMPLATE = ROOT / ".github" / "PULL_REQUEST_TEMPLATE" / "release-signoff.md"
GENERATOR = ROOT / "tools" / "gen_release_signoff.py"

# K.11 group ordering (v1.3-plan-v10) — every release sign-off must cover all 8.
REQUIRED_SECTIONS = (
    "## Foundation",
    "## Engine",
    "## Patterns",
    "## UX",
    "## Security",
    "## Process",
    "## Tests",
    "## Release",
)


def test_template_exists() -> None:
    assert TEMPLATE.is_file()


def test_template_covers_all_k11_sections() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    for section in REQUIRED_SECTIONS:
        assert section in text, f"template missing section: {section}"


def test_template_has_version_and_date_placeholders() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    assert "_VERSION_" in text, "template must include _VERSION_ placeholder"
    assert "_DATE_" in text, "template must include _DATE_ placeholder"


def test_template_evidence_columns_present() -> None:
    """Every checkbox should be paired with an `Evidence:` callout."""
    text = TEMPLATE.read_text(encoding="utf-8")
    # Count checkboxes vs Evidence callouts.
    checkbox_count = text.count("- [ ] ")
    evidence_count = text.count("Evidence:")
    # Some Notes/Risks sections may have free-form items; allow a small
    # slack but require the vast majority of checkboxes to have evidence.
    assert evidence_count >= checkbox_count - 5, (
        f"checkboxes ({checkbox_count}) and Evidence callouts "
        f"({evidence_count}) should be roughly balanced"
    )


def test_template_mentions_release_signoff_workflow() -> None:
    """Template must reference the CI gate that validates evidence links."""
    text = TEMPLATE.read_text(encoding="utf-8")
    assert "release-signoff-evidence-check" in text


def test_generator_exists() -> None:
    assert GENERATOR.is_file()


def test_generator_interpolates_version() -> None:
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "1.3.0", "--today", "2026-05-01"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0
    assert "v1.3.0" in result.stdout
    assert "2026-05-01" in result.stdout
    assert "_VERSION_" not in result.stdout
    assert "_DATE_" not in result.stdout


def test_generator_handles_unusual_versions() -> None:
    """Generator passes the version string through verbatim — no validation."""
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "1.3.0-rc1", "--today", "2026-05-01"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0
    assert "v1.3.0-rc1" in result.stdout
