"""CI gate: PR-F sc-* skills exist with the required structure.

Spec §6 of docs/superpowers/specs/2026-05-02-pr-f-sc-skills-design.md.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = REPO_ROOT / ".claude" / "skills"

EXPECTED_SKILLS = {
    "sc-corpus": {
        "required_verbs": [
            "secureclaw dev corpus add",
            "secureclaw dev corpus list",
            "secureclaw dev corpus validate",
            "secureclaw dev corpus anonymize",
            "secureclaw dev corpus set-pr-number",
        ],
    },
    "sc-rule": {
        "required_verbs": [
            "secureclaw dev rule new",
            "secureclaw dev rule test",
            "secureclaw dev rule validate",
        ],
    },
    "sc-bench": {
        "required_verbs": [
            "secureclaw dev bench run",
            "secureclaw dev bench baseline",
            "secureclaw dev bench diff",
        ],
    },
}


@pytest.mark.parametrize("skill_name", sorted(EXPECTED_SKILLS))
def test_skill_directory_and_file_exist(skill_name: str) -> None:
    skill_md = SKILLS_DIR / skill_name / "SKILL.md"
    assert skill_md.is_file(), f"missing skill file: {skill_md}"


@pytest.mark.parametrize("skill_name", sorted(EXPECTED_SKILLS))
def test_skill_has_frontmatter(skill_name: str) -> None:
    skill_md = SKILLS_DIR / skill_name / "SKILL.md"
    text = skill_md.read_text(encoding="utf-8")
    assert text.startswith("---\n"), f"{skill_md}: missing opening frontmatter delimiter"
    closing = text.find("\n---\n", 4)
    assert closing > 0, f"{skill_md}: missing closing frontmatter delimiter"
    frontmatter = text[4:closing]
    assert re.search(r"^name:\s*", frontmatter, re.MULTILINE), f"{skill_md}: missing 'name'"
    assert re.search(r"^description:\s*", frontmatter, re.MULTILINE), (
        f"{skill_md}: missing 'description'"
    )
    assert re.search(r"^version:\s*", frontmatter, re.MULTILINE), f"{skill_md}: missing 'version'"


@pytest.mark.parametrize("skill_name", sorted(EXPECTED_SKILLS))
def test_skill_name_matches_directory(skill_name: str) -> None:
    skill_md = SKILLS_DIR / skill_name / "SKILL.md"
    text = skill_md.read_text(encoding="utf-8")
    closing = text.find("\n---\n", 4)
    frontmatter = text[4:closing]
    m = re.search(r"^name:\s*(\S+)", frontmatter, re.MULTILINE)
    assert m, f"{skill_md}: name field unparseable"
    assert m.group(1) == skill_name, (
        f"{skill_md}: frontmatter name {m.group(1)!r} does not match directory {skill_name!r}"
    )


@pytest.mark.parametrize("skill_name", sorted(EXPECTED_SKILLS))
def test_skill_documents_every_required_verb(skill_name: str) -> None:
    skill_md = SKILLS_DIR / skill_name / "SKILL.md"
    text = skill_md.read_text(encoding="utf-8")
    for verb in EXPECTED_SKILLS[skill_name]["required_verbs"]:
        assert verb in text, f"{skill_md}: required verb {verb!r} not found in skill body"


@pytest.mark.parametrize("skill_name", sorted(EXPECTED_SKILLS))
def test_skill_is_thin(skill_name: str) -> None:
    """Spec §4: each skill is 30-60 lines. Allow a small overshoot for examples."""
    skill_md = SKILLS_DIR / skill_name / "SKILL.md"
    text = skill_md.read_text(encoding="utf-8")
    lines = text.splitlines()
    assert 20 <= len(lines) <= 100, (
        f"{skill_md}: {len(lines)} lines is outside the thin-wrapper range [20, 100]"
    )
