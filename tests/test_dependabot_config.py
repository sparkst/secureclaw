"""Shape tests for Dependabot config + auto-merge workflow.

Per v1.3-plan-v10 PR-J2: regex pinned exact, dev deps auto-mergeable on
patch/minor, major bumps gated, security advisories never auto-merged.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).parent.parent
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
AUTO_MERGE = ROOT / ".github" / "workflows" / "dependabot-auto-merge.yml"


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def test_dependabot_config_exists() -> None:
    assert DEPENDABOT.is_file()


def test_dependabot_config_version_is_2() -> None:
    data = _load_yaml(DEPENDABOT)
    assert data["version"] == 2


def test_dependabot_covers_pip_and_actions() -> None:
    data = _load_yaml(DEPENDABOT)
    ecosystems = {u["package-ecosystem"] for u in data["updates"]}
    assert "pip" in ecosystems, "pyproject.toml deps need a pip update entry"
    assert "github-actions" in ecosystems, "actions in workflows need updates"


def test_regex_major_bumps_ignored() -> None:
    """REQ R7-REQ003 enforcement: regex's exact pin can only be relaxed via
    explicit major-bump review PR, never via Dependabot auto-PR."""
    data = _load_yaml(DEPENDABOT)
    pip_entry = next(u for u in data["updates"] if u["package-ecosystem"] == "pip")
    ignore = pip_entry.get("ignore", [])
    regex_entries = [e for e in ignore if e.get("dependency-name") == "regex"]
    assert regex_entries, "regex must have an ignore entry blocking major bumps"
    types = regex_entries[0].get("update-types", [])
    assert "version-update:semver-major" in types


def test_auto_merge_workflow_exists() -> None:
    assert AUTO_MERGE.is_file()


def test_auto_merge_uses_pull_request_target() -> None:
    """Dependabot PRs require pull_request_target so the merge token has
    write scope; v1.3-plan-v10 §E.4 documents this carve-out."""
    data = _load_yaml(AUTO_MERGE)
    triggers = data.get("on") or data.get(True)
    assert "pull_request_target" in triggers


def test_auto_merge_is_dependabot_only() -> None:
    """Workflow runs only when actor is dependabot[bot] — avoids merging
    arbitrary external PRs that masquerade as Dependabot."""
    data = _load_yaml(AUTO_MERGE)
    job = data["jobs"]["auto-merge"]
    cond = job.get("if", "")
    assert "dependabot[bot]" in cond


def test_auto_merge_refuses_major_bumps() -> None:
    text = AUTO_MERGE.read_text()
    assert "version-update:semver-major" in text
    assert "auto-merge disabled" in text


def test_auto_merge_refuses_security_advisories() -> None:
    text = AUTO_MERGE.read_text()
    assert "security-advisory" in text or "alert-state" in text


def test_auto_merge_only_patches_and_minors() -> None:
    text = AUTO_MERGE.read_text()
    assert "version-update:semver-patch" in text
    assert "version-update:semver-minor" in text


def test_auto_merge_requires_least_privilege_on_default_perms() -> None:
    """Top-level `permissions: contents: read` ensures the default token
    has minimal scope; the auto-merge job explicitly elevates within
    its scoped block per E.4."""
    data = _load_yaml(AUTO_MERGE)
    perms = data.get("permissions", {})
    assert perms.get("contents") == "read"
    job = data["jobs"]["auto-merge"]
    job_perms = job.get("permissions", {})
    # Job needs write to do the merge; outer default is read.
    assert job_perms.get("contents") == "write"
    assert job_perms.get("pull-requests") == "write"
