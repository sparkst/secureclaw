"""Shape tests for the auto-merge-on-green label gate workflow.

Per v1.3-plan-v10 §K.3 + R6-PROC001 fix: two-tier enforcement.
- Tier 1: real-time label removal when an unauthorized actor applies the
  ``auto-merge-on-green`` label.
- Tier 2: persistent status check that walks PR timeline and asserts the
  label was applied by @sparkst.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "label-gate.yml"


def _load() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def test_workflow_exists() -> None:
    assert WORKFLOW.is_file()


def test_workflow_uses_pull_request_target() -> None:
    data = _load()
    triggers = data.get("on") or data.get(True)
    assert "pull_request_target" in triggers


def test_workflow_default_permissions_are_read_only() -> None:
    """Top-level permissions: contents: read; jobs elevate scoped (E.4)."""
    data = _load()
    perms = data.get("permissions", {})
    assert perms == {"contents": "read"}


def test_remove_unauthorized_label_job_exists() -> None:
    data = _load()
    assert "remove-unauthorized-label" in data["jobs"]


def test_label_status_job_exists() -> None:
    data = _load()
    assert "label-status" in data["jobs"]


def test_remove_job_only_runs_on_label_event() -> None:
    data = _load()
    job = data["jobs"]["remove-unauthorized-label"]
    cond = job.get("if", "")
    assert "labeled" in cond
    assert "auto-merge-on-green" in cond


def test_remove_job_owner_check() -> None:
    text = WORKFLOW.read_text()
    # Compare sender.login to sparkst (the repo owner).
    assert "sender.login" in text
    assert "sparkst" in text


def test_remove_job_writes_pull_requests_only() -> None:
    """Tier-1 elevates pull-requests:write only — no contents:write."""
    data = _load()
    job = data["jobs"]["remove-unauthorized-label"]
    job_perms = job.get("permissions", {})
    assert job_perms.get("contents") == "read"
    assert job_perms.get("pull-requests") == "write"


def test_label_status_job_walks_timeline() -> None:
    """Tier-2 walks PR timeline events to find labeled events."""
    text = WORKFLOW.read_text()
    assert "issues/${PR}/timeline" in text
    assert "labeled" in text


def test_label_status_job_does_not_have_write_perms() -> None:
    """Tier-2 is observation-only; contents:read only."""
    data = _load()
    job = data["jobs"]["label-status"]
    job_perms = job.get("permissions", {"contents": "read"})
    # Either no permissions block (inherits top-level) or read-only
    if job_perms:
        assert job_perms.get("contents") == "read"
        assert job_perms.get("pull-requests") in (None, "read")
