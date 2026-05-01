"""Smoke tests for cross-platform CI workflow YAML.

Verifies the workflow file structure matches the v1.3 plan REQ-7.1 quorum
rule and E.4 permissions block. Doesn't run the workflow — just shape-checks.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

WORKFLOW = Path(__file__).parent.parent / ".github" / "workflows" / "cross-platform.yml"


def _load() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def test_workflow_exists() -> None:
    assert WORKFLOW.is_file(), f"missing {WORKFLOW}"


def test_workflow_permissions_least_privilege() -> None:
    data = _load()
    perms = data.get("permissions", {})
    # E.4: contents: read only; nothing else granted.
    assert perms.get("contents") == "read"
    # No write scopes
    for k, v in perms.items():
        assert v != "write", f"workflow grants write to {k}; violates E.4"


def test_workflow_triggers() -> None:
    data = _load()
    # PyYAML parses bare 'on:' key as Python boolean True. Handle both.
    triggers = data.get("on") or data.get(True)
    assert triggers is not None
    assert "pull_request" in triggers
    assert "workflow_dispatch" in triggers


def test_quorum_gate_present() -> None:
    data = _load()
    jobs = data["jobs"]
    assert "quorum-gate" in jobs, "quorum-gate job missing"
    needs = jobs["quorum-gate"].get("needs", [])
    expected = {
        "self-hosted-jarvis",
        "self-hosted-macbook",
        "self-hosted-ubuntu",
        "self-hosted-macair",
    }
    assert set(needs) == expected, f"quorum-gate needs mismatch: {needs}"


def test_macair_continue_on_error() -> None:
    """REQ-7.1: macair offline does NOT block merge."""
    data = _load()
    macair = data["jobs"]["self-hosted-macair"]
    assert macair.get("continue-on-error") is True


def test_self_hosted_jobs_gated_by_runners_registered() -> None:
    """Jobs only fire after RUNNERS_REGISTERED=true is set in repo vars."""
    data = _load()
    for job_name in ("self-hosted-jarvis", "self-hosted-macbook", "self-hosted-ubuntu"):
        job = data["jobs"][job_name]
        cond = job.get("if", "")
        assert "RUNNERS_REGISTERED" in cond, (
            f"job {job_name} not gated by RUNNERS_REGISTERED variable: {cond}"
        )


def test_required_runner_labels_present() -> None:
    data = _load()
    expected_labels = {
        "self-hosted-jarvis": "mac-arm64-jarvis",
        "self-hosted-macbook": "mac-arm64-macbook",
        "self-hosted-ubuntu": "linux-ubuntu",
        "self-hosted-macair": "mac-sequoia-air",
    }
    for job_name, label in expected_labels.items():
        runs_on = data["jobs"][job_name]["runs-on"]
        assert "self-hosted" in runs_on
        assert label in runs_on, f"{job_name} missing label {label}: {runs_on}"


def test_bootstrap_scripts_exist_and_executable() -> None:
    root = WORKFLOW.parent.parent.parent
    for name in ("mac.sh", "linux.sh"):
        path = root / "tools" / "runner-bootstrap" / name
        assert path.is_file(), f"missing {path}"
