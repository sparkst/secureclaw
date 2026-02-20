"""Tests for the security posture analyzer."""

import json
import os
from pathlib import Path
from unittest.mock import patch

from secureclaw.posture.analyzer import (
    check_browser_cache,
    check_claude_code,
    check_cursor,
    check_downloads_documents,
    check_openclaw,
    run_posture_analysis,
)


class TestCheckClaudeCode:
    """Tests for check_claude_code posture analysis."""

    def test_no_claude_dir_returns_not_found(self, tmp_path):
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_claude_code()
        assert len(checks) == 1
        assert checks[0].status == "not_found"
        assert checks[0].tool_name == "Claude Code"
        assert checks[0].check_name == "Installation"

    def test_empty_claude_dir_returns_secure(self, tmp_path):
        (tmp_path / ".claude").mkdir()
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_claude_code()
        statuses = [c.status for c in checks]
        assert "secure" in statuses
        assert any(c.check_name == "Installation" for c in checks)

    def test_settings_with_edit_permission_warns(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = {"permissions": {"allow": ["Edit", "Read"]}}
        (claude_dir / "settings.json").write_text(json.dumps(settings))
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_claude_code()
        assert any(
            c.status == "warning" and "write" in c.check_name.lower()
            for c in checks
        )

    def test_settings_with_bash_permission_warns(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = {"permissions": {"allow": ["Bash"]}}
        (claude_dir / "settings.json").write_text(json.dumps(settings))
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_claude_code()
        assert any(
            c.status == "warning" and "shell" in c.check_name.lower()
            for c in checks
        )

    def test_settings_without_dangerous_permissions_no_warning(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = {"permissions": {"allow": ["Read"]}}
        settings_file = claude_dir / "settings.json"
        settings_file.write_text(json.dumps(settings))
        # Set restrictive permissions so file permissions check does not warn
        if os.name != "nt":
            settings_file.chmod(0o600)
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_claude_code()
        # Filter out file permission warnings (not related to AI permission model)
        permission_model_warnings = [
            c for c in checks
            if c.status == "warning" and c.tool_name == "Claude Code"
            and "File Permissions" not in c.tool_name
            and "world" not in c.check_name
        ]
        assert len(permission_model_warnings) == 0

    def test_malformed_settings_json_handled(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        (claude_dir / "settings.json").write_text("{not valid json!!!")
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_claude_code()
        # Should not crash, should still return installation check
        assert any(c.check_name == "Installation" for c in checks)

    def test_claude_md_detected_in_scan_dir(self, tmp_path):
        (tmp_path / ".claude").mkdir()
        scan_dir = tmp_path / "project"
        scan_dir.mkdir()
        (scan_dir / "CLAUDE.md").write_text("# Instructions")
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_claude_code(scan_dir=scan_dir)
        assert any(
            "CLAUDE.md" in c.check_name for c in checks
        )

    def test_mcp_servers_few_is_secure(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        mcp_config = {"mcpServers": {"server1": {}, "server2": {}}}
        (claude_dir / "mcp.json").write_text(json.dumps(mcp_config))
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_claude_code()
        mcp_checks = [c for c in checks if "MCP" in c.check_name]
        assert len(mcp_checks) == 1
        assert mcp_checks[0].status == "secure"

    def test_mcp_servers_many_is_warning(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        mcp_config = {
            "mcpServers": {f"server{i}": {} for i in range(5)}
        }
        (claude_dir / "mcp.json").write_text(json.dumps(mcp_config))
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_claude_code()
        mcp_checks = [c for c in checks if "MCP" in c.check_name]
        assert len(mcp_checks) == 1
        assert mcp_checks[0].status == "warning"

    def test_mcp_malformed_json_handled(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        (claude_dir / "mcp.json").write_text("not json")
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_claude_code()
        # Should not crash, no MCP check emitted
        mcp_checks = [c for c in checks if "MCP" in c.check_name]
        assert len(mcp_checks) == 0

    def test_mcp_empty_servers_no_check(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        mcp_config = {"mcpServers": {}}
        (claude_dir / "mcp.json").write_text(json.dumps(mcp_config))
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_claude_code()
        mcp_checks = [c for c in checks if "MCP" in c.check_name]
        assert len(mcp_checks) == 0


class TestCheckCursor:
    """Tests for check_cursor posture analysis."""

    def test_no_cursor_dir_returns_not_found(self, tmp_path):
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_cursor()
        assert len(checks) == 1
        assert checks[0].status == "not_found"
        assert checks[0].tool_name == "Cursor"

    def test_cursor_dir_present_returns_secure(self, tmp_path):
        (tmp_path / ".cursor").mkdir()
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_cursor()
        assert any(c.status == "secure" and c.check_name == "Installation" for c in checks)

    def test_cursorrules_detected(self, tmp_path):
        (tmp_path / ".cursor").mkdir()
        scan_dir = tmp_path / "project"
        scan_dir.mkdir()
        (scan_dir / ".cursorrules").write_text("rules here")
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_cursor(scan_dir=scan_dir)
        assert any(".cursorrules" in c.check_name for c in checks)

    def test_cursor_mcp_servers_detected(self, tmp_path):
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        mcp_config = {"mcpServers": {"s1": {}, "s2": {}}}
        (cursor_dir / "mcp.json").write_text(json.dumps(mcp_config))
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_cursor()
        mcp_checks = [c for c in checks if "MCP" in c.check_name]
        assert len(mcp_checks) == 1

    def test_cursor_mcp_malformed_json(self, tmp_path):
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        (cursor_dir / "mcp.json").write_text("{broken json")
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_cursor()
        # Should not crash
        mcp_checks = [c for c in checks if "MCP" in c.check_name]
        assert len(mcp_checks) == 0


class TestCheckOpenclaw:
    """Tests for check_openclaw posture analysis."""

    def test_no_openclaw_dir_returns_not_found(self, tmp_path):
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_openclaw()
        assert len(checks) == 1
        assert checks[0].status == "not_found"
        assert checks[0].tool_name == "OpenClaw"

    def test_openclaw_dir_present_returns_secure(self, tmp_path):
        (tmp_path / ".openclaw").mkdir()
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_openclaw()
        assert any(c.status == "secure" and c.check_name == "Installation" for c in checks)

    def test_skills_directory_detected(self, tmp_path):
        openclaw_dir = tmp_path / ".openclaw"
        openclaw_dir.mkdir()
        skills_dir = openclaw_dir / "skills"
        skills_dir.mkdir()
        (skills_dir / "skill1").mkdir()
        (skills_dir / "skill2").mkdir()
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_openclaw()
        skill_checks = [c for c in checks if "Skills" in c.check_name]
        assert len(skill_checks) == 1
        assert "2" in skill_checks[0].check_name

    def test_many_skills_is_warning(self, tmp_path):
        openclaw_dir = tmp_path / ".openclaw"
        openclaw_dir.mkdir()
        skills_dir = openclaw_dir / "skills"
        skills_dir.mkdir()
        for i in range(15):
            (skills_dir / f"skill{i}").mkdir()
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_openclaw()
        skill_checks = [c for c in checks if "Skills" in c.check_name]
        assert len(skill_checks) == 1
        assert skill_checks[0].status == "warning"

    def test_cron_jobs_detected(self, tmp_path):
        openclaw_dir = tmp_path / ".openclaw"
        openclaw_dir.mkdir()
        cron_dir = openclaw_dir / "cron"
        cron_dir.mkdir()
        (cron_dir / "job1.json").write_text("{}")
        (cron_dir / "job2.json").write_text("{}")
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_openclaw()
        cron_checks = [c for c in checks if "Scheduled" in c.check_name]
        assert len(cron_checks) == 1
        assert cron_checks[0].status == "warning"

    def test_empty_cron_dir_no_warning(self, tmp_path):
        openclaw_dir = tmp_path / ".openclaw"
        openclaw_dir.mkdir()
        (openclaw_dir / "cron").mkdir()
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_openclaw()
        cron_checks = [c for c in checks if "Scheduled" in c.check_name]
        assert len(cron_checks) == 0


class TestCheckDownloadsDocuments:
    """Tests for check_downloads_documents posture analysis."""

    def test_empty_downloads_no_findings(self, tmp_path):
        downloads = tmp_path / "Downloads"
        downloads.mkdir()
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_downloads_documents()
        download_checks = [c for c in checks if "Downloads" in c.check_name]
        assert len(download_checks) == 0

    def test_risky_scripts_detected(self, tmp_path):
        downloads = tmp_path / "Downloads"
        downloads.mkdir()
        (downloads / "install.sh").write_text("#!/bin/bash")
        (downloads / "setup.py").write_text("import os")
        (downloads / "run.bat").write_text("echo hello")
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_downloads_documents()
        download_checks = [c for c in checks if "Downloads" in c.check_name]
        assert len(download_checks) == 1
        assert "3" in download_checks[0].description

    def test_non_risky_files_ignored(self, tmp_path):
        downloads = tmp_path / "Downloads"
        downloads.mkdir()
        (downloads / "readme.txt").write_text("hello")
        (downloads / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe0")
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_downloads_documents()
        download_checks = [c for c in checks if "Downloads" in c.check_name]
        assert len(download_checks) == 0

    def test_no_downloads_dir_no_check(self, tmp_path):
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_downloads_documents()
        assert len(checks) == 0


class TestCheckBrowserCache:
    """Tests for check_browser_cache posture analysis."""

    def test_no_browser_profiles_returns_empty(self, tmp_path):
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_browser_cache()
        assert len(checks) == 0

    def test_chrome_profile_detected(self, tmp_path):
        # macOS Chrome path
        chrome_dir = tmp_path / "Library" / "Application Support" / "Google" / "Chrome"
        chrome_dir.mkdir(parents=True)
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_browser_cache()
        assert any(
            "Chrome" in c.check_name and c.status == "advisory"
            for c in checks
        )

    def test_firefox_profile_detected(self, tmp_path):
        # Linux Firefox path
        ff_dir = tmp_path / ".mozilla" / "firefox"
        ff_dir.mkdir(parents=True)
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_browser_cache()
        assert any("Firefox" in c.check_name for c in checks)

    def test_multiple_browsers_all_detected(self, tmp_path):
        # Create both Chrome and Firefox
        (tmp_path / "Library" / "Application Support" / "Google" / "Chrome").mkdir(parents=True)
        (tmp_path / ".mozilla" / "firefox").mkdir(parents=True)
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = check_browser_cache()
        browser_names = {c.check_name for c in checks}
        assert any("Chrome" in n for n in browser_names)
        assert any("Firefox" in n for n in browser_names)


class TestRunPostureAnalysis:
    """Tests for the top-level run_posture_analysis function."""

    def test_aggregates_all_checks(self, tmp_path):
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".cursor").mkdir()
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = run_posture_analysis()
        tool_names = {c.tool_name for c in checks}
        assert "Claude Code" in tool_names
        assert "Cursor" in tool_names

    def test_passes_scan_dir_through(self, tmp_path):
        (tmp_path / ".claude").mkdir()
        scan_dir = tmp_path / "project"
        scan_dir.mkdir()
        (scan_dir / "CLAUDE.md").write_text("# Test")
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = run_posture_analysis(scan_dir=scan_dir)
        assert any("CLAUDE.md" in c.check_name for c in checks)

    def test_empty_system_returns_not_found_entries(self, tmp_path):
        with patch("secureclaw.posture.analyzer._home", return_value=tmp_path):
            checks = run_posture_analysis()
        not_found = [c for c in checks if c.status == "not_found"]
        # Should have not_found for Claude Code, Cursor, OpenClaw
        assert len(not_found) >= 3
