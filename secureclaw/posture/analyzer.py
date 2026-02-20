"""Security posture analyzer for Claude Code, Cursor, and OpenClaw.

Checks AI tool configurations for security best practices and reports
the user's current security posture.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import List, Optional

from secureclaw.core.models import PostureCheck

logger = logging.getLogger(__name__)


def _home() -> Path:
    return Path.home()


def _check_file_permissions(path: Path, description: str) -> Optional[PostureCheck]:
    """Check if a sensitive file has overly permissive permissions (Unix only)."""
    if os.name == "nt":
        return None
    try:
        mode = path.stat().st_mode
        world_readable = mode & 0o004
        world_writable = mode & 0o002
        if world_writable:
            return PostureCheck(
                tool_name="File Permissions",
                check_name=f"{description} is world-writable",
                status="insecure",
                description=f"{path} can be modified by any user on this system.",
                recommendation=f"Run: chmod 600 {path}",
                config_path=path,
            )
        if world_readable:
            return PostureCheck(
                tool_name="File Permissions",
                check_name=f"{description} is world-readable",
                status="warning",
                description=f"{path} can be read by any user on this system.",
                recommendation=f"Run: chmod 600 {path}",
                config_path=path,
            )
    except OSError:
        pass
    return None


def check_claude_code(scan_dir: Optional[Path] = None) -> List[PostureCheck]:
    """Check Claude Code security posture."""
    checks: List[PostureCheck] = []
    home = _home()

    # Check for Claude Code installation
    claude_dir = home / ".claude"
    if not claude_dir.exists():
        checks.append(PostureCheck(
            tool_name="Claude Code",
            check_name="Installation",
            status="not_found",
            description="Claude Code configuration directory not found at ~/.claude",
        ))
        return checks

    checks.append(PostureCheck(
        tool_name="Claude Code",
        check_name="Installation",
        status="secure",
        description="Claude Code is installed.",
        config_path=claude_dir,
    ))

    # Check settings.json for permission model
    settings_path = claude_dir / "settings.json"
    if settings_path.exists():
        try:
            with open(settings_path, encoding="utf-8") as f:
                settings = json.load(f)

            # Check permission mode
            perm_mode = settings.get("permissions", {})
            if isinstance(perm_mode, dict):
                allow_all = perm_mode.get("allow", [])
                if "Edit" in allow_all or "Write" in allow_all:
                    checks.append(PostureCheck(
                        tool_name="Claude Code",
                        check_name="File write permissions",
                        status="warning",
                        description="Claude Code has blanket file write permission. This means AI-generated content can modify any file.",
                        recommendation="Consider using 'acceptEdits' mode instead of blanket write permission.",
                        config_path=settings_path,
                    ))
                if "Bash" in allow_all:
                    checks.append(PostureCheck(
                        tool_name="Claude Code",
                        check_name="Shell execution permissions",
                        status="warning",
                        description="Claude Code has blanket shell execution permission. Commands from prompt injections could execute on your system.",
                        recommendation="Review which bash commands are allowed. Consider restricting to specific safe commands.",
                        config_path=settings_path,
                    ))
            perm_check = _check_file_permissions(settings_path, "Claude Code settings")
            if perm_check:
                checks.append(perm_check)
        except (json.JSONDecodeError, OSError) as e:
            logger.debug("Cannot read Claude Code settings: %s", e)

    # Check for CLAUDE.md in common locations
    for check_dir in [scan_dir, Path.cwd()] if scan_dir else [Path.cwd()]:
        if check_dir:
            claude_md = check_dir / "CLAUDE.md"
            if claude_md.exists():
                checks.append(PostureCheck(
                    tool_name="Claude Code",
                    check_name="Project instructions (CLAUDE.md)",
                    status="secure",
                    description=f"Found CLAUDE.md at {claude_md}. This file controls AI behavior for this project.",
                    recommendation="Review CLAUDE.md periodically to ensure no unauthorized changes.",
                    config_path=claude_md,
                ))

    # Check for MCP server configurations
    mcp_paths = [
        claude_dir / "mcp.json",
        claude_dir / ".mcp.json",
    ]
    for mcp_path in mcp_paths:
        if mcp_path.exists():
            try:
                with open(mcp_path, encoding="utf-8") as f:
                    mcp_config = json.load(f)
                server_count = len(mcp_config.get("mcpServers", {}))
                if server_count > 0:
                    checks.append(PostureCheck(
                        tool_name="Claude Code",
                        check_name=f"MCP servers ({server_count} configured)",
                        status="warning" if server_count > 3 else "secure",
                        description=f"{server_count} MCP server(s) configured. Each server extends Claude's capabilities with external tools.",
                        recommendation="Review each MCP server source. Only use servers from trusted providers." if server_count > 3 else "MCP server count is reasonable. Review periodically.",
                        config_path=mcp_path,
                    ))
            except (json.JSONDecodeError, OSError):
                pass

    return checks


def check_cursor(scan_dir: Optional[Path] = None) -> List[PostureCheck]:
    """Check Cursor AI security posture."""
    checks: List[PostureCheck] = []
    home = _home()

    # Check for Cursor installation
    cursor_dir = home / ".cursor"
    if not cursor_dir.exists():
        checks.append(PostureCheck(
            tool_name="Cursor",
            check_name="Installation",
            status="not_found",
            description="Cursor configuration directory not found at ~/.cursor",
        ))
        return checks

    checks.append(PostureCheck(
        tool_name="Cursor",
        check_name="Installation",
        status="secure",
        description="Cursor is installed.",
        config_path=cursor_dir,
    ))

    # Check for .cursorrules
    for check_dir in [scan_dir, Path.cwd()] if scan_dir else [Path.cwd()]:
        if check_dir:
            cursorrules = check_dir / ".cursorrules"
            if cursorrules.exists():
                checks.append(PostureCheck(
                    tool_name="Cursor",
                    check_name="Project rules (.cursorrules)",
                    status="secure",
                    description=f"Found .cursorrules at {cursorrules}. This file controls Cursor AI behavior.",
                    recommendation="Review .cursorrules periodically for unauthorized changes.",
                    config_path=cursorrules,
                ))

    # Check for MCP configs
    mcp_path = cursor_dir / "mcp.json"
    if mcp_path.exists():
        try:
            with open(mcp_path, encoding="utf-8") as f:
                mcp_config = json.load(f)
            server_count = len(mcp_config.get("mcpServers", {}))
            checks.append(PostureCheck(
                tool_name="Cursor",
                check_name=f"MCP servers ({server_count} configured)",
                status="warning" if server_count > 5 else "secure",
                description=f"{server_count} MCP server(s) configured in Cursor.",
                recommendation="Review each MCP server. Cursor MCP servers have broad tool access.",
                config_path=mcp_path,
            ))
        except (json.JSONDecodeError, OSError):
            pass

    return checks


def check_openclaw(scan_dir: Optional[Path] = None) -> List[PostureCheck]:
    """Check OpenClaw security posture."""
    checks: List[PostureCheck] = []
    home = _home()

    # Check for OpenClaw installation
    openclaw_dir = home / ".openclaw"
    if not openclaw_dir.exists():
        checks.append(PostureCheck(
            tool_name="OpenClaw",
            check_name="Installation",
            status="not_found",
            description="OpenClaw configuration directory not found at ~/.openclaw",
        ))
        return checks

    checks.append(PostureCheck(
        tool_name="OpenClaw",
        check_name="Installation",
        status="secure",
        description="OpenClaw is installed.",
        config_path=openclaw_dir,
    ))

    # Check for skills directory
    skills_dir = openclaw_dir / "skills"
    if skills_dir.exists():
        skill_count = sum(1 for _ in skills_dir.iterdir() if _.is_dir())
        checks.append(PostureCheck(
            tool_name="OpenClaw",
            check_name=f"Skills installed ({skill_count})",
            status="warning" if skill_count > 10 else "secure",
            description=f"{skill_count} skill(s) installed. Each skill can execute code on your system.",
            recommendation="Audit installed skills. Only use skills from trusted sources.",
            config_path=skills_dir,
        ))

    # Check for cron jobs (scheduled tasks)
    cron_dir = openclaw_dir / "cron"
    if cron_dir.exists():
        cron_count = sum(1 for f in cron_dir.iterdir() if f.is_file())
        if cron_count > 0:
            checks.append(PostureCheck(
                tool_name="OpenClaw",
                check_name=f"Scheduled tasks ({cron_count})",
                status="warning",
                description=f"{cron_count} scheduled task(s) running. These execute automatically without your confirmation.",
                recommendation="Review each scheduled task. Ensure they only perform trusted operations.",
                config_path=cron_dir,
            ))

    return checks


def check_downloads_documents() -> List[PostureCheck]:
    """Check common download/document directories for AI-related risks."""
    checks: List[PostureCheck] = []
    home = _home()

    downloads = home / "Downloads"
    documents = home / "Documents"

    for dir_path, dir_name in [(downloads, "Downloads"), (documents, "Documents")]:
        if dir_path.exists():
            # Count potentially risky file types
            risky_extensions = {".py", ".sh", ".bat", ".cmd", ".ps1", ".js", ".mjs"}
            risky_count = 0
            try:
                for f in dir_path.iterdir():
                    if f.is_file() and f.suffix.lower() in risky_extensions:
                        risky_count += 1
            except PermissionError:
                pass

            if risky_count > 0:
                checks.append(PostureCheck(
                    tool_name="System",
                    check_name=f"Executable scripts in ~/{dir_name}",
                    status="advisory" if risky_count < 5 else "warning",
                    description=f"Found {risky_count} executable script(s) in ~/{dir_name}. Downloaded scripts may contain prompt injections.",
                    recommendation=f"Review scripts in ~/{dir_name} before running them or letting AI tools access them.",
                    config_path=dir_path,
                ))

    return checks


def check_browser_cache() -> List[PostureCheck]:
    """Check for browser extension/cache directories that AI tools might access."""
    checks: List[PostureCheck] = []
    home = _home()

    # Common browser profile paths
    browser_paths = {
        "Chrome": [
            home / "Library" / "Application Support" / "Google" / "Chrome",  # macOS
            home / ".config" / "google-chrome",  # Linux
            home / "AppData" / "Local" / "Google" / "Chrome" / "User Data",  # Windows
        ],
        "Firefox": [
            home / "Library" / "Application Support" / "Firefox" / "Profiles",
            home / ".mozilla" / "firefox",
            home / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles",
        ],
        "Edge": [
            home / "Library" / "Application Support" / "Microsoft Edge",
            home / ".config" / "microsoft-edge",
            home / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data",
        ],
    }

    for browser, paths in browser_paths.items():
        for p in paths:
            if p.exists():
                checks.append(PostureCheck(
                    tool_name="Browser",
                    check_name=f"{browser} profile found",
                    status="advisory",
                    description=f"{browser} profile directory exists at {p}. Browser data (history, cached pages) could contain prompt injections from malicious websites.",
                    recommendation="Avoid pointing AI tools at browser profile directories. If you must, scan them first.",
                    config_path=p,
                ))
                break  # Only report first found path per browser

    return checks


def run_posture_analysis(scan_dir: Optional[Path] = None) -> List[PostureCheck]:
    """Run all security posture checks."""
    all_checks: List[PostureCheck] = []
    all_checks.extend(check_claude_code(scan_dir))
    all_checks.extend(check_cursor(scan_dir))
    all_checks.extend(check_openclaw(scan_dir))
    all_checks.extend(check_downloads_documents())
    all_checks.extend(check_browser_cache())
    return all_checks
