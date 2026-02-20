"""Cross-platform file scanner with safe file walking and binary detection."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from secureclaw.core.models import (
    FileContext,
    FileResult,
    ScanSummary,
)
from secureclaw.core.patterns import PatternEngine

logger = logging.getLogger(__name__)

# Default max file size: 10MB
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024

# Extensions we scan (text-based files that could contain injections)
TEXT_EXTENSIONS = {
    ".txt",
    ".md",
    ".markdown",
    ".rst",
    ".adoc",
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".mjs",
    ".cjs",
    ".rb",
    ".php",
    ".java",
    ".go",
    ".rs",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ps1",
    ".bat",
    ".cmd",
    ".html",
    ".htm",
    ".xml",
    ".svg",
    ".css",
    ".scss",
    ".less",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".envrc",
    ".env.local",
    ".env.example",
    ".csv",
    ".tsv",
    ".sql",
    ".graphql",
    ".gql",
    ".dockerfile",
    ".docker-compose",
    ".tf",
    ".tfvars",
    ".hcl",
    ".r",
    ".rmd",
    ".lua",
    ".vim",
    ".el",
    ".gitignore",
    ".gitattributes",
    ".gitmodules",
    ".editorconfig",
    ".prettierrc",
    ".eslintrc",
    ".cursorrules",
    ".cursorignore",
    ".clinerules",
}

# Files to always scan regardless of extension
ALWAYS_SCAN_NAMES = {
    "CLAUDE.md",
    "CLAUDE.local.md",
    ".claude",
    "Makefile",
    "Rakefile",
    "Vagrantfile",
    "Procfile",
    "requirements.txt",
    "Pipfile",
    "Gemfile",
    "package.json",
    "composer.json",
    "Cargo.toml",
    ".cursorrules",
    ".cursorignore",
    ".clinerules",
}

# System directories to skip by default (exact directory matches)
SYSTEM_DIRS = {
    "/etc",
    "/usr",
    "/var",
    "/sbin",
    "/bin",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/Library",
    "/System",
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
}

# Directories to always skip (build artifacts, dependencies)
SKIP_DIRS = {
    "node_modules",
    ".git",
    "__pycache__",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "venv",
    ".venv",
    "env",
    ".env",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".terraform",
    ".serverless",
    "vendor",
    "bower_components",
    ".DS_Store",
    "Thumbs.db",
}

# Priority directories for AI tool scanning
AI_TOOL_DIRS = {
    ".claude": "Claude Code configuration",
    ".cursor": "Cursor AI configuration",
    ".continue": "Continue.dev configuration",
    ".cline": "Cline configuration",
    ".openclaw": "OpenClaw configuration",
    ".config/claude": "Claude Code global config",
}


# Patterns in AI config files are legitimate instructions, not injections.
# Only exfiltration/credential patterns (PI-004, PI-005, PI-022, PI-028) apply in AI configs.
AI_CONFIG_ONLY_PATTERNS = {"PI-004", "PI-005", "PI-008", "PI-014", "PI-022", "PI-028"}

# Path components that indicate an AI configuration file
AI_CONFIG_INDICATORS = {
    ".claude",
    ".cursor",
    ".continue",
    ".cline",
    ".openclaw",
    ".config/claude",
    ".config/cursor",
}

# Filenames that are AI configuration
AI_CONFIG_FILENAMES = {
    "CLAUDE.md",
    "CLAUDE.local.md",
    "SKILL.md",
    ".cursorrules",
    ".cursorignore",
    ".clinerules",
}

# Parent directory names that indicate AI tool structure
AI_CONFIG_PARENTS = {
    "agents",
    "skills",
    "commands",
    "hooks",
    "prompts",
    "agent-knowledge",
    "knowledge-base",
}

# Test directory/file indicators
TEST_INDICATORS = {
    "test",
    "tests",
    "spec",
    "specs",
    "__tests__",
    "fixtures",
    "test_",
    "spec_",
    "_test",
    "_spec",
}


def classify_file_context(path: Path) -> FileContext:
    """Classify a file's context to determine scanning behavior.

    AI config files (skills, agents, prompts) legitimately contain instruction-like
    patterns. We still scan them for exfiltration/credential issues but skip
    instructional pattern matches.
    """
    parts = set(path.parts)
    path_str = str(path)

    # Check filename
    if path.name in AI_CONFIG_FILENAMES:
        return FileContext.AI_CONFIG

    # Check path components for AI tool directories
    for indicator in AI_CONFIG_INDICATORS:
        if indicator in path_str:
            return FileContext.AI_CONFIG

    # Check if inside an agents/skills/commands/hooks directory
    for parent in AI_CONFIG_PARENTS:
        if parent in parts:
            # Only if it's under a .claude or similar AI config root
            for indicator in AI_CONFIG_INDICATORS:
                if indicator in path_str:
                    return FileContext.AI_CONFIG

    # Check for plugin structure (.claude-plugin, plugin.json nearby)
    if ".claude-plugin" in path_str or "claude-plugin" in parts:
        return FileContext.AI_CONFIG

    # Check for test files
    name_lower = path.name.lower()
    if any(t in name_lower for t in ("test_", "spec_", "_test.", "_spec.", ".spec.", ".test.")):
        return FileContext.TEST_FIXTURE
    for part in parts:
        if part.lower() in TEST_INDICATORS:
            return FileContext.TEST_FIXTURE

    return FileContext.USER_CONTENT


def is_binary_file(path: Path, sample_size: int = 8192) -> bool:
    """Detect binary files by checking for null bytes in the first 8KB (git's method)."""
    try:
        with path.open("rb") as f:
            chunk = f.read(sample_size)
            return b"\x00" in chunk
    except (OSError, PermissionError):
        return True  # Treat unreadable files as binary


def safe_walk(
    root: Path,
    max_depth: int = 50,
    skip_dirs: Optional[Set[str]] = None,
    allow_system_dirs: bool = False,
    seen: Optional[Set[Tuple[int, int]]] = None,
) -> List[Path]:
    """Safely walk a directory tree with symlink loop detection and depth limiting.

    Uses (st_dev, st_ino) on Unix and path-string deduplication on Windows
    to detect loops.
    """
    if skip_dirs is None:
        skip_dirs = SKIP_DIRS
    if seen is None:
        seen = set()

    files: List[Path] = []
    root = root.resolve()

    # Check for system directories (exact match on the root itself)
    if not allow_system_dirs:
        root_str = str(root)
        for sys_dir in SYSTEM_DIRS:
            if root_str == sys_dir or root_str.rstrip("/\\") == sys_dir.rstrip("/\\"):
                logger.info("Skipping system directory: %s", root)
                return files

    def _walk(current: Path, depth: int) -> None:
        if depth > max_depth:
            logger.warning("Max depth %d reached at %s", max_depth, current)
            return

        try:
            st = current.stat()
        except (OSError, PermissionError):
            return

        # Loop detection: (device, inode) on Unix, path string on Windows
        if os.name == "nt":
            inode_key = (0, hash(str(current)))
        else:
            inode_key = (st.st_dev, st.st_ino)

        if inode_key in seen:
            logger.debug("Symlink loop detected at %s", current)
            return
        seen.add(inode_key)

        try:
            entries = sorted(current.iterdir())
        except (PermissionError, OSError) as e:
            logger.debug("Cannot read directory %s: %s", current, e)
            return

        for entry in entries:
            try:
                if entry.is_dir():
                    if entry.name in skip_dirs:
                        continue
                    if entry.is_symlink():
                        resolved = entry.resolve()
                        try:
                            resolved.relative_to(root)
                        except ValueError:
                            logger.debug("Symlink escapes scan boundary: %s -> %s", entry, resolved)
                            continue
                        try:
                            r_st = resolved.stat()
                            r_key = (
                                (0, hash(str(resolved)))
                                if os.name == "nt"
                                else (r_st.st_dev, r_st.st_ino)
                            )
                            if r_key in seen:
                                logger.debug("Symlink loop at %s -> %s", entry, resolved)
                                continue
                        except OSError:
                            continue
                    _walk(entry, depth + 1)
                elif entry.is_symlink():
                    logger.debug("Skipping file symlink: %s", entry)
                elif entry.is_file():
                    files.append(entry)
            except (PermissionError, OSError) as e:
                logger.debug("Cannot access %s: %s", entry, e)

    _walk(root, 0)
    return files


def should_scan_file(path: Path, max_file_size: int = DEFAULT_MAX_FILE_SIZE) -> Tuple[bool, str]:
    """Determine if a file should be scanned."""
    # Check file size
    try:
        size = path.stat().st_size
        if size > max_file_size:
            return False, f"File too large ({size:,} bytes > {max_file_size:,} byte limit)"
        if size == 0:
            return False, "Empty file"
    except OSError as e:
        return False, f"Cannot stat file: {e}"

    # Always scan certain filenames
    if path.name in ALWAYS_SCAN_NAMES:
        return True, ""

    # Check extension
    suffix = path.suffix.lower()
    if not suffix:
        # No extension — check if it looks like text
        if not is_binary_file(path):
            return True, ""
        return False, "Binary file (no extension)"

    if suffix in TEXT_EXTENSIONS:
        # Final check: is it actually binary?
        if is_binary_file(path):
            return False, f"Binary file despite {suffix} extension"
        return True, ""

    return False, f"Skipped extension: {suffix}"


def scan_file(
    path: Path,
    engine: PatternEngine,
    encoding: str = "utf-8",
    context_lines: int = 1,
    scan_ai_configs: bool = False,
) -> FileResult:
    """Scan a single file for prompt injection patterns.

    If the file is an AI config (skill, agent, prompt), only exfiltration and
    credential patterns are checked unless scan_ai_configs=True.
    """
    result = FileResult(path=path)
    file_context = classify_file_context(path)

    try:
        with path.open(encoding=encoding, errors="replace") as f:
            lines = f.readlines()
    except (OSError, PermissionError) as e:
        result.skipped = True
        result.skip_reason = f"Cannot read file: {e}"
        return result

    result.encoding_used = encoding

    for i, line in enumerate(lines, start=1):
        context_before = lines[max(0, i - 1 - context_lines) : i - 1]
        context_after = lines[i : min(len(lines), i + context_lines)]

        findings = engine.match_line(
            line=line.rstrip("\n\r"),
            file_path=path,
            line_number=i,
            context_before="".join(context_before).rstrip(),
            context_after="".join(context_after).rstrip(),
        )

        for finding in findings:
            finding.file_context = file_context

            # In AI config files, skip instructional patterns (they're expected)
            if file_context == FileContext.AI_CONFIG and not scan_ai_configs:
                if finding.pattern_id not in AI_CONFIG_ONLY_PATTERNS:
                    continue

            result.findings.append(finding)

    return result


class Scanner:
    """Main scanner orchestrating file discovery and pattern matching."""

    def __init__(
        self,
        engine: PatternEngine,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        skip_dirs: Optional[Set[str]] = None,
        allow_system_dirs: bool = False,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        scan_ai_configs: bool = False,
    ):
        self.engine = engine
        self.max_file_size = max_file_size
        self.skip_dirs = skip_dirs or SKIP_DIRS
        self.allow_system_dirs = allow_system_dirs
        self.progress_callback = progress_callback
        self.scan_ai_configs = scan_ai_configs

    def scan_paths(self, targets: List[Path]) -> Tuple[List[FileResult], ScanSummary]:
        """Scan one or more target paths."""
        start_time = time.time()
        all_files: List[Path] = []
        summary = ScanSummary()
        summary.directories_scanned = [str(t) for t in targets]
        summary.patterns_checked = self.engine.pattern_count

        # Collect all files
        for target in targets:
            target = target.resolve()
            if target.is_file():
                all_files.append(target)
            elif target.is_dir():
                all_files.extend(
                    safe_walk(
                        target,
                        skip_dirs=self.skip_dirs,
                        allow_system_dirs=self.allow_system_dirs,
                    )
                )
            else:
                logger.warning("Target not found: %s", target)

        total_files = len(all_files)
        file_results: List[FileResult] = []
        file_types_scanned: Dict[str, int] = {}
        file_types_skipped: Dict[str, int] = {}

        for idx, file_path in enumerate(all_files):
            if self.progress_callback:
                self.progress_callback(idx + 1, total_files, str(file_path))

            should_scan, skip_reason = should_scan_file(file_path, self.max_file_size)
            suffix = file_path.suffix.lower() or "(no ext)"

            if not should_scan:
                file_types_skipped[suffix] = file_types_skipped.get(suffix, 0) + 1
                summary.total_files_skipped += 1
                file_results.append(
                    FileResult(path=file_path, skipped=True, skip_reason=skip_reason)
                )
                continue

            file_types_scanned[suffix] = file_types_scanned.get(suffix, 0) + 1
            result = scan_file(file_path, self.engine, scan_ai_configs=self.scan_ai_configs)
            file_results.append(result)
            summary.total_files_scanned += 1

        summary.scan_duration_seconds = time.time() - start_time
        summary.file_types_scanned = file_types_scanned
        summary.file_types_skipped = file_types_skipped

        return file_results, summary
