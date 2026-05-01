#!/usr/bin/env python3
"""Build the standalone secureclaw.py single-file distribution.

Reads all source modules and assembles them into a single zero-dependency Python file.
"""

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
SRC = ROOT / "secureclaw"
DIST = ROOT / "dist"
SITE = ROOT.parent / "secureclaw-site" / "public"

VERSION = "1.2.0"

# Modules in dependency order (each module only depends on modules above it)
SECTIONS = [
    ("Core Models", SRC / "core" / "models.py"),
    ("Pattern Engine", SRC / "core" / "patterns.py"),
    ("File Scanner", SRC / "core" / "scanner.py"),
    ("Allowlist", SRC / "core" / "allowlist.py"),
    ("Credentials Single Source of Truth", SRC / "core" / "credentials.py"),
    ("Match Quality Scoring (content-only)", SRC / "core" / "match_quality.py"),
    ("Path Heuristics Scoring (path-only)", SRC / "core" / "path_heuristics.py"),
    ("Confidence Scoring (composer)", SRC / "core" / "confidence.py"),
    ("Symlink-Safe Filesystem Primitives", SRC / "core" / "safe_fs.py"),
    ("Auto-Remediation", SRC / "core" / "remediate.py"),
    ("Posture Analyzer", SRC / "posture" / "analyzer.py"),
    ("Terminal Reporter", SRC / "reporters" / "terminal.py"),
    ("HTML Reporter", SRC / "reporters" / "html_report.py"),
    ("JSON Reporter", SRC / "reporters" / "json_report.py"),
    ("GUI Server", SRC / "gui.py"),
    ("Dev CLI Subcommands", SRC / "dev" / "cli.py"),
    ("CLI", SRC / "cli.py"),
]

# Lines to strip from module code (intra-package imports, duplicate future imports)
STRIP_PATTERNS = [
    re.compile(r"^from secureclaw\b.*import\b.*$"),
    re.compile(r"^from __future__ import annotations\s*$"),
    re.compile(r"^import secureclaw\b.*$"),
]


def strip_internal_imports(code: str) -> str:
    """Remove secureclaw.* imports and duplicate __future__ imports.

    Handles multi-line imports like:
        from secureclaw.core.models import (
            Finding,
            Pattern,
        )
    """
    lines = code.split("\n")
    result = []
    in_multiline_strip = False

    for line in lines:
        stripped = line.strip()

        # If we're inside a multi-line import being stripped, skip until closing paren
        if in_multiline_strip:
            if ")" in stripped:
                in_multiline_strip = False
            continue

        # Check if this line should be stripped
        skip = False
        for pat in STRIP_PATTERNS:
            if pat.match(stripped):
                # Check if it's the start of a multi-line import (has open paren but no close)
                if "(" in stripped and ")" not in stripped:
                    in_multiline_strip = True
                skip = True
                break

        if not skip:
            result.append(line)

    return "\n".join(result)


def strip_module_docstring(code: str) -> str:
    """Strip the leading module docstring (triple-quoted) from code."""
    stripped = code.lstrip()
    if stripped.startswith('"""'):
        end = stripped.find('"""', 3)
        if end != -1:
            return stripped[end + 3:].lstrip("\n")
    if stripped.startswith("'''"):
        end = stripped.find("'''", 3)
        if end != -1:
            return stripped[end + 3:].lstrip("\n")
    return code


def section_separator(name: str) -> str:
    bar = "# " + "=" * 59
    return f"\n{bar}\n# {name}\n{bar}\n"


def build() -> Path:
    """Assemble the standalone file."""
    # Load embedded rules
    rules_path = SRC / "rules" / "default_rules.json"
    rules_json = json.dumps(json.loads(rules_path.read_text("utf-8")), separators=(",", ":"), ensure_ascii=True)

    parts = []

    # Header
    parts.append(f'''#!/usr/bin/env python3
"""SecureClaw v{VERSION} - Cross-platform prompt injection scanner.

Standalone single-file distribution. Zero dependencies, Python 3.9+.
Your AI reads your files. Make sure those files aren't trying to hijack it.

Built by Sparkry AI - https://secureclaw.sparkry.ai
Source: https://github.com/sparkryai/secureclaw

Usage:
    python3 secureclaw.py scan .
    python3 secureclaw.py scan ~/Documents ~/.claude --format html -o report.html
    python3 secureclaw.py scan . --format json -o report.json && python3 secureclaw.py fix report.json
    python3 secureclaw.py posture
"""

from __future__ import annotations

__version__ = "{VERSION}"
''')

    # Embedded rules — use repr() to generate a valid Python string literal
    # that handles all escape sequences correctly
    parts.append(section_separator("Embedded default rules (do not edit manually)"))
    parts.append(f"_EMBEDDED_RULES_JSON = {repr(rules_json)}\n")

    # Each source module — insert standalone override after Pattern Engine
    for name, path in SECTIONS:
        code = path.read_text("utf-8")
        code = strip_internal_imports(code)
        code = strip_module_docstring(code)
        parts.append(section_separator(name))
        parts.append(code.rstrip() + "\n")

        # After Pattern Engine, override load_default_patterns to use embedded JSON
        if name == "Pattern Engine":
            parts.append(section_separator("Standalone: embedded rules loader"))
            parts.append('''
# Override load_default_patterns to use embedded JSON (standalone mode)
_original_load_default_patterns = load_default_patterns

def load_default_patterns() -> list:
    """Load patterns from embedded rules (standalone mode)."""
    import json as _json
    data = _json.loads(_EMBEDDED_RULES_JSON)
    patterns = []
    for entry in data.get("patterns", []):
        patterns.append(
            Pattern(
                id=entry["id"],
                name=entry["name"],
                regex=entry["regex"],
                severity=_severity_from_str(entry.get("severity", "advisory")),
                category=_category_from_str(entry.get("category", "instruction_override")),
                description=entry.get("description", ""),
                remediation=entry.get("remediation", ""),
                examples=entry.get("examples", []),
                case_sensitive=entry.get("case_sensitive", False),
            )
        )
    return patterns
''')

    # Entry point
    parts.append(section_separator("Entry Point"))
    parts.append('''
if __name__ == "__main__":
    main()
''')

    DIST.mkdir(exist_ok=True)
    output = DIST / "secureclaw.py"
    content = "\n".join(parts)
    output.write_text(content, encoding="utf-8")
    return output


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _check_command(output: Path, *args: str) -> None:
    """Run the standalone file with the given args and exit on failure."""
    label = " ".join(args) if args else "--version"
    result = subprocess.run(
        [sys.executable, str(output), *args],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"  ERROR: standalone {label} failed: {result.stderr}")
        sys.exit(1)
    out = result.stdout.strip()
    print(f"  {label}: {out if out else 'OK'}")


def main():
    print(f"Building SecureClaw v{VERSION} standalone...")

    output = build()
    line_count = sum(1 for _ in output.read_text(encoding="utf-8").splitlines())
    print(f"  Written: {output} ({output.stat().st_size:,} bytes, {line_count} lines)")

    sha = compute_sha256(output)
    sums_path = DIST / "SHA256SUMS"
    sums_path.write_text(f"{sha}  secureclaw.py\n")
    print(f"  SHA256: {sha}")

    _check_command(output, "--version")
    _check_command(output, "scan", "--help")
    _check_command(output, "fix", "--help")
    _check_command(output, "gui", "--help")

    # Copy to site
    if SITE.exists():
        shutil.copy2(output, SITE / "secureclaw.py")
        shutil.copy2(sums_path, SITE / "SHA256SUMS")
        print(f"  Copied to site: {SITE}")
    else:
        print(f"  Site directory not found: {SITE}")

    print("Done.")


if __name__ == "__main__":
    main()
