"""Static checks that prevent the standalone bundler aliasing trap.

`tools/build_standalone.py` strips every line matching
``^from secureclaw\\b.*import\\b`` from each inlined module. This is fine
for unaliased imports (the symbol still resolves because every module is
concatenated into a single namespace), but **aliased** imports break:

    from secureclaw import attach as attach_corpus     # PR-C bug (commit 421a9ec)
    from secureclaw import dispatch as dispatch_corpus  # PR-C bug
    from secureclaw import __version__ as _secureclaw_version  # PR-E bug (commit 54ed310)

After the strip, the alias never gets bound — `attach_corpus` /
`dispatch_corpus` / `_secureclaw_version` end up undefined and the
standalone CLI crashes with `NameError`.

This test fails any future commit that introduces another aliased
``from secureclaw...`` import inside the standalone-bundled tree, so the
same class of bug can't ship a fourth time.

Scope: only files that the bundler inlines (per the SECTIONS list in
``tools/build_standalone.py``). Tests, dev-only scripts, and the GUI
server are excluded — they don't end up in ``dist/secureclaw.py``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "secureclaw"

# Pattern matches: from secureclaw[.subpackage] import <name> as <alias>
# Both single-line and multi-line `import (...)` parenthesized forms.
_ALIASED_IMPORT_RE = re.compile(
    r"^\s*from\s+secureclaw\b[\w.]*\s+import\b[^\n]*\bas\s+\w+",
    re.MULTILINE,
)


def _bundled_module_paths() -> list[Path]:
    """Return every Python module the standalone bundler inlines.

    Reads tools/build_standalone.py to extract the SECTIONS list rather
    than duplicating it here — single source of truth.
    """
    bundler_src = (REPO_ROOT / "tools" / "build_standalone.py").read_text(encoding="utf-8")
    # Match SRC / "x" / "y" path components inside the SECTIONS tuple.
    section_re = re.compile(r"SRC\s*/\s*((?:\"[^\"]+\"\s*/\s*)*\"[^\"]+\")")
    parts_re = re.compile(r"\"([^\"]+)\"")
    paths: list[Path] = []
    for match in section_re.finditer(bundler_src):
        parts = parts_re.findall(match.group(1))
        if parts:
            paths.append(SRC.joinpath(*parts))
    return paths


def test_bundled_modules_have_no_aliased_secureclaw_imports() -> None:
    """No `from secureclaw[.x] import Y as Z` in any bundled module.

    The standalone bundler strips these lines and the alias never binds —
    leading to `NameError` at standalone runtime. Use the canonical name
    directly, or rename the function/symbol so no alias is needed.
    """
    offenders: list[tuple[Path, int, str]] = []
    for module_path in _bundled_module_paths():
        if not module_path.is_file():
            continue  # bundler will fail loudly on missing file, separate concern
        text = module_path.read_text(encoding="utf-8")
        for match in _ALIASED_IMPORT_RE.finditer(text):
            line_no = text[: match.start()].count("\n") + 1
            offenders.append((module_path.relative_to(REPO_ROOT), line_no, match.group(0).strip()))

    if offenders:
        msg = (
            "Aliased `from secureclaw...` imports break the standalone bundler "
            "(see tests/test_standalone_bundler_invariants.py docstring). Use the "
            "canonical name directly. Offenders:\n"
        )
        for path, line, text in offenders:
            msg += f"  {path}:{line}  {text}\n"
        pytest.fail(msg)


def test_bundler_sections_list_is_parseable() -> None:
    """The static helper above must actually find the SECTIONS list.

    Guards against future bundler refactors that change the SECTIONS
    syntax in a way the regex can't see, which would silently make the
    aliased-import check vacuous.
    """
    paths = _bundled_module_paths()
    assert len(paths) >= 10, (
        f"_bundled_module_paths returned only {len(paths)} entries; "
        "the regex against tools/build_standalone.py SECTIONS may be out of date"
    )
    # Every path should resolve to a real .py file.
    missing = [p for p in paths if not p.is_file()]
    assert not missing, f"bundler SECTIONS references missing files: {missing}"
