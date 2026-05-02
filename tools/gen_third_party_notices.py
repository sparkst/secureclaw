#!/usr/bin/env python3
"""Regenerate THIRD_PARTY_NOTICES.md from rule + dependency metadata.

Per v1.3-plan-v10 PR-A7 + R5-ARCH001 fix:

THIRD_PARTY_NOTICES.md is **generated**, not hand-edited. Every PR that
touches ``secureclaw/rules/default_rules.json`` (and its ``sources[]``
attribution arrays) MUST re-run this generator and commit the diff. CI
gate ``test_third_party_notices_drift`` re-runs the generator and asserts
the committed file matches the regeneration output.

Usage:
    python tools/gen_third_party_notices.py            # write to file
    python tools/gen_third_party_notices.py --check    # diff-check, exit 1 on drift
    python tools/gen_third_party_notices.py --stdout   # print to stdout
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).parent.parent
RULES_PATH = ROOT / "secureclaw" / "rules" / "default_rules.json"
PYPROJECT_PATH = ROOT / "pyproject.toml"
OUTPUT_PATH = ROOT / "THIRD_PARTY_NOTICES.md"

# SPDX allowlist + denylist per v1.3-plan-v10 §C.4.
SPDX_ALLOWLIST = frozenset(
    {
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSD-3-Clause-Clear",
        "ISC",
        "Unlicense",
        "CC0-1.0",
        "MPL-2.0",
        "0BSD",
        "Llama-3.3-Community",  # v1.4 ML extras only; runtime-rejected per C.4
        # PSF / built-in stdlib markers used for clarity in the runtime-deps table:
        "PSF-2.0",
    }
)

SPDX_DENYLIST_PREFIXES = ("GPL-", "AGPL-", "LGPL-", "EUPL-", "SSPL-")


def _classify_license(spdx: str) -> str:
    """Return 'allowed', 'denied', or 'unknown'."""
    if spdx in SPDX_ALLOWLIST:
        return "allowed"
    if any(spdx.startswith(p) for p in SPDX_DENYLIST_PREFIXES):
        return "denied"
    return "unknown"


def _parse_pyproject_deps(pyproject_text: str) -> Dict[str, List[str]]:
    """Extract runtime + dev deps from pyproject.toml.

    Avoids tomllib so this works on Python 3.9. We just regex-grep the
    arrays we need.
    """
    out: Dict[str, List[str]] = {"runtime": [], "dev": []}

    # Runtime: [project] dependencies = [...]
    m = re.search(
        r"^\[project\]\s*$(?:.*?)^dependencies\s*=\s*\[(?P<body>.*?)^\]",
        pyproject_text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if m:
        out["runtime"] = _extract_dep_strings(m.group("body"))

    # Dev: [project.optional-dependencies] dev = [...]
    m = re.search(
        r"^\[project\.optional-dependencies\]\s*$(?:.*?)^dev\s*=\s*\[(?P<body>.*?)\]",
        pyproject_text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if m:
        out["dev"] = _extract_dep_strings(m.group("body"))
    return out


def _extract_dep_strings(body: str) -> List[str]:
    """Pull double-quoted dep specifiers out of a TOML array body."""
    return sorted(re.findall(r'"([^"]+)"', body))


# Best-effort license metadata for our small set of runtime + dev deps. This
# table is hand-maintained (small list); CI fails if a new dep appears
# without an entry here. Keeps THIRD_PARTY_NOTICES.md accurate without a
# transitive-dep walker.
DEP_LICENSE_TABLE = {
    "regex": ("Apache-2.0", "Unicode property classes + per-match timeout"),
    "send2trash": ("BSD-3-Clause", "Cross-platform recoverable delete"),
    "pytest": ("MIT", "Test framework (dev only)"),
    "ruff": ("MIT", "Lint + format (dev only)"),
    "PyYAML": ("MIT", "YAML parsing (dev only — workflow tests)"),
    "packaging": ("Apache-2.0 OR BSD-2-Clause", "Semver parsing for REQ-15 (dev only)"),
    "jsonschema": ("MIT", "Validate corpus expected.json against schema (dev only)"),
    "hypothesis": ("MPL-2.0", "Property-based PEM line-count tests (dev only)"),
}


def _strip_specifier(dep: str) -> str:
    """Get just the package name from `regex==2024.11.6` or `pytest>=7.0`."""
    return re.split(r"[<>=!~\s]", dep, maxsplit=1)[0].strip()


def _format_dep_table(deps: List[str], heading: str) -> List[str]:
    """Build a markdown table for a list of pyproject deps."""
    lines = [f"## {heading}\n", "| Package | Version | License | Role |", "|---|---|---|---|"]
    if not deps:
        lines.append("| _none_ | | | |")
        return lines
    for dep in deps:
        name = _strip_specifier(dep)
        version = dep[len(name) :].strip() or "any"
        spec = DEP_LICENSE_TABLE.get(name)
        if spec is None:
            print(
                f"WARNING: dependency {name!r} has no entry in DEP_LICENSE_TABLE",
                file=sys.stderr,
            )
            license_id, role = "?", "**license unknown — add to DEP_LICENSE_TABLE**"
        else:
            license_id, role = spec
        lines.append(f"| `{name}` | `{version}` | {license_id} | {role} |")
    return lines


def _format_pattern_table(patterns: List[Dict[str, Any]]) -> List[str]:
    """Build the pattern-attribution table from rule sources[] metadata.

    Rules without ``sources`` are listed under "Own work" with license
    "MIT (own work)". Rules with sources flatten one row per source entry.
    """
    lines = [
        "## Pattern Catalog\n",
        "_Generated from `secureclaw/rules/default_rules.json` `sources[]` metadata._",
        "",
        "| Rule ID | Source | License | Upstream Commit | Fetched | Role |",
        "|---|---|---|---|---|---|",
    ]
    own_work_count = 0
    sources_seen: Dict[str, str] = {}
    for entry in sorted(patterns, key=lambda p: p["id"]):
        rule_id = entry["id"]
        sources = entry.get("sources", [])
        if not sources:
            own_work_count += 1
            continue
        for src in sources:
            url = src.get("url", "?")
            spdx = src.get("spdx_id", "?")
            commit = src.get("commit", "?")
            short_commit = commit[:8] if commit and commit != "?" else "?"
            fetched = src.get("fetched_date", "?")
            role = src.get("role", "?")
            lines.append(
                f"| {rule_id} | <{url}> | {spdx} | `{short_commit}` | {fetched} | {role} |"
            )
            sources_seen[url] = spdx

    if own_work_count > 0:
        lines.append(
            f"| _{own_work_count} rules_ | (own work — `MIT`) | MIT | n/a | n/a | identical |"
        )

    # License-compatibility audit summary
    classifications: Dict[str, int] = defaultdict(int)
    for spdx in sources_seen.values():
        classifications[_classify_license(spdx)] += 1
    if classifications:
        lines.append("")
        lines.append("**License compatibility audit:**")
        for klass in ("allowed", "unknown", "denied"):
            n = classifications.get(klass, 0)
            if n:
                lines.append(f"- {klass}: {n}")
        if classifications.get("denied", 0) > 0:
            lines.append(
                ">  ⚠️  **Denied licenses present** — CI rule loader will reject. "
                "Either re-derive from clean upstream or remove the rule."
            )

    return lines


HEADER = """\
# Third-Party Notices

This file lists upstream sources from which SecureClaw rules and code are
derived, along with their licenses and version pins. It is **generated** by
``tools/gen_third_party_notices.py``.

**DO NOT EDIT MANUALLY.** Drift between this file and rule metadata is a CI
failure (``test_third_party_notices_drift``).

## Generation

```bash
python tools/gen_third_party_notices.py            # write
python tools/gen_third_party_notices.py --check    # diff against committed
```

## Allowed Licenses

Rules and runtime dependencies must carry permissive licenses compatible with
SecureClaw's MIT release.

**Allowed**: ``MIT``, ``Apache-2.0``, ``BSD-2-Clause``, ``BSD-3-Clause``,
``ISC``, ``Unlicense``, ``CC0-1.0``, ``MPL-2.0``, ``BSD-3-Clause-Clear``,
``0BSD``. ``Llama-3.3-Community`` allowed for ``[ml]`` extras only.

**Denied**: ``GPL-*``, ``AGPL-*``, ``LGPL-*``, ``EUPL-*``, ``SSPL-*``.
Patterns inspired by GPL-licensed upstreams (notably ``utkusen/promptmap``)
are re-derived from clean upstream sources cited in the rule's ``sources[]``.

"""


def render() -> str:
    rules = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    pyproject_text = PYPROJECT_PATH.read_text(encoding="utf-8")
    deps = _parse_pyproject_deps(pyproject_text)

    parts: List[str] = [HEADER]
    parts.append("\n".join(_format_dep_table(deps["runtime"], "Runtime Dependencies")))
    parts.append("")
    parts.append("\n".join(_format_dep_table(deps["dev"], "Development Dependencies")))
    parts.append("")
    parts.append("\n".join(_format_pattern_table(rules.get("patterns", []))))
    parts.append("")
    parts.append(
        "---\n\n"
        "For corrections, open a PR that updates the rule's ``sources[]`` field in "
        "``secureclaw/rules/default_rules.json`` (or the ``DEP_LICENSE_TABLE`` in this "
        "generator), then re-run the generator and commit the diff.\n"
    )
    return "\n".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="Diff-check; exit 1 on drift.")
    ap.add_argument("--stdout", action="store_true", help="Print to stdout instead of write.")
    args = ap.parse_args()

    rendered = render()

    if args.stdout:
        sys.stdout.write(rendered)
        return 0

    if args.check:
        existing = OUTPUT_PATH.read_text(encoding="utf-8") if OUTPUT_PATH.exists() else ""
        if existing != rendered:
            sys.stderr.write(
                "DRIFT: THIRD_PARTY_NOTICES.md is out of date. "
                "Run `python tools/gen_third_party_notices.py` and commit the diff.\n"
            )
            return 1
        return 0

    OUTPUT_PATH.write_text(rendered, encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
