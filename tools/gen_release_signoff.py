#!/usr/bin/env python3
"""Generate a release sign-off PR body from the template + version.

Per v1.3-plan-v10 §K.10: every release tag has a dedicated sign-off PR
that lists every Section N DoD item with linked evidence. The
``release-signoff-evidence-check`` CI gate (separate workflow, future
PR) verifies every checkbox is ticked and every Evidence link resolves
before allowing merge.

This script is intentionally minimal: it interpolates the version into
the template at ``.github/PULL_REQUEST_TEMPLATE/release-signoff.md`` and
prints to stdout. The template itself is the source of truth for the
checklist; updating that template is the way to keep release sign-offs
current.

Usage:
    python tools/gen_release_signoff.py 1.3.0 > /tmp/signoff.md
    gh pr create --base main --body-file /tmp/signoff.md \\
        --title "Release Sign-Off: v1.3.0"
"""

from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
TEMPLATE = ROOT / ".github" / "PULL_REQUEST_TEMPLATE" / "release-signoff.md"


def render(version: str, today: str | None = None) -> str:
    text = TEMPLATE.read_text(encoding="utf-8")
    today = today or datetime.date.today().isoformat()
    text = text.replace("_VERSION_", version)
    text = text.replace("_DATE_", today)
    return text


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("version", help="Release version (e.g., 1.3.0)")
    ap.add_argument(
        "--today",
        help="Override today's date (ISO-8601). Useful for deterministic tests.",
    )
    args = ap.parse_args()
    sys.stdout.write(render(args.version, args.today))
    return 0


if __name__ == "__main__":
    sys.exit(main())
