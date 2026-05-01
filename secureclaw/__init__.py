"""SecureClaw — Cross-platform prompt injection scanner."""

from __future__ import annotations

import os
import sys

__version__ = "1.2.0"

# ---------------------------------------------------------------------------
# Engine dispatcher (REQ-13, REQ-18, REQ-20)
# ---------------------------------------------------------------------------
# Per v1.3-plan-v10 §K.5 and §H.12, SecureClaw v1.3 ships with a frozen
# pre-v1.3 engine snapshot at ``secureclaw.legacy.v1_engine`` so users can
# fall back to v1.2 behavior via the ``SECURECLAW_ENGINE`` env var.
#
# Precedence (REQ-20):
#     1. SECURECLAW_ENGINE env var (case-insensitive; aliases below).
#     2. ~/.secureclaw/config.json {"engine": "default"|"legacy"} (PR-K-PR).
#     3. Default ("default").
#
# When the canonicalized value is ``legacy``:
#   - Tier A banner emits at module import (this file) — catches CLI/script use.
#   - Tier B banner re-emits at scan time (Scanner.run) per REQ-18.
#   - All five reporters render ``legacy_engine_active: true`` (PR-K-PR).
#
# Aliases per v1.3-plan-v10 §H.12 (canonicalizer):
ENV_ENGINE_ALIASES = {
    "v1": "legacy",
    "1": "legacy",
    "legacy": "legacy",
    "v2": "default",
    "2": "default",
    "default": "default",
    "": "default",
}


def _canonical_engine_setting(raw: object) -> str:
    """Normalize an engine selection to ``"default"`` or ``"legacy"``.

    Unknown values fail-safe to ``"default"`` (REQ-18 fail-safe).
    """
    if raw is None:
        return "default"
    return ENV_ENGINE_ALIASES.get(str(raw).strip().lower(), "default")


def get_active_engine() -> str:
    """Return the active engine name based on REQ-20 precedence.

    Note: ``~/.secureclaw/config.json`` is read by the GUI preferences
    endpoint (PR-K-PR). At the engine boundary we honor whichever value
    is currently set in the environment; if not set, we currently fall
    through to ``"default"`` because the GUI hasn't shipped yet.
    """
    env_val = os.environ.get("SECURECLAW_ENGINE")
    if env_val is not None:
        return _canonical_engine_setting(env_val)
    # Future: read ~/.secureclaw/config.json here once PR-K-PR lands.
    return "default"


# Disabled-rules summary for the banner. Updated as new categories ship.
_DISABLED_WHEN_LEGACY = "PI-N01..PI-N14"


def _emit_legacy_banner_to_stderr() -> None:
    """Tier A banner: emitted at import time when legacy is active."""
    sys.stderr.write(
        "\n"
        "*** SecureClaw: LEGACY ENGINE ACTIVE ***\n"
        "*** SECURECLAW_ENGINE set to legacy alias. ***\n"
        f"*** New rules ({_DISABLED_WHEN_LEGACY}) DISABLED. ***\n"
        "*** Unset SECURECLAW_ENGINE or set 'default' to enable v1.3 engine. ***\n"
        "\n"
    )


# Emit Tier A banner once at import if legacy is active. Caller may suppress
# stderr (e.g. ``2>/dev/null``); Tier B (in Scanner.run, future PR) is the
# unbypassable signal via JSON output ``legacy_engine_active: true``.
if get_active_engine() == "legacy":
    _emit_legacy_banner_to_stderr()
