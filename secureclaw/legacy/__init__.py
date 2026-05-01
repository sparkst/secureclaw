"""Frozen pre-v1.3 engine snapshot for SECURECLAW_ENGINE=v1 rollback.

Per v1.3-plan-v10 §K.5: this directory is a verbatim snapshot of the
pre-Foundation engine code, captured BEFORE PR-A3 (score decomposition).
The dispatcher in ``secureclaw/__init__.py`` routes scoring through here
when the user sets ``SECURECLAW_ENGINE=v1`` (or any alias canonicalizing
to ``legacy``).

Lifecycle:
- v1.3.0: legacy ships, dispatcher routes via env var; banner emitted.
- v1.3.x: deprecation warning emitted on import when legacy is active.
- v1.4.0: this directory is removed; env var produces a warning + uses
  default.

CVE patches MAY land here through the dedicated PR-CVE-* workflow per
``docs/security.md``. All other changes are forbidden by CODEOWNERS.
"""

from __future__ import annotations
