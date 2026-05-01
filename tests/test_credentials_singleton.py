"""Single-source-of-truth invariants for credential detection.

REAL_TOKEN_PREFIXES and PLACEHOLDER_PATTERNS live in
``secureclaw/core/credentials.py``. ``confidence.py`` re-exports them for
backward compatibility, and the upcoming anonymizer (PR-C) will import from
``credentials.py`` directly. CI fails if drift is introduced.
"""

from __future__ import annotations

from secureclaw.core import confidence, credentials


def test_credentials_module_exports() -> None:
    assert hasattr(credentials, "REAL_TOKEN_PREFIXES")
    assert hasattr(credentials, "PLACEHOLDER_PATTERNS")
    assert isinstance(credentials.REAL_TOKEN_PREFIXES, tuple)
    assert all(isinstance(p, str) for p in credentials.REAL_TOKEN_PREFIXES)


def test_confidence_reexports_match_credentials() -> None:
    """confidence.py must re-export the same objects (identity, not copy)."""
    assert confidence.REAL_TOKEN_PREFIXES is credentials.REAL_TOKEN_PREFIXES
    assert confidence.PLACEHOLDER_PATTERNS is credentials.PLACEHOLDER_PATTERNS


def test_real_token_prefixes_are_well_known() -> None:
    """Sanity: every prefix should look like a real-world credential prefix."""
    expected = {
        "sk-ant-",
        "sk-proj-",
        "sk-",
        "ghp_",
        "gho_",
        "ghs_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "AKIA",
        "eyJ",
        "AIza",
        "r8_",
        "hf_",
        "Bearer ",
    }
    assert set(credentials.REAL_TOKEN_PREFIXES) == expected


def test_placeholder_patterns_match_common_examples() -> None:
    p = credentials.PLACEHOLDER_PATTERNS
    for example in ("YOUR_TOKEN", "your-key", "changeme", "REPLACE_ME", "<your-key>", "dummy"):
        assert p.search(example), f"placeholder regex should match: {example!r}"


def test_placeholder_patterns_dont_match_real_keys() -> None:
    p = credentials.PLACEHOLDER_PATTERNS
    for real in (
        "sk-ant-api03-abc123",
        "ghp_abcdefghij1234567890ABCDEFGHIJklmnopqrst",
        "AKIAIOSFODNN7EXAMPLE",
        "AIzaSyABCDEFGHIJKLMNOP",
    ):
        assert p.search(real) is None, f"placeholder regex should NOT match real key {real!r}"
