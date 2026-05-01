"""Smoke tests for runtime dependencies.

Per v1.3-plan-v10 §B.8 (regex library decision) and §G.0 (send2trash for
Move-to-Trash UX), SecureClaw v1.3 declares two runtime deps:

    regex==2024.11.6   — Apache-2.0; Unicode property classes + per-match
                         timeout for ReDoS protection.
    send2trash>=1.8    — BSD-3; cross-platform recoverable delete.

These tests verify the libraries are importable, expose the APIs the engine
will use, and don't conflict with stdlib imports.
"""

from __future__ import annotations


def test_regex_library_importable() -> None:
    import regex

    # Basic compile + match
    pat = regex.compile(r"\b\w+\b")
    assert pat.search("hello world") is not None


def test_regex_library_supports_timeout_kwarg() -> None:
    """B.8: per-match timeout is the safety net for ReDoS protection."""
    import regex

    pat = regex.compile(r"a*b")
    # `timeout` keyword on `match`. Catastrophic-backtracking inputs trigger
    # `regex.error: timeout`, which the engine catches and quarantines.
    result = pat.match("aaab", timeout=1.0)
    assert result is not None


def test_regex_library_supports_unicode_property_classes() -> None:
    """B.4: sentence segmentation needs \\p{Lu}|\\p{Lo} for CJK/Arabic."""
    import regex

    # \p{Lu} = uppercase letter (Latin/Cyrillic/Greek/etc.)
    # \p{Lo} = "other letter" (CJK ideographs, Korean Hangul, etc.)
    pat = regex.compile(r"\p{Lu}|\p{Lo}")

    # Latin uppercase
    assert pat.search("Hello") is not None
    # CJK
    assert pat.search("中文") is not None
    # Korean
    assert pat.search("한글") is not None
    # All-lowercase Latin: must not match
    assert pat.search("hello") is None


def test_regex_library_supports_tag_block_in_class() -> None:
    """B.2 P2: Unicode Tag block U+E0000-U+E007F must be expressible."""
    import regex

    # Tag block range — used to strip ASCII smuggling
    pat = regex.compile(r"[\U000E0000-\U000E007F]")
    visible = "Hello"
    smuggled = "Hello\U000e0048\U000e0069"  # "Hi" in tag chars
    assert pat.search(visible) is None
    assert pat.search(smuggled) is not None


def test_send2trash_library_importable() -> None:
    """G.0: send2trash powers the Move-to-Trash affordance per finding."""
    import send2trash

    assert hasattr(send2trash, "send2trash")


def test_pyproject_pins_regex_exactly() -> None:
    """B.8 + R19: regex is pinned exactly to a known-good version."""
    from pathlib import Path

    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert "regex==2024.11.6" in content


def test_pyproject_pins_send2trash_range() -> None:
    """G.0: send2trash range-pinned for stability + security patches."""
    from pathlib import Path

    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    assert "send2trash>=1.8,<2.0" in content
