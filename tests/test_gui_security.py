"""Tests for GUI server security primitives (PR-K-PR).

Per v1.3-plan-v10 REQ-16 + §H.11 + §H.12 + §H.4.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from secureclaw.core.gui_security import (
    PathRejected,
    SessionToken,
    canonical_engine_setting,
    extract_bearer_token,
    raise_if_outside_scan_root,
    redact_token_in_log,
    validate_host_header,
    validate_origin,
)


# ---------------------------------------------------------------------------
# canonical_engine_setting
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("v1", "legacy"),
        ("V1", "legacy"),
        ("legacy", "legacy"),
        ("LEGACY", "legacy"),
        ("1", "legacy"),
        (" v1 ", "legacy"),
        ("default", "default"),
        ("v2", "default"),
        ("2", "default"),
        ("", "default"),
        ("garbage", "default"),
        ("v9999", "default"),
        (None, "default"),
    ],
)
def test_canonical_engine_setting(raw: object, expected: str) -> None:
    assert canonical_engine_setting(raw) == expected


# ---------------------------------------------------------------------------
# SessionToken
# ---------------------------------------------------------------------------


def test_session_token_default_value_is_url_safe_and_long() -> None:
    t = SessionToken()
    assert len(t.value) >= 32
    # urlsafe alphabet: A-Z, a-z, 0-9, -, _
    assert all(c.isalnum() or c in "-_" for c in t.value)


def test_session_token_starts_unexpired() -> None:
    t = SessionToken()
    assert not t.is_expired()


def test_session_token_expires_after_ttl() -> None:
    t = SessionToken(ttl_seconds=0.01)
    time.sleep(0.05)
    assert t.is_expired()


def test_session_token_touch_resets_expiry() -> None:
    t = SessionToken(ttl_seconds=0.01)
    time.sleep(0.05)
    assert t.is_expired()
    t.touch()
    assert not t.is_expired()


def test_session_token_rotate_changes_value() -> None:
    t = SessionToken()
    old = t.value
    t.rotate()
    assert t.value != old
    assert not t.is_expired()


# ---------------------------------------------------------------------------
# extract_bearer_token
# ---------------------------------------------------------------------------


def test_bearer_extraction_happy_path() -> None:
    assert extract_bearer_token({"Authorization": "Bearer abc123"}) == "abc123"


def test_bearer_extraction_case_insensitive_scheme() -> None:
    assert extract_bearer_token({"Authorization": "bearer abc"}) == "abc"
    assert extract_bearer_token({"Authorization": "BEARER abc"}) == "abc"


def test_bearer_extraction_lowercase_header_name() -> None:
    """HTTP servers may pass the header in lowercase."""
    assert extract_bearer_token({"authorization": "Bearer xyz"}) == "xyz"


def test_bearer_extraction_missing_header() -> None:
    assert extract_bearer_token({}) is None


def test_bearer_extraction_wrong_scheme() -> None:
    assert extract_bearer_token({"Authorization": "Basic dXNlcjpwYXNz"}) is None


def test_bearer_extraction_no_token() -> None:
    assert extract_bearer_token({"Authorization": "Bearer "}) is None
    assert extract_bearer_token({"Authorization": "Bearer"}) is None


# ---------------------------------------------------------------------------
# validate_host_header
# ---------------------------------------------------------------------------


def test_host_header_valid_127() -> None:
    assert validate_host_header("127.0.0.1:54321", expected_port=54321)


def test_host_header_valid_localhost() -> None:
    assert validate_host_header("localhost:54321", expected_port=54321)


def test_host_header_rejects_external_host() -> None:
    assert not validate_host_header("evil.com:54321", expected_port=54321)


def test_host_header_rejects_wrong_port() -> None:
    assert not validate_host_header("127.0.0.1:99999", expected_port=54321)


def test_host_header_rejects_missing_port() -> None:
    assert not validate_host_header("127.0.0.1", expected_port=54321)


def test_host_header_rejects_empty() -> None:
    assert not validate_host_header(None, expected_port=54321)
    assert not validate_host_header("", expected_port=54321)


def test_host_header_no_expected_port_passes_any_port() -> None:
    assert validate_host_header("127.0.0.1:1234")


# ---------------------------------------------------------------------------
# validate_origin
# ---------------------------------------------------------------------------


def test_origin_exact_match_passes() -> None:
    assert validate_origin(
        "http://127.0.0.1:54321",
        allowed_origins=["http://127.0.0.1:54321", "http://localhost:54321"],
    )


def test_origin_mismatch_rejected() -> None:
    assert not validate_origin(
        "http://evil.com",
        allowed_origins=["http://127.0.0.1:54321"],
    )


def test_origin_missing_rejected() -> None:
    assert not validate_origin(None, allowed_origins=["http://127.0.0.1:54321"])
    assert not validate_origin("", allowed_origins=["http://127.0.0.1:54321"])


# ---------------------------------------------------------------------------
# redact_token_in_log
# ---------------------------------------------------------------------------


def test_redact_authorization_bearer() -> None:
    line = "GET /api/scan HTTP/1.1\nAuthorization: Bearer abc123def456\n"
    out = redact_token_in_log(line)
    assert "abc123def456" not in out
    assert "[REDACTED]" in out


def test_redact_token_query_param() -> None:
    line = "GET /view?file=foo.txt&token=secret123 HTTP/1.1"
    out = redact_token_in_log(line)
    assert "secret123" not in out
    assert "[REDACTED]" in out


def test_redact_token_in_url_fragment() -> None:
    line = "Referer: http://127.0.0.1:54321/#token=secret456"
    out = redact_token_in_log(line)
    assert "secret456" not in out


def test_redact_token_in_json() -> None:
    line = '{"token": "supersecret789", "user": "alice"}'
    out = redact_token_in_log(line)
    assert "supersecret789" not in out
    assert "alice" in out  # only token redacted


def test_redact_no_op_on_clean_line() -> None:
    line = "GET / HTTP/1.1"
    assert redact_token_in_log(line) == line


# ---------------------------------------------------------------------------
# raise_if_outside_scan_root
# ---------------------------------------------------------------------------


def test_path_inside_visited_root_passes(tmp_path: Path) -> None:
    target = tmp_path / "subdir" / "file.txt"
    target.parent.mkdir()
    target.write_text("x")
    resolved = raise_if_outside_scan_root(str(target), scan_roots_visited=[tmp_path])
    assert resolved == target.resolve()


def test_path_outside_visited_root_rejected(tmp_path: Path) -> None:
    other = tmp_path / "other"
    other.mkdir()
    target = other / "file.txt"
    target.write_text("x")
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    with pytest.raises(PathRejected, match="outside all visited"):
        raise_if_outside_scan_root(str(target), scan_roots_visited=[scan_root])


def test_path_with_double_dot_rejected(tmp_path: Path) -> None:
    with pytest.raises(PathRejected, match="forbidden path segment"):
        raise_if_outside_scan_root(
            str(tmp_path / ".." / "etc" / "passwd"),
            scan_roots_visited=[tmp_path],
        )


def test_path_with_null_byte_rejected(tmp_path: Path) -> None:
    with pytest.raises(PathRejected, match="null byte"):
        raise_if_outside_scan_root(
            str(tmp_path / "file\x00.txt"),
            scan_roots_visited=[tmp_path],
        )


def test_path_with_unc_prefix_rejected(tmp_path: Path) -> None:
    with pytest.raises(PathRejected, match="UNC"):
        raise_if_outside_scan_root(
            "\\\\evil-share\\file.txt",
            scan_roots_visited=[tmp_path],
        )


def test_path_url_double_encoded_rejected(tmp_path: Path) -> None:
    """%252e%252e/etc/passwd would unquote to %2e%2e/... still containing
    %, indicating double-encoding."""
    with pytest.raises(PathRejected, match="double-encoded"):
        raise_if_outside_scan_root(
            "%252e%252e/etc/passwd",
            scan_roots_visited=[tmp_path],
        )


def test_path_resolve_failure_rejected(tmp_path: Path) -> None:
    with pytest.raises(PathRejected, match="does not resolve"):
        raise_if_outside_scan_root(
            str(tmp_path / "nonexistent.txt"),
            scan_roots_visited=[tmp_path],
        )
