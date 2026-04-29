"""Tests for the browser-based GUI server."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import HTTPServer

import pytest

from secureclaw.gui import GuiHandler, start_gui_server, _build_gui_html


@pytest.fixture(scope="module")
def gui_server():
    """Start a GUI server on a random port for the test suite."""
    server = HTTPServer(("127.0.0.1", 0), GuiHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Give the server a moment to start
    time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


class TestStartGuiServer:
    """Tests for the start_gui_server entry point."""

    def test_start_gui_server_is_callable(self):
        """start_gui_server exists and is callable."""
        assert callable(start_gui_server)


class TestGuiHtml:
    """Tests for the inline GUI HTML."""

    def test_html_contains_sparkry_branding(self):
        html = _build_gui_html()
        assert "SecureClaw" in html

    def test_html_contains_folder_input(self):
        html = _build_gui_html()
        assert 'id="scan-path"' in html

    def test_html_contains_scan_button(self):
        html = _build_gui_html()
        assert 'id="scan-btn"' in html

    def test_html_is_self_contained(self):
        """No external CSS or JS links."""
        html = _build_gui_html()
        # Should not link to external stylesheets or scripts
        assert "https://" not in html
        assert "http://" not in html

    def test_html_has_dark_theme(self):
        html = _build_gui_html()
        assert "#1b1b1b" in html

    def test_html_has_accent_color(self):
        html = _build_gui_html()
        assert "#E8751A" in html.upper() or "#e8751a" in html.lower()


class TestGuiGetRoot:
    """Tests for GET / serving the HTML app."""

    def test_get_root_returns_html(self, gui_server):
        resp = urllib.request.urlopen(f"{gui_server}/")
        assert resp.status == 200
        content_type = resp.getheader("Content-Type")
        assert "text/html" in content_type
        body = resp.read().decode("utf-8")
        assert "SecureClaw" in body

    def test_get_root_contains_scan_form(self, gui_server):
        resp = urllib.request.urlopen(f"{gui_server}/")
        body = resp.read().decode("utf-8")
        assert 'id="scan-path"' in body
        assert 'id="scan-btn"' in body


class TestApiScan:
    """Tests for POST /api/scan."""

    def test_scan_valid_directory(self, gui_server, tmp_path):
        """Scanning a valid directory returns status ok and html report."""
        # Create a simple file to scan
        test_file = tmp_path / "hello.txt"
        test_file.write_text("This is a safe file.")

        payload = json.dumps({"path": str(tmp_path)}).encode("utf-8")
        req = urllib.request.Request(
            f"{gui_server}/api/scan",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req)
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["status"] == "ok"
        assert "html" in data
        assert "summary" in data
        assert isinstance(data["summary"], dict)

    def test_scan_nonexistent_path(self, gui_server):
        """Scanning a non-existent path returns an error."""
        payload = json.dumps({"path": "/nonexistent/path/xyz123"}).encode("utf-8")
        req = urllib.request.Request(
            f"{gui_server}/api/scan",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            pytest.fail("Expected HTTP error")
        except urllib.error.HTTPError as e:
            assert e.code == 400
            data = json.loads(e.read().decode("utf-8"))
            assert data["status"] == "error"
            assert "message" in data

    def test_scan_file_not_directory(self, gui_server, tmp_path):
        """Scanning a file (not a directory) returns an error."""
        test_file = tmp_path / "single.txt"
        test_file.write_text("just a file")

        payload = json.dumps({"path": str(test_file)}).encode("utf-8")
        req = urllib.request.Request(
            f"{gui_server}/api/scan",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            pytest.fail("Expected HTTP error")
        except urllib.error.HTTPError as e:
            assert e.code == 400
            data = json.loads(e.read().decode("utf-8"))
            assert data["status"] == "error"

    def test_scan_missing_path_field(self, gui_server):
        """POST with missing 'path' field returns an error."""
        payload = json.dumps({"folder": "/tmp"}).encode("utf-8")
        req = urllib.request.Request(
            f"{gui_server}/api/scan",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            pytest.fail("Expected HTTP error")
        except urllib.error.HTTPError as e:
            assert e.code == 400

    def test_scan_invalid_json(self, gui_server):
        """POST with invalid JSON returns an error."""
        req = urllib.request.Request(
            f"{gui_server}/api/scan",
            data=b"not json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            pytest.fail("Expected HTTP error")
        except urllib.error.HTTPError as e:
            assert e.code == 400

    def test_scan_internal_error_returns_500(self, gui_server, tmp_path):
        """Scanner crash returns a structured JSON error, not a broken connection."""
        from unittest.mock import patch

        payload = json.dumps({"path": str(tmp_path)}).encode("utf-8")
        req = urllib.request.Request(
            f"{gui_server}/api/scan",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with patch(
            "secureclaw.gui._run_scan",
            side_effect=RuntimeError("disk on fire"),
        ):
            try:
                urllib.request.urlopen(req)
                pytest.fail("Expected HTTP error")
            except urllib.error.HTTPError as e:
                assert e.code == 500
                data = json.loads(e.read().decode("utf-8"))
                assert data["status"] == "error"
                assert "message" in data

    def test_scan_result_html_is_report(self, gui_server, tmp_path):
        """The returned HTML should be a valid report."""
        test_file = tmp_path / "test.md"
        test_file.write_text("Some markdown content.")

        payload = json.dumps({"path": str(tmp_path)}).encode("utf-8")
        req = urllib.request.Request(
            f"{gui_server}/api/scan",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req)
        data = json.loads(resp.read().decode("utf-8"))
        # The HTML report should contain SecureClaw branding
        assert "SecureClaw" in data["html"]


class TestGuiNotFound:
    """Tests for unknown routes."""

    def test_unknown_get_returns_404(self, gui_server):
        try:
            urllib.request.urlopen(f"{gui_server}/unknown/path")
            pytest.fail("Expected HTTP error")
        except urllib.error.HTTPError as e:
            assert e.code == 404

    def test_post_to_unknown_endpoint_returns_404(self, gui_server):
        req = urllib.request.Request(
            f"{gui_server}/api/unknown",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            pytest.fail("Expected HTTP error")
        except urllib.error.HTTPError as e:
            assert e.code == 404
