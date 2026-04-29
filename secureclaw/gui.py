"""Browser-based GUI for SecureClaw.

Launches a local HTTP server on 127.0.0.1 with a single-page app
that lets users pick a folder, run a scan, and view the simple-mode
HTML report inline. Zero external dependencies (stdlib only).
"""

from __future__ import annotations

import html as html_mod
import json
import logging
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict

from secureclaw import __version__
from secureclaw.core.confidence import score_findings
from secureclaw.core.models import (
    ScanResult,
    Severity,
)
from secureclaw.core.patterns import PatternEngine, load_default_patterns
from secureclaw.core.scanner import Scanner
from secureclaw.posture.analyzer import run_posture_analysis
from secureclaw.reporters.html_report import format_html_report

logger = logging.getLogger(__name__)


def _build_gui_html() -> str:
    """Return the self-contained single-page HTML app.

    All CSS and JS are inlined. No external resources are loaded.
    User input is escaped via a JS helper that uses textContent for
    safe text rendering. The scan report is rendered inside an iframe
    using srcdoc (trusted server-generated HTML from format_html_report).
    """
    version = html_mod.escape(__version__)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>SecureClaw Scanner</title>\n"
        "<style>\n"
        "*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }\n"
        "body {\n"
        "  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,\n"
        "    Helvetica, Arial, sans-serif;\n"
        "  background: #1b1b1b;\n"
        "  color: #e0e0e0;\n"
        "  min-height: 100vh;\n"
        "  display: flex;\n"
        "  flex-direction: column;\n"
        "}\n"
        "header {\n"
        "  background: #252525;\n"
        "  border-bottom: 3px solid #E8751A;\n"
        "  padding: 1rem 2rem;\n"
        "  display: flex;\n"
        "  align-items: center;\n"
        "  gap: 1rem;\n"
        "}\n"
        "header .logo {\n"
        "  font-size: 1.5rem;\n"
        "  font-weight: 700;\n"
        "  color: #E8751A;\n"
        "  letter-spacing: -0.02em;\n"
        "}\n"
        "header .logo span {\n"
        "  color: #e0e0e0;\n"
        "  font-weight: 400;\n"
        "}\n"
        "header .version {\n"
        "  font-size: 0.85rem;\n"
        "  color: #888;\n"
        "}\n"
        "main {\n"
        "  flex: 1;\n"
        "  max-width: 900px;\n"
        "  width: 100%;\n"
        "  margin: 2rem auto;\n"
        "  padding: 0 1.5rem;\n"
        "}\n"
        ".scan-form {\n"
        "  display: flex;\n"
        "  gap: 0.75rem;\n"
        "  margin-bottom: 1.5rem;\n"
        "}\n"
        ".scan-form input {\n"
        "  flex: 1;\n"
        "  padding: 0.75rem 1rem;\n"
        "  border: 1px solid #444;\n"
        "  border-radius: 6px;\n"
        "  background: #2a2a2a;\n"
        "  color: #e0e0e0;\n"
        "  font-size: 1rem;\n"
        "  outline: none;\n"
        "  transition: border-color 0.2s;\n"
        "}\n"
        ".scan-form input:focus {\n"
        "  border-color: #E8751A;\n"
        "}\n"
        ".scan-form button {\n"
        "  padding: 0.75rem 2rem;\n"
        "  background: #E8751A;\n"
        "  color: #fff;\n"
        "  border: none;\n"
        "  border-radius: 6px;\n"
        "  font-size: 1rem;\n"
        "  font-weight: 600;\n"
        "  cursor: pointer;\n"
        "  transition: background 0.2s;\n"
        "  white-space: nowrap;\n"
        "}\n"
        ".scan-form button:hover {\n"
        "  background: #d0650f;\n"
        "}\n"
        ".scan-form button:disabled {\n"
        "  background: #555;\n"
        "  cursor: not-allowed;\n"
        "}\n"
        "#status-area {\n"
        "  margin-bottom: 1.5rem;\n"
        "  min-height: 2rem;\n"
        "}\n"
        ".scanning {\n"
        "  display: flex;\n"
        "  align-items: center;\n"
        "  gap: 0.75rem;\n"
        "  color: #E8751A;\n"
        "  font-weight: 500;\n"
        "}\n"
        ".spinner {\n"
        "  width: 20px;\n"
        "  height: 20px;\n"
        "  border: 3px solid #444;\n"
        "  border-top-color: #E8751A;\n"
        "  border-radius: 50%;\n"
        "  animation: spin 0.8s linear infinite;\n"
        "}\n"
        "@keyframes spin {\n"
        "  to { transform: rotate(360deg); }\n"
        "}\n"
        ".error-msg {\n"
        "  background: #3a1515;\n"
        "  border: 1px solid #ff4444;\n"
        "  border-radius: 6px;\n"
        "  padding: 1rem;\n"
        "  color: #ff8888;\n"
        "}\n"
        "#results-area {\n"
        "  border-radius: 8px;\n"
        "  overflow: hidden;\n"
        "}\n"
        "#results-area iframe {\n"
        "  width: 100%;\n"
        "  border: none;\n"
        "  border-radius: 8px;\n"
        "  background: #fff;\n"
        "  min-height: 600px;\n"
        "}\n"
        "footer {\n"
        "  text-align: center;\n"
        "  padding: 1rem;\n"
        "  color: #666;\n"
        "  font-size: 0.85rem;\n"
        "}\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "<header>\n"
        '  <div class="logo">SecureClaw <span>Scanner</span></div>\n'
        '  <div class="version">v' + version + "</div>\n"
        "</header>\n"
        "<main>\n"
        '  <div class="scan-form">\n'
        '    <input type="text" id="scan-path"\n'
        '      placeholder="Enter folder path to scan (e.g. /Users/you/project)"\n'
        '      autocomplete="off" spellcheck="false">\n'
        '    <button type="button" id="scan-btn">Scan</button>\n'
        "  </div>\n"
        '  <div id="status-area"></div>\n'
        '  <div id="results-area"></div>\n'
        "</main>\n"
        "<footer>\n"
        "  SecureClaw v" + version + " &middot; Built by Sparkry AI"
        " &middot; 127.0.0.1 only\n"
        "</footer>\n"
        "<script>\n"
        "/* Safe text escaper using textContent */\n"
        "function escapeHtml(s) {\n"
        '  var d = document.createElement("div");\n'
        "  d.appendChild(document.createTextNode(s));\n"
        "  return d.innerHTML;\n"  # noqa: E501 -- returns entity-escaped string
        "}\n"
        "function showError(msg) {\n"
        '  var el = document.createElement("div");\n'
        '  el.className = "error-msg";\n'
        "  el.textContent = msg;\n"
        '  document.getElementById("status-area").textContent = "";\n'
        '  document.getElementById("status-area").appendChild(el);\n'
        "}\n"
        "function showSpinner() {\n"
        '  var area = document.getElementById("status-area");\n'
        '  area.textContent = "";\n'
        '  var wrap = document.createElement("div");\n'
        '  wrap.className = "scanning";\n'
        '  var sp = document.createElement("div");\n'
        '  sp.className = "spinner";\n'
        "  wrap.appendChild(sp);\n"
        '  wrap.appendChild(document.createTextNode("Scanning\\u2026"));\n'
        "  area.appendChild(wrap);\n"
        "}\n"
        "function runScan() {\n"
        '  var pathInput = document.getElementById("scan-path");\n'
        '  var btn = document.getElementById("scan-btn");\n'
        '  var resultsArea = document.getElementById("results-area");\n'
        "  var scanPath = pathInput.value.trim();\n"
        "  if (!scanPath) {\n"
        '    showError("Please enter a folder path.");\n'
        "    return;\n"
        "  }\n"
        "  btn.disabled = true;\n"
        '  btn.textContent = "Scanning...";\n'
        "  showSpinner();\n"
        '  resultsArea.textContent = "";\n'
        '  fetch("/api/scan", {\n'
        '    method: "POST",\n'
        '    headers: { "Content-Type": "application/json" },\n'
        "    body: JSON.stringify({ path: scanPath })\n"
        "  })\n"
        "  .then(function(resp) {\n"
        "    return resp.json().then(function(data) {\n"
        "      return { ok: resp.ok, data: data };\n"
        "    });\n"
        "  })\n"
        "  .then(function(result) {\n"
        "    btn.disabled = false;\n"
        '    btn.textContent = "Scan";\n'
        "    if (!result.ok) {\n"
        '      showError(result.data.message || "Scan failed.");\n'
        "      return;\n"
        "    }\n"
        '    document.getElementById("status-area").textContent = "";\n'
        '    var iframe = document.createElement("iframe");\n'
        "    iframe.srcdoc = result.data.html;\n"
        '    iframe.setAttribute("sandbox", "allow-same-origin allow-scripts");\n'
        '    resultsArea.textContent = "";\n'
        "    resultsArea.appendChild(iframe);\n"
        "    iframe.onload = function() {\n"
        "      try {\n"
        "        iframe.style.height ="
        ' iframe.contentDocument.body.scrollHeight + 40 + "px";\n'
        "      } catch(e) {}\n"
        "    };\n"
        "  })\n"
        "  .catch(function(err) {\n"
        "    btn.disabled = false;\n"
        '    btn.textContent = "Scan";\n'
        '    showError("Network error: " + String(err));\n'
        "  });\n"
        "}\n"
        'document.getElementById("scan-btn").addEventListener("click", runScan);\n'
        'document.getElementById("scan-path").addEventListener("keydown",'
        " function(e) {\n"
        '  if (e.key === "Enter") runScan();\n'
        "});\n"
        "</script>\n"
        "</body>\n"
        "</html>"
    )


def _dedup_findings(findings: list) -> list:
    """Deduplicate findings by (file_path, line_number, pattern_id)."""
    seen: set = set()
    deduped: list = []
    for f in findings:
        key = f.dedup_key
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


def _run_scan(scan_path: str) -> Dict[str, Any]:
    """Run the scanner on the given path and return a result dict."""
    target = Path(scan_path).resolve()

    if not target.exists():
        return {
            "status": "error",
            "message": f"Path does not exist: {scan_path}",
        }

    if not target.is_dir():
        return {
            "status": "error",
            "message": f"Path is not a directory: {scan_path}",
        }

    # Load patterns and create scanner
    patterns = load_default_patterns()
    engine = PatternEngine(patterns)
    scanner = Scanner(engine=engine)

    # Run scan
    file_results, summary = scanner.scan_paths([target])

    # Collect findings
    all_findings: list = []
    for fr in file_results:
        all_findings.extend(fr.findings)

    deduped = _dedup_findings(all_findings)
    scored = score_findings(deduped)

    # Update summary counts
    summary.total_findings = len(scored)
    summary.critical_count = sum(1 for f in scored if f.severity == Severity.CRITICAL)
    summary.high_count = sum(1 for f in scored if f.severity == Severity.HIGH)
    summary.advisory_count = sum(1 for f in scored if f.severity == Severity.ADVISORY)

    # Posture checks
    posture_checks = run_posture_analysis(target)

    # Build ScanResult
    result = ScanResult(
        findings=scored,
        file_results=file_results,
        posture_checks=posture_checks,
        summary=summary,
        tool_version=__version__,
    )

    # Generate HTML report (simple mode for GUI users)
    report_html = format_html_report(result, mode="simple")

    return {
        "status": "ok",
        "html": report_html,
        "summary": {
            "files_scanned": summary.total_files_scanned,
            "files_skipped": summary.total_files_skipped,
            "total_findings": summary.total_findings,
            "critical": summary.critical_count,
            "high": summary.high_count,
            "advisory": summary.advisory_count,
        },
    }


class GuiHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the SecureClaw GUI."""

    def do_GET(self) -> None:
        """Handle GET requests."""
        if self.path == "/" or self.path == "":
            html_content = _build_gui_html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_content)))
            self.end_headers()
            self.wfile.write(html_content)
        else:
            self.send_error(404, "Not Found")

    def do_POST(self) -> None:
        """Handle POST requests."""
        if self.path == "/api/scan":
            self._handle_scan()
        else:
            self.send_error(404, "Not Found")

    def _handle_scan(self) -> None:
        """Process a scan request."""
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)

        try:
            body = json.loads(raw_body)
        except (json.JSONDecodeError, ValueError):
            self._send_json(400, {"status": "error", "message": "Invalid JSON."})
            return

        scan_path = body.get("path")
        if not scan_path or not isinstance(scan_path, str):
            self._send_json(
                400,
                {"status": "error", "message": "Missing required field: path"},
            )
            return

        try:
            result = _run_scan(scan_path)
        except Exception:
            logger.exception("Scan failed for path: %s", scan_path)
            self._send_json(
                500,
                {"status": "error", "message": "Internal scan error. Check server logs."},
            )
            return

        if result["status"] == "error":
            self._send_json(400, result)
        else:
            self._send_json(200, result)

    def _send_json(self, code: int, data: Dict[str, Any]) -> None:
        """Send a JSON response."""
        payload = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        """Route HTTP logs through Python logging instead of stderr."""
        logger.debug(format, *args)


def start_gui_server(port: int = 0) -> None:
    """Launch the GUI server and open the browser.

    Binds to 127.0.0.1 only (localhost) for security.
    Port 0 means the OS picks a free port automatically.
    """
    server = HTTPServer(("127.0.0.1", port), GuiHandler)
    actual_port = server.server_address[1]
    url = f"http://127.0.0.1:{actual_port}"

    print(f"\n  SecureClaw GUI running at {url}")
    print("  Press Ctrl+C to stop.\n")

    webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down SecureClaw GUI.")
    finally:
        server.server_close()
