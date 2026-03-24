"""HTTP backend for the Safe Install Docker Desktop extension.

Serves the React frontend and exposes scan APIs.
Works standalone (python backend/main.py) for testing.
"""

import json
import os
import sys
import tempfile
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs

# Allow importing safe_install from the parent repo when running standalone
_here = os.path.dirname(os.path.abspath(__file__))
_repo_src = os.path.normpath(os.path.join(_here, "..", "..", "src"))
if os.path.isdir(_repo_src) and _repo_src not in sys.path:
    sys.path.insert(0, _repo_src)

from safe_install.api import audit_package, query_findings, log_finding, get_status
from safe_install.ecosystems.docker_eco import DockerEcosystem

CHANNEL = os.environ.get("SAFE_INSTALL_CHANNEL", "docker-extension")
PORT = int(os.environ.get("SAFE_INSTALL_PORT", "9080"))
UI_DIR = os.path.normpath(os.path.join(_here, "..", "ui", "build"))


def _json_response(handler, data, status=200):
    body = json.dumps(data, default=str).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()
    handler.wfile.write(body)


def _read_body(handler):
    length = int(handler.headers.get("Content-Length", 0))
    if length == 0:
        return b""
    return handler.rfile.read(length)


class ExtensionHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("directory", UI_DIR)
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/api/scan-image":
            self._handle_scan_image(qs)
        elif path == "/api/findings":
            self._handle_findings(qs)
        elif path == "/api/status":
            self._handle_status()
        elif path.startswith("/api/"):
            _json_response(self, {"error": "not found"}, 404)
        else:
            # Serve static frontend files
            if not os.path.isdir(UI_DIR):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>Safe Install</h1><p>Frontend not built. Run npm run build in ui/</p>")
                return
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/scan-dockerfile":
            self._handle_scan_dockerfile()
        else:
            _json_response(self, {"error": "not found"}, 404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # --- API handlers ---

    def _handle_scan_image(self, qs):
        image = qs.get("image", [None])[0]
        if not image:
            _json_response(self, {"error": "missing ?image= parameter"}, 400)
            return

        eco = DockerEcosystem()
        result = audit_package(image, ecosystem="docker")
        result["channel"] = CHANNEL

        log_finding({
            "package": image,
            "ecosystem": "docker",
            "channel": CHANNEL,
            "severity": result.get("severity", "CLEAN"),
            "findings_count": len(result.get("findings", [])),
            "typosquat": result.get("typosquat", {}),
        })

        _json_response(self, result)

    def _handle_scan_dockerfile(self):
        body = _read_body(self)
        if not body:
            _json_response(self, {"error": "empty body"}, 400)
            return

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {"content": body.decode("utf-8", errors="replace")}

        content = payload.get("content", "")
        if not content:
            _json_response(self, {"error": "no Dockerfile content provided"}, 400)
            return

        eco = DockerEcosystem()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".Dockerfile", delete=False) as tmp:
            tmp.write(content)
            tmp.flush()
            tmp_path = tmp.name

        try:
            findings = eco.scan_dockerfile(tmp_path)
        finally:
            os.unlink(tmp_path)

        severity = "CLEAN"
        if findings:
            severity = "HIGH" if len(findings) > 2 else "MEDIUM"

        result = {
            "findings": findings,
            "severity": severity,
            "total": len(findings),
            "channel": CHANNEL,
        }

        log_finding({
            "package": "Dockerfile",
            "ecosystem": "docker",
            "channel": CHANNEL,
            "severity": severity,
            "findings_count": len(findings),
        })

        _json_response(self, result)

    def _handle_findings(self, qs):
        channel = qs.get("channel", [CHANNEL])[0]
        limit = int(qs.get("limit", ["100"])[0])
        results = query_findings(channel=channel)
        _json_response(self, {"findings": results[-limit:], "total": len(results)})

    def _handle_status(self):
        status = get_status()
        status["channel"] = CHANNEL
        _json_response(self, status)

    def log_message(self, format, *args):
        sys.stderr.write(f"[safe-install] {format % args}\n")


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def main():
    server = ThreadedHTTPServer(("0.0.0.0", PORT), ExtensionHandler)
    print(f"[safe-install] Docker extension backend listening on port {PORT}")
    if os.path.isdir(UI_DIR):
        print(f"[safe-install] Serving UI from {UI_DIR}")
    else:
        print(f"[safe-install] UI not built yet ({UI_DIR})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[safe-install] Shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
