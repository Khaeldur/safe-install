"""Simple web dashboard for safe-install."""
import http.server
import json
import os
import re
import socketserver
import subprocess
import sys
import urllib.parse

PORT = 8899
PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(PROJECT, "src")


def run_safe_install(args):
    env = {**os.environ, "PYTHONPATH": SRC, "PYTHONIOENCODING": "utf-8"}
    try:
        r = subprocess.run(
            [sys.executable, "-m", "safe_install"] + args,
            capture_output=True, text=True, timeout=120, env=env, cwd=PROJECT
        )
        clean = re.sub(r'\033\[[0-9;]*m', '', r.stdout + r.stderr)
        return clean
    except subprocess.TimeoutExpired:
        return "Command timed out (120s)"
    except Exception as e:
        return str(e)


def get_html():
    html_path = os.path.join(os.path.dirname(__file__), "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(get_html().encode('utf-8'))
        elif self.path.startswith('/api/run'):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            args_str = params.get('args', ['--help'])[0]
            args = args_str.split()
            output = run_safe_install(args)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(output.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


if __name__ == '__main__':
    print(f"safe-install dashboard running at http://localhost:{PORT}")
    server = ThreadedServer(('localhost', PORT), Handler)
    server.serve_forever()
