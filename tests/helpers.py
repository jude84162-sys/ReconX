"""Shared helpers for the ReconX test suite.

Everything here binds to 127.0.0.1 only — the tests never touch the internet.
"""

import http.server
import socket
import threading


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ReconXTest/1.0"
    sys_version = ""

    def do_GET(self):
        if self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "/page")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        body = (b"<!doctype html><html><head><title>Test &amp; Probe</title></head>"
                b"<body>hello</body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class LocalServer:
    """Loopback HTTP server on a random port, used as a live target."""

    def __init__(self):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    @property
    def port(self):
        return self.httpd.server_address[1]

    def url(self, path="/"):
        return f"http://127.0.0.1:{self.port}{path}"


def free_port():
    """A port that was just released, so connecting to it is refused."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
