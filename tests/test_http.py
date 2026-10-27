import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from exhibit_a.models.http import post_json
from exhibit_a.models.errors import ProviderError


def run_test_server(handler_cls):
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_retry_on_500_then_200():
    class Handler(BaseHTTPRequestHandler):
        calls = 0

        def do_POST(self):
            type(self).calls += 1
            if type(self).calls == 1:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"server error")
                return
            # second call: succeed with JSON
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b"{}"
            data = {"echo": json.loads(body)}
            resp = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def log_message(self, format, *args):
            return

    server = run_test_server(Handler)
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/test"
    try:
        result = post_json(url, {"a": 1}, {}, timeout=5.0)
        assert "echo" in result
        assert result["echo"]["a"] == 1
        assert Handler.calls >= 2
    finally:
        server.shutdown()


def test_timeout_raises_provider_error():
    class SlowHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            # sleep longer than the client's overall timeout
            time.sleep(1.5)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def log_message(self, format, *args):
            return

    server = run_test_server(SlowHandler)
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/slow"
    try:
        with pytest.raises(ProviderError):
            # overall timeout shorter than handler sleep
            post_json(url, {}, {}, timeout=0.5)
    finally:
        server.shutdown()
