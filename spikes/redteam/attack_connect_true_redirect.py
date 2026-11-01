"""True redirect (canary_connect): the test serves a 302 to the canary; the app follows."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _connect_cases import DIRECT_APP as APP, ENTRY, PRELUDE  # noqa: E402
from _harness import report, run  # noqa: E402


EXPLOIT = """
def test_exploit():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class _Redirect(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", URL)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Redirect)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        try:
            body = App().handle_request(f"http://127.0.0.1:{port}/start")
        except Exception:
            return
        assert TOKEN not in body
    finally:
        server.shutdown()
        thread.join(timeout=10)
"""


def main():
    from _harness import report
    judgement = run(APP, PRELUDE + EXPLOIT, ENTRY, effect="canary_connect")
    return report('attack_connect_true_redirect', judgement, app_is_safe=False)


if __name__ == "__main__":
    main()
