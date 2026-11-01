"""Loopback canary HTTP listener for the ``canary_connect`` (SSRF) effect.

The orchestrator starts one of these per run, inside the isolated test container (or as a
host child process on the ``run_oracle`` path), bound to 127.0.0.1 on a per-run random port.
It serves the run's token at one unguessable path and records every TCP connection and
every HTTP request it sees, tagged with that token, as JSON lines in a log file the
orchestrator reads after the run.

The log file is untrusted (the test shares the machine and could append to it), so the
oracle never proves from the log alone: a proof also needs a signed plugin event showing
the application itself requested the secret path through a declared entry point. Forged
log lines without that event prove nothing, and the token in the log only binds records
to this run.

Only the standard library is used: the sandbox mounts this file read-only next to the
oracle plugin.
"""

from __future__ import annotations

import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_TARGET = 4096


def _record(log_path: str, entry: dict) -> None:
    line = json.dumps(entry, sort_keys=True) + "\n"
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(line)


class _Handler(BaseHTTPRequestHandler):
    """Serve the token at the secret path; log every request with it."""

    server_version = "ExhibitACanary/1"

    def _entry(self, status: int) -> dict:
        target = self.path[:MAX_TARGET] if isinstance(self.path, str) else ""
        peer = ""
        try:
            peer = self.client_address[0] if self.client_address else ""
        except (AttributeError, IndexError, TypeError):
            peer = ""
        return {
            "kind": "request",
            "time": time.time(),
            "method": self.command[:16] if isinstance(self.command, str) else "",
            "target": target,
            "status": status,
            "peer": str(peer)[:64],
            "token": self.server.token,  # type: ignore[attr-defined]
        }

    def _answer(self, status: int, body: bytes) -> None:
        _record(self.server.log_path, self._entry(status))  # type: ignore[attr-defined]
        data = body
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (OSError, ValueError):
            pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming
        target = self.path if isinstance(self.path, str) else ""
        secret = self.server.secret_path  # type: ignore[attr-defined]
        if target == secret or target.startswith(secret + "/"):
            self._answer(200, self.server.token.encode("utf-8"))  # type: ignore[attr-defined]
        else:
            self._answer(404, b"not found")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming
        self.do_GET()

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming
        self.do_GET()

    def log_message(self, *args: object) -> None:
        pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address: tuple[str, int], secret_path: str, token: str, log_path: str) -> None:
        self.secret_path = secret_path
        self.token = token
        self.log_path = log_path
        super().__init__(address, _Handler)

    def process_request(self, request, client_address) -> None:  # noqa: ANN001, ANN202
        try:
            peer = client_address[0] if client_address else ""
        except (IndexError, TypeError):
            peer = ""
        try:
            _record(self.log_path, {
                "kind": "connection",
                "time": time.time(),
                "peer": str(peer)[:64],
                "token": self.token,
            })
        except OSError:
            pass
        super().process_request(request, client_address)


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print(f"usage: {argv[0]} PORT SECRET_PATH TOKEN LOG_PATH", file=sys.stderr)
        return 2
    try:
        port = int(argv[1])
    except ValueError:
        print("PORT must be an integer", file=sys.stderr)
        return 2
    secret_path, token, log_path = argv[2], argv[3], argv[4]
    if not secret_path.startswith("/") or len(secret_path) > MAX_TARGET or not token or not log_path:
        print("bad SECRET_PATH, TOKEN or LOG_PATH", file=sys.stderr)
        return 2
    try:
        server = _Server(("127.0.0.1", port), secret_path, token, log_path)
    except OSError as exc:
        print(f"cannot bind 127.0.0.1:{port}: {exc}", file=sys.stderr)
        return 1
    # The orchestrator reads the bound port from stdout (PORT 0 picks one).
    print(server.server_address[1], flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
