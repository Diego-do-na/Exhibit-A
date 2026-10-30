"""Dashboard HTTP server: static UI plus a read-only JSON/SSE API on 127.0.0.1.

Security posture (threat model in docs/design/dashboard.md):

- Binds 127.0.0.1 only; there is no host option.
- A random per-launch bootstrap token is printed in the terminal. Opening
  ``/auth?token=...`` once sets an HttpOnly, SameSite=Strict session cookie
  (a different random value) and consumes the token. Every ``/api/`` request
  needs that cookie; static files carry no data and need none.
- Every request must carry ``Host: 127.0.0.1:<port>`` or ``localhost:<port>``
  exactly, which defeats DNS rebinding. Cross-site fetch metadata and foreign
  ``Origin`` headers are refused on the API.
- Responses carry a strict CSP (``default-src 'self'``), ``nosniff``,
  ``no-referrer`` and frame denial. No CORS headers are ever sent.
- GET only. No endpoint writes files. Request lines are never logged with
  their query string, so the token never reaches a log.

Endpoints (GET):

- ``/``, ``/app.js``, ``/style.css``: the UI in ``web/dashboard/``.
- ``/auth?token=``: one-time bootstrap; redirects to ``/``.
- ``/api/info``: source label and caps.
- ``/api/runs?page=&per_page=``: runs list rows, newest first.
- ``/api/runs/<id>``: run detail (timeline stages, proven evidence, discarded).
- ``/api/runs/<id>/events?from=&limit=``: bounded event views, in ledger order.
- ``/api/runs/<id>/replay?speed=&from=``: Server-Sent Events replay of a
  finished ledger, paced by ``exhibit_a.live.replay.Replayer``.
- ``/api/trends?limit=``: verdict counts of the most recent runs, oldest first.
"""

from __future__ import annotations

import argparse
import hmac
import json
import re
import secrets
import sys
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from ..live.replay import Replayer, format_done, parse_speed, select_events
from .model import build_trends, event_view, run_detail, run_row
from .sources import RUN_ID_RE, RunSource, SourceError, parse_source

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
COOKIE_NAME = "exhibit_a_dashboard"

#: Static files the server may send, mapped to their content types.
STATIC_FILES = {
    "index.html": "text/html; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
}

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}

MAX_PATH = 2048
MAX_PER_PAGE = 100
DEFAULT_PER_PAGE = 20
MAX_EVENTS_PAGE = 500
DEFAULT_EVENTS_PAGE = 200
MAX_TREND_RUNS = 200
DEFAULT_TREND_RUNS = 50
#: Fastest replay accepted; faster requests are clamped.
MAX_SPEED = 64.0

_RUN_ROUTE = re.compile(r"^/api/runs/([^/]+)(/events|/replay)?$")


def default_web_dir() -> Path:
    """``web/dashboard`` of the source checkout, else of the current directory."""
    checkout = Path(__file__).resolve().parents[3] / "web" / "dashboard"
    return checkout if checkout.is_dir() else Path("web") / "dashboard"


@dataclass
class DashboardState:
    """Per-launch secrets and configuration shared by every request."""

    source: RunSource
    web_dir: Path
    port: int
    token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    session: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    token_used: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def allowed_hosts(self) -> frozenset[str]:
        return frozenset({f"127.0.0.1:{self.port}", f"localhost:{self.port}"})

    def bootstrap_url(self) -> str:
        return f"http://{HOST}:{self.port}/auth?token={self.token}"

    def consume(self, presented: str) -> bool:
        """Accept the bootstrap token once, in constant time."""
        with self.lock:
            if self.token_used or not hmac.compare_digest(presented.encode(), self.token.encode()):
                return False
            self.token_used = True
            return True

    def valid_session(self, presented: str) -> bool:
        return bool(presented) and hmac.compare_digest(presented.encode(), self.session.encode())


class _BadRequest(ValueError):
    pass


def _int_param(query: dict[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = query.get(name, "")
    if raw == "":
        return default
    if not raw.isdigit() or len(raw) > 9:
        raise _BadRequest(f"invalid {name}: expected an integer")
    value = int(raw)
    if value < low:
        raise _BadRequest(f"invalid {name}: must be at least {low}")
    return min(value, high)


def _cookie(header: str | None, name: str) -> str:
    if not header or len(header) > 8192:
        return ""
    for part in header.split(";"):
        key, _, value = part.strip().partition("=")
        if key == name:
            return value
    return ""


def _sorted_refs(source: RunSource) -> list[Any]:
    refs = source.list_runs()
    return sorted(refs, key=lambda r: (r.started_at, r.run_id), reverse=True)


def make_handler(state: DashboardState) -> type[BaseHTTPRequestHandler]:
    """Build a request handler bound to one launch's state."""

    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "ExhibitADashboard/0.1"
        sys_version = ""

        # -- logging: path only, never the query string (it can hold the token) --

        def log_request(self, code: Any = "-", size: Any = "-") -> None:
            if getattr(self.server, "verbose", False):
                path = urlsplit(getattr(self, "path", "")).path[:200]
                sys.stderr.write(f"dashboard: {getattr(self, 'command', '?')} {path} {code}\n")

        def log_error(self, *args: Any) -> None:
            pass

        def log_message(self, *args: Any) -> None:
            pass

        # -- responses --------------------------------------------------------

        def _headers(self, status: int, content_type: str, length: int | None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            if length is not None:
                self.send_header("Content-Length", str(length))
            for key, value in SECURITY_HEADERS.items():
                self.send_header(key, value)

        def _send(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
            self._headers(status, content_type, len(body))
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, obj: Any, status: int = 200) -> None:
            body = json.dumps(obj, ensure_ascii=True, allow_nan=False).encode("ascii")
            self._send(status, body, "application/json; charset=utf-8")

        def _error(self, status: int, message: str) -> None:
            self._json({"error": message}, status)

        # -- request gates ----------------------------------------------------

        def _host_ok(self) -> bool:
            host = self.headers.get("Host", "")
            return host in state.allowed_hosts

        def _cross_site(self) -> bool:
            site = self.headers.get("Sec-Fetch-Site")
            if site is not None and site not in ("same-origin", "none"):
                return True
            origin = self.headers.get("Origin")
            if origin is not None and origin not in {f"http://{h}" for h in state.allowed_hosts}:
                return True
            return False

        def _authed(self) -> bool:
            return state.valid_session(_cookie(self.headers.get("Cookie"), COOKIE_NAME))

        def _query(self) -> dict[str, str]:
            try:
                raw = parse_qs(urlsplit(self.path).query, max_num_fields=20)
            except ValueError as exc:
                raise _BadRequest("too many query parameters") from exc
            return {key: values[0] for key, values in raw.items() if values}

        # -- routing ----------------------------------------------------------

        def _refuse_method(self) -> None:
            if not self._host_ok():
                self._error(421, "unexpected Host header")
                return
            self._send(405, b'{"error": "read-only: GET only"}', "application/json; charset=utf-8", {"Allow": "GET"})

        do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = do_TRACE = do_CONNECT = _refuse_method  # noqa: N815

        def do_GET(self) -> None:  # noqa: N802 (http.server naming)
            if len(self.path) > MAX_PATH:
                self._error(414, "request target too long")
                return
            if not self._host_ok():
                self._error(421, "unexpected Host header")
                return
            route = urlsplit(self.path).path
            try:
                if route == "/auth":
                    self._auth()
                elif route in ("/", "/index.html"):
                    self._static("index.html")
                elif route.lstrip("/") in STATIC_FILES:
                    self._static(route.lstrip("/"))
                elif route.startswith("/api/"):
                    self._api(route)
                else:
                    self._error(404, "not found")
            except _BadRequest as exc:
                self._error(400, str(exc))
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _auth(self) -> None:
            if self._cross_site():
                self._error(403, "cross-site request refused")
                return
            token = self._query().get("token", "")
            if self._authed() or (token and state.consume(token)):
                cookie = f"{COOKIE_NAME}={state.session}; HttpOnly; SameSite=Strict; Path=/"
                self._send(303, b"", "text/plain; charset=utf-8", {"Location": "/", "Set-Cookie": cookie})
                return
            self._send(
                403,
                b"This bootstrap link is invalid or was already used. "
                b"Restart the dashboard to get a new one.\n",
                "text/plain; charset=utf-8",
            )

        def _static(self, name: str) -> None:
            root = state.web_dir.resolve()
            target = (root / name).resolve()
            if target != root / name or not target.is_file():
                self._error(404, "not found")
                return
            self._send(200, target.read_bytes(), STATIC_FILES[name])

        def _api(self, route: str) -> None:
            if self._cross_site():
                self._error(403, "cross-site request refused")
                return
            if not self._authed():
                self._error(401, "open the bootstrap link printed in the terminal")
                return
            query = self._query()
            if route == "/api/info":
                self._json({"source": state.source.label, "stages_note": "nothing could be proven is not safe"})
            elif route == "/api/runs":
                self._runs(query)
            elif route == "/api/trends":
                self._trends(query)
            else:
                match = _RUN_ROUTE.match(route)
                if match is None or not RUN_ID_RE.match(match.group(1)):
                    self._error(404, "not found")
                    return
                self._run(match.group(1), match.group(2) or "", query)

        # -- API handlers -------------------------------------------------------

        def _load(self, run_id: str) -> Any:
            try:
                return state.source.load_run(run_id)
            except KeyError:
                return None

        def _runs(self, query: dict[str, str]) -> None:
            page = _int_param(query, "page", 1, 1, 1_000_000)
            per_page = _int_param(query, "per_page", DEFAULT_PER_PAGE, 1, MAX_PER_PAGE)
            try:
                refs = _sorted_refs(state.source)
            except SourceError as exc:
                self._error(502, str(exc))
                return
            total = len(refs)
            window = refs[(page - 1) * per_page : page * per_page]
            rows = []
            for ref in window:
                data = self._load(ref.run_id)
                if data is not None:
                    rows.append(run_row(data))
            self._json(
                {
                    "source": state.source.label,
                    "runs": rows,
                    "page": page,
                    "per_page": per_page,
                    "total": total,
                    "pages": max(1, -(-total // per_page)),
                }
            )

        def _trends(self, query: dict[str, str]) -> None:
            limit = _int_param(query, "limit", DEFAULT_TREND_RUNS, 1, MAX_TREND_RUNS)
            try:
                refs = _sorted_refs(state.source)[:limit]
            except SourceError as exc:
                self._error(502, str(exc))
                return
            rows = [run_row(d) for d in (self._load(r.run_id) for r in refs) if d is not None]
            self._json({"points": build_trends(rows), "limit": limit, "total": len(refs)})

        def _run(self, run_id: str, tail: str, query: dict[str, str]) -> None:
            data = self._load(run_id)
            if data is None:
                self._error(404, "unknown run")
                return
            if tail == "":
                self._json(run_detail(data))
                return
            if data.error:
                self._error(422, f"run could not be read: {data.error}")
                return
            if tail == "/events":
                start = _int_param(query, "from", 0, 0, 10**9)
                limit = _int_param(query, "limit", DEFAULT_EVENTS_PAGE, 1, MAX_EVENTS_PAGE)
                window = data.events[start : start + limit]
                self._json(
                    {
                        "run_id": run_id,
                        "from": start,
                        "events": [event_view(start + i, e) for i, e in enumerate(window)],
                        "count": len(window),
                        "total": len(data.events),
                    }
                )
            else:
                self._replay(data.events, query)

        def _replay(self, events: Sequence[Any], query: dict[str, str]) -> None:
            try:
                speed = min(parse_speed(query.get("speed")), MAX_SPEED)
            except ValueError as exc:
                raise _BadRequest(str(exc)) from exc
            start = _int_param(query, "from", 0, 0, 10**9)
            player = Replayer(events=select_events(events, None, skip=start), speed=speed)
            self._headers(200, "text/event-stream; charset=utf-8", None)
            # Close-delimited stream, as in live/server.py: no keep-alive.
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b": exhibit-a dashboard replay\n\n")
            self.wfile.flush()
            for index, (event, delay) in enumerate(player.iter_with_delays()):
                if delay:
                    time.sleep(delay)
                view = event_view(start + index, event)
                frame = f"id: {start + index}\nevent: step\ndata: {json.dumps(view, ensure_ascii=True)}\n\n"
                self.wfile.write(frame.encode("ascii"))
                self.wfile.flush()
            self.wfile.write(format_done(len(player.events)).encode("ascii"))
            self.wfile.flush()

    return DashboardHandler


class DashboardServer(ThreadingHTTPServer):
    """Threaded loopback server; daemon threads so tests shut down cleanly."""

    daemon_threads = True
    allow_reuse_address = False
    verbose = False
    state: DashboardState


def create_server(
    source: RunSource,
    *,
    port: int = 0,
    web_dir: str | Path | None = None,
    verbose: bool = False,
) -> DashboardServer:
    """Bind 127.0.0.1 (port 0 picks a free one) and return the unstarted server."""
    state = DashboardState(source=source, web_dir=Path(web_dir) if web_dir else default_web_dir(), port=port)
    server = DashboardServer((HOST, port), make_handler(state))
    # The handler reads the port from ``state`` per request, so the Host check
    # matches the port actually bound (port 0 picks one).
    state.port = server.server_address[1]
    server.state = state
    server.verbose = verbose
    return server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m exhibit_a.dashboard",
        description="Exhibit A local dashboard: what was proven over time (127.0.0.1 only).",
    )
    parser.add_argument(
        "--source", required=True, help="local:<dir of run folders> or github:<owner/repo>"
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port on 127.0.0.1 (0 = any free port).")
    parser.add_argument(
        "--artifact", default="exhibit-a-ledger", help="GitHub artifact name holding ledger.jsonl/result.json."
    )
    parser.add_argument("--web", default=None, help="Directory holding the dashboard UI (default: web/dashboard).")
    parser.add_argument("--verbose", action="store_true", help="Log method, path and status (never queries).")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``python -m exhibit_a.dashboard``."""
    args = build_parser().parse_args(argv)
    if not 0 <= args.port <= 65535:
        print("dashboard: --port must be between 0 and 65535", file=sys.stderr)
        return 2
    try:
        source = parse_source(args.source, artifact=args.artifact)
    except SourceError as exc:
        print(f"dashboard: {exc}", file=sys.stderr)
        return 2
    try:
        server = create_server(source, port=args.port, web_dir=args.web, verbose=args.verbose)
    except OSError as exc:
        print(f"dashboard: cannot bind {HOST}:{args.port}: {exc}", file=sys.stderr)
        return 1
    print(f"dashboard: serving {source.label} on http://{HOST}:{server.state.port}/ (read-only, ^C to stop)")
    print("dashboard: open this one-time link in your browser (it sets a session cookie):")
    print(f"  {server.state.bootstrap_url()}")
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
