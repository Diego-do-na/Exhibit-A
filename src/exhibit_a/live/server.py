"""Small HTTP server: serves web/ and streams ledger events over SSE.

Endpoints (all GET):

- ``/`` serves ``web/index.html``; ``/app.js``, ``/style.css`` and
  ``/sample-ledger.jsonl`` serve the sibling static files.
- ``/api/runs`` lists run ids in first-appearance order.
- ``/api/events?run_id=&from=&limit=`` returns recorded events as JSON.
- ``/api/summary?run_id=`` returns the ``build_summary`` view-model as JSON.
- ``/events?run_id=&replay=&speed=&from=&follow=`` streams events as
  Server-Sent Events. Live mode tails the ledger file and pushes new
  appends; replay mode (``replay=1``) re-emits a finished run from the
  start with ``base_interval / speed`` seconds between events, sends a
  ``done`` frame, and closes. ``follow=0`` makes live mode close after
  the recorded events instead of waiting for new ones.

Run it with::

    python -m exhibit_a.live.server --ledger ledger.jsonl --port 8000

then open http://127.0.0.1:8000/ in a browser.
"""

from __future__ import annotations

import argparse
import json
import time
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from ..ledger import Ledger
from ..schemas import Event
from .replay import (
    DEFAULT_BASE_INTERVAL,
    Replayer,
    format_done,
    format_sse,
    parse_speed,
    select_events,
)
from .summary import build_summary

#: How often live mode re-reads the ledger while waiting for new appends.
POLL_INTERVAL = 0.25

#: Static files the server may send, mapped to their content types.
STATIC_FILES = {
    "index.html": "text/html; charset=utf-8",
    "app.js": "application/javascript; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
    "sample-ledger.jsonl": "application/x-ndjson; charset=utf-8",
}


def _parse_offset(raw: str | None, name: str) -> int:
    if raw is None or raw == "":
        return 0
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"invalid {name} {raw!r}: not an integer") from exc
    if value < 0:
        raise ValueError(f"invalid {name} {raw!r}: must be zero or more")
    return value


def _parse_flag(raw: str | None, name: str, default: bool) -> bool:
    if raw is None or raw == "":
        return default
    lowered = raw.lower()
    if lowered in ("1", "true", "yes"):
        return True
    if lowered in ("0", "false", "no"):
        return False
    raise ValueError(f"invalid {name} {raw!r}: expected 0/1, true/false")


def _read_filtered(ledger: Ledger, run_id: str | None) -> list[Event]:
    """Read the ledger and keep one run (None keeps every run), in order."""
    return select_events(ledger.read_all(), run_id)


def make_handler(
    ledger_path: Path, web_dir: Path
) -> type[BaseHTTPRequestHandler]:
    """Build a request handler bound to one ledger file and one web dir."""

    class LiveHandler(BaseHTTPRequestHandler):
        server_version = "ExhibitALive/0.1"

        def log_message(self, *args: Any) -> None:  # keep test output clean
            pass

        # -- small response helpers -------------------------------------

        def _cors(self) -> None:
            self.send_header("Access-Control-Allow-Origin", "*")

        def _send_json(self, obj: Any, status: int = 200) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self._cors()
            self.end_headers()
            self.wfile.write(body)

        def _send_static(self, name: str) -> None:
            content_type = STATIC_FILES[name]
            target = (web_dir / name).resolve()
            root = web_dir.resolve()
            if target != root / name or not target.is_file():
                self._send_json({"error": f"not found: /{name}"}, status=404)
                return
            body = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self._cors()
            self.end_headers()
            self.wfile.write(body)

        def _query(self) -> dict[str, str]:
            raw = parse_qs(urlsplit(self.path).query)
            return {key: values[0] for key, values in raw.items() if values}

        def _run_id(self, query: dict[str, str]) -> str | None:
            value = query.get("run_id", "")
            return value or None

        # -- routing ----------------------------------------------------

        def do_OPTIONS(self) -> None:  # noqa: N802 (http.server naming)
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802 (http.server naming)
            route = urlsplit(self.path).path
            if route in ("/", "/index.html"):
                self._send_static("index.html")
            elif route.lstrip("/") in STATIC_FILES:
                self._send_static(route.lstrip("/"))
            elif route == "/api/runs":
                self._api_runs()
            elif route == "/api/events":
                self._api_events()
            elif route == "/api/summary":
                self._api_summary()
            elif route == "/events":
                self._stream_events()
            else:
                self._send_json({"error": f"not found: {route}"}, status=404)

        # -- JSON APIs --------------------------------------------------

        def _api_runs(self) -> None:
            try:
                events = Ledger(ledger_path).read_all()
            except (OSError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            runs: list[str] = []
            for event in events:
                if event.run_id not in runs:
                    runs.append(event.run_id)
            self._send_json({"runs": runs})

        def _api_events(self) -> None:
            query = self._query()
            try:
                offset = _parse_offset(query.get("from"), "from")
                limit = _parse_offset(query.get("limit"), "limit")
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=400)
                return
            try:
                events = _read_filtered(Ledger(ledger_path), self._run_id(query))
            except (OSError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            total = len(events)
            window = events[offset:]
            if limit:
                window = window[:limit]
            self._send_json(
                {
                    "run_id": self._run_id(query),
                    "events": [e.model_dump(mode="json") for e in window],
                    "count": len(window),
                    "total": total,
                }
            )

        def _api_summary(self) -> None:
            query = self._query()
            try:
                events = _read_filtered(Ledger(ledger_path), self._run_id(query))
            except (OSError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(build_summary(events))

        # -- SSE stream -------------------------------------------------

        def _stream_events(self) -> None:
            query = self._query()
            try:
                replay = _parse_flag(query.get("replay"), "replay", False)
                follow = _parse_flag(query.get("follow"), "follow", True)
                offset = _parse_offset(query.get("from"), "from")
                speed = parse_speed(query.get("speed"))
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=400)
                return
            run_id = self._run_id(query)
            try:
                events = _read_filtered(Ledger(ledger_path), run_id)[offset:]
            except (OSError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            # No Content-Length on purpose: the stream is close-delimited,
            # so the connection must close when a finite stream ends.
            # (keep-alive here hangs real clients: both sides wait forever.)
            self.send_header("Connection", "close")
            self._cors()
            self.end_headers()
            try:
                self.wfile.write(b": exhibit-a live\n\n")
                self.wfile.flush()
                if replay:
                    self._send_replay(events, speed, offset)
                else:
                    self._send_live(run_id, events, offset, follow)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the viewer went away; nothing left to do

        def _push(self, frame: str) -> None:
            self.wfile.write(frame.encode("utf-8"))
            self.wfile.flush()

        def _send_replay(
            self, events: Sequence[Event], speed: float, offset: int
        ) -> None:
            player = Replayer(events=events, speed=speed)
            for index, (event, delay) in enumerate(player.iter_with_delays()):
                if delay:
                    time.sleep(delay)
                self._push(format_sse(event, id=offset + index))
            self._push(format_done(len(events)))

        def _send_live(
            self,
            run_id: str | None,
            first: Sequence[Event],
            offset: int,
            follow: bool,
        ) -> None:
            sent = 0
            for event in first:
                self._push(format_sse(event, id=offset + sent))
                sent += 1
            if not follow:
                self._push(format_done(sent))
                return
            ledger = Ledger(ledger_path)
            poll_failed = False
            while True:
                time.sleep(POLL_INTERVAL)
                try:
                    current = _read_filtered(ledger, run_id)[offset:]
                except (OSError, ValueError):
                    if not poll_failed:  # edge-triggered: one error, then quiet
                        self._push(
                            "event: error\n"
                            f"data: {json.dumps({'error': 'ledger unreadable'})}\n\n"
                        )
                    poll_failed = True
                    continue
                poll_failed = False
                for event in current[sent:]:
                    self._push(format_sse(event, id=offset + sent))
                    sent += 1

    return LiveHandler


class LiveServer(ThreadingHTTPServer):
    """Threaded server with daemon threads so tests shut down cleanly."""

    daemon_threads = True
    allow_reuse_address = True


def create_server(
    ledger_path: str | Path,
    web_dir: str | Path,
    host: str = "127.0.0.1",
    port: int = 0,
) -> LiveServer:
    """Create (but do not start) a live view server. Port 0 picks a free one."""
    handler = make_handler(Path(ledger_path), Path(web_dir))
    return LiveServer((host, port), handler)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="exhibit_a.live.server",
        description="Exhibit A live view: ledger SSE stream plus replay mode.",
    )
    parser.add_argument(
        "--ledger", default="ledger.jsonl", help="Ledger file to stream."
    )
    parser.add_argument("--host", default="127.0.0.1", help="Interface to bind.")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind.")
    parser.add_argument(
        "--web", default="web", help="Directory holding index.html and app.js."
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``python -m exhibit_a.live.server``."""
    args = build_parser().parse_args(argv)
    try:
        server = create_server(args.ledger, args.web, args.host, args.port)
    except OSError as exc:
        print(f"live: cannot bind {args.host}:{args.port}: {exc}")
        return 1
    url = f"http://{args.host}:{server.server_address[1]}/"
    print(f"live: serving {url} from ledger {args.ledger} (^C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
