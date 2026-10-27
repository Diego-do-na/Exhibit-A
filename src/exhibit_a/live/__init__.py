"""Live view backend: SSE stream plus replay mode (SPEC.md section 9).

The UI in web/ is a thin window into the engine: this package feeds it with
ledger events, either live as they are appended or replayed from a finished
run at adjustable speed. It reads the recorded ledger file only and never
touches the engine itself.
"""

from .replay import (
    DEFAULT_BASE_INTERVAL,
    Replayer,
    format_done,
    format_sse,
    parse_speed,
    parse_sse,
    select_events,
)
from .server import LiveServer, build_parser, create_server, main, make_handler
from .summary import build_summary, summarize_event

__all__ = [
    "DEFAULT_BASE_INTERVAL",
    "LiveServer",
    "Replayer",
    "build_parser",
    "build_summary",
    "create_server",
    "format_done",
    "format_sse",
    "main",
    "make_handler",
    "parse_speed",
    "parse_sse",
    "select_events",
    "summarize_event",
]
