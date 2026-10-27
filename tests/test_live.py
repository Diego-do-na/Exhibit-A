"""Tests for the live view: SSE endpoint, replay ordering, sample ledger.

Endpoint tests drive the real handler class (``make_handler``) over an
in-memory request/response pair instead of TCP: the bytes on the wire are
identical (status line, headers, SSE frames), but no socket bind is needed,
so the suite runs in sandboxes where listening is forbidden.
"""

import io
import json
from pathlib import Path

import pytest

from exhibit_a.ledger import Ledger
from exhibit_a.live import (
    Replayer,
    build_parser,
    build_summary,
    format_sse,
    make_handler,
    parse_speed,
    parse_sse,
    select_events,
)
from exhibit_a.live.server import main
from exhibit_a.schemas import Event

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"
SAMPLE = WEB_DIR / "sample-ledger.jsonl"


def make_event(seq, run_id="r1", type="scan_done", **overrides):
    data = {
        "ts": f"2026-10-27T12:00:{seq:02d}Z",
        "run_id": run_id,
        "type": type,
        "role": "",
        "model": "",
        "tokens_in": 0,
        "tokens_out": 0,
        "cost_usd": 0.0,
        "latency_ms": 0,
        "payload": {"seq": seq},
    }
    data.update(overrides)
    return Event.model_validate(data)


def write_ledger(path, events):
    ledger = Ledger(path)
    for event in events:
        ledger.append(event)
    return ledger


class _KeepBytes(io.BytesIO):
    def close(self):  # keep the buffer readable after handler teardown
        pass


class _FakeRequest:
    """In-memory stand-in for a client socket (see module docstring)."""

    def __init__(self, raw: bytes):
        self._reader = io.BytesIO(raw)
        self.out = _KeepBytes()

    def makefile(self, mode, *args, **kwargs):
        return self._reader if "r" in mode else self.out

    def sendall(self, data: bytes):  # used by the 3.14+ writer path
        self.out.write(data)


def handle(ledger_path, target, web_dir=None):
    """Send one GET through the real handler; return (status, headers, body)."""
    handler_cls = make_handler(Path(ledger_path), web_dir or WEB_DIR)
    raw = f"GET {target} HTTP/1.0\r\nHost: test\r\n\r\n".encode()
    request = _FakeRequest(raw)
    handler_cls(request, ("127.0.0.1", 1), None)
    head, _, body = request.out.getvalue().partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return status, headers, body.decode("utf-8")


def get_json(ledger_path, target):
    status, _, body = handle(ledger_path, target)
    return status, json.loads(body)


def get_sse_frames(ledger_path, target):
    """GET an SSE endpoint that closes by itself; return parsed frames."""
    status, headers, body = handle(ledger_path, target)
    assert status == 200
    assert headers["content-type"].startswith("text/event-stream")
    return parse_sse(body)


# -- speed parsing ------------------------------------------------------


def test_parse_speed_defaults_to_one():
    assert parse_speed(None) == 1.0
    assert parse_speed("") == 1.0
    assert parse_speed("2.5") == pytest.approx(2.5)


@pytest.mark.parametrize("raw", ["0", "0.0", "-1", "-0.5", "abc", "nan", "inf"])
def test_parse_speed_rejects_non_positive(raw):
    with pytest.raises(ValueError):
        parse_speed(raw)


def test_replayer_rejects_bad_speed():
    with pytest.raises(ValueError):
        Replayer(events=[], speed=0)
    with pytest.raises(ValueError):
        Replayer(events=[], speed=-3)


# -- replay ordering and pacing ------------------------------------------


def test_select_events_filters_run_and_keeps_order(tmp_path):
    ledger = write_ledger(
        tmp_path / "events.jsonl",
        [make_event(seq=i, run_id=f"r{i % 2}") for i in range(6)],
    )
    assert [e.payload["seq"] for e in select_events(ledger.read_all(), "r1")] == [1, 3, 5]
    assert [e.payload["seq"] for e in select_events(ledger.read_all(), None)] == list(range(6))
    assert select_events(ledger.read_all(), "nope") == []
    assert [e.payload["seq"] for e in select_events(ledger.read_all(), "r1", skip=1)] == [3, 5]


def test_select_events_rejects_negative_skip():
    with pytest.raises(ValueError):
        select_events([], None, skip=-1)


def test_replayer_preserves_ledger_order(tmp_path):
    ledger = write_ledger(
        tmp_path / "events.jsonl",
        [make_event(seq=i, run_id=f"r{i % 2}") for i in range(6)],
    )
    player = Replayer(events=select_events(ledger.read_all(), "r0"))
    assert [e.payload["seq"] for e in player.events] == [0, 2, 4]
    assert [e.payload["seq"] for e, _ in player.iter_with_delays()] == [0, 2, 4]


def test_replayer_speed_scales_gaps_inversely():
    events = [make_event(seq=i) for i in range(3)]
    assert Replayer(events=events, speed=1.0, base_interval=1.0).delays() == [0.0, 1.0, 1.0]
    assert Replayer(events=events, speed=4.0, base_interval=1.0).delays() == [0.0, 0.25, 0.25]
    assert Replayer(events=events, speed=0.5, base_interval=1.0).gap == pytest.approx(2.0)


def test_with_speed_keeps_order_and_changes_gap():
    events = [make_event(seq=i) for i in range(2)]
    faster = Replayer(events=events, speed=1.0).with_speed(8.0)
    assert [e.payload["seq"] for e in faster.events] == [0, 1]
    assert faster.gap == pytest.approx(0.25 / 8.0)


def test_format_sse_round_trip_through_parse_sse():
    event = make_event(seq=3, type="verdict", payload={"verdict": "proven"})
    frames = parse_sse(format_sse(event, id=7) + ": comment line\n\n")
    assert len(frames) == 1
    assert frames[0]["event"] == "verdict"
    assert frames[0]["id"] == "7"
    assert json.loads(frames[0]["data"])["payload"] == {"verdict": "proven"}


# -- SSE endpoint --------------------------------------------------------


def sse_payloads(frames):
    return [json.loads(f["data"]) for f in frames if f["event"] != "done"]


def test_sse_replay_streams_run_in_order(tmp_path):
    path = tmp_path / "events.jsonl"
    write_ledger(path, [make_event(seq=i, run_id=f"r{i % 2}") for i in range(6)])
    frames = get_sse_frames(path, "/events?run_id=r1&replay=1&speed=64")
    assert [p["payload"]["seq"] for p in sse_payloads(frames)] == [1, 3, 5]
    assert frames[-1]["event"] == "done"
    assert json.loads(frames[-1]["data"]) == {"count": 3}
    assert [f["id"] for f in frames if f["event"] != "done"] == ["0", "1", "2"]


def test_sse_live_without_follow_returns_existing_in_order(tmp_path):
    path = tmp_path / "events.jsonl"
    write_ledger(path, [make_event(seq=i) for i in range(4)])
    frames = get_sse_frames(path, "/events?follow=0")
    assert [p["payload"]["seq"] for p in sse_payloads(frames)] == [0, 1, 2, 3]
    assert frames[-1]["event"] == "done"


def test_sse_from_offset_skips_leading_events(tmp_path):
    path = tmp_path / "events.jsonl"
    write_ledger(path, [make_event(seq=i) for i in range(5)])
    frames = get_sse_frames(path, "/events?replay=1&speed=64&from=2")
    assert [p["payload"]["seq"] for p in sse_payloads(frames)] == [2, 3, 4]
    assert json.loads(frames[-1]["data"]) == {"count": 3}


def test_sse_replay_unknown_run_sends_empty_done(tmp_path):
    path = tmp_path / "events.jsonl"
    write_ledger(path, [make_event(seq=0)])
    frames = get_sse_frames(path, "/events?run_id=nope&replay=1&speed=64")
    assert sse_payloads(frames) == []
    assert frames[-1]["event"] == "done"
    assert json.loads(frames[-1]["data"]) == {"count": 0}


def test_sse_finite_modes_close_the_connection(tmp_path):
    # Regression: the stream has no Content-Length, so it is close-delimited.
    # A keep-alive header here hangs real HTTP clients, which wait for an
    # EOF that never comes while the server waits for a second request.
    path = tmp_path / "events.jsonl"
    write_ledger(path, [make_event(seq=0)])
    _, headers, _ = handle(path, "/events?replay=1&speed=64")
    assert headers["connection"] == "close"
    _, headers, _ = handle(path, "/events?follow=0")
    assert headers["connection"] == "close"


def test_sse_invalid_params_are_400(tmp_path):
    path = tmp_path / "events.jsonl"
    write_ledger(path, [make_event(seq=0)])
    for query in ("replay=1&speed=0", "replay=1&speed=abc", "from=-1", "follow=maybe"):
        status, body = get_json(path, f"/events?{query}")
        assert status == 400
        assert "error" in body


def test_sse_replay_is_slower_when_speed_drops(tmp_path):
    import time

    path = tmp_path / "events.jsonl"
    write_ledger(path, [make_event(seq=i) for i in range(4)])
    start = time.monotonic()
    get_sse_frames(path, "/events?replay=1&speed=64")
    fast = time.monotonic() - start
    start = time.monotonic()
    get_sse_frames(path, "/events?replay=1&speed=2")
    slow = time.monotonic() - start
    # 3 gaps: ~0.01s fast vs ~0.375s slow; assert a wide, stable margin.
    assert slow > fast + 0.15


# -- JSON APIs -----------------------------------------------------------


def test_api_events_filters_by_run(tmp_path):
    path = tmp_path / "events.jsonl"
    write_ledger(path, [make_event(seq=i, run_id=f"r{i % 2}") for i in range(6)])
    status, body = get_json(path, "/api/events?run_id=r0")
    assert status == 200
    assert body["run_id"] == "r0"
    assert [e["payload"]["seq"] for e in body["events"]] == [0, 2, 4]
    assert body["count"] == 3
    assert body["total"] == 3


def test_api_runs_lists_runs_in_order(tmp_path):
    path = tmp_path / "events.jsonl"
    write_ledger(
        path,
        [make_event(seq=0, run_id="b"), make_event(seq=1, run_id="a"), make_event(seq=2, run_id="b")],
    )
    status, body = get_json(path, "/api/runs")
    assert status == 200
    assert body == {"runs": ["b", "a"]}


def test_api_summary_matches_build_summary(tmp_path):
    path = tmp_path / "events.jsonl"
    events = [make_event(seq=0), make_event(seq=1, type="verdict", payload={"verdict": "proven"})]
    write_ledger(path, events)
    status, body = get_json(path, "/api/summary?run_id=r1")
    assert status == 200
    assert body["event_count"] == 2
    assert body["red_to_green"]["red"] is True
    assert body["verdict_counts"]["proven"] == 1


def test_unknown_route_is_404(tmp_path):
    path = tmp_path / "events.jsonl"
    write_ledger(path, [make_event(seq=0)])
    status, body = get_json(path, "/nope")
    assert status == 404
    assert "error" in body


def test_index_is_served(tmp_path):
    path = tmp_path / "events.jsonl"
    write_ledger(path, [make_event(seq=0)])
    status, headers, body = handle(path, "/")
    assert status == 200
    assert "text/html" in headers["content-type"]
    assert 'id="timeline"' in body


def test_cli_defaults_and_bind_failure(capsys):
    args = build_parser().parse_args([])
    assert (args.host, args.port, args.ledger, args.web) == ("127.0.0.1", 8000, "ledger.jsonl", "web")
    assert main(["--host", "256.256.256.256", "--port", "9"]) == 1
    assert "cannot bind" in capsys.readouterr().out


# -- sample ledger renders every panel -----------------------------------


def test_sample_ledger_is_valid_and_ordered():
    assert SAMPLE.is_file(), "web/sample-ledger.jsonl must ship with the page"
    events = Ledger(SAMPLE).read_all()
    assert len(events) >= 10
    assert [e.ts for e in events] == sorted(e.ts for e in events)


def test_sample_summary_feeds_every_panel():
    summary = build_summary(Ledger(SAMPLE).read_all())
    assert summary["diff"], "diff panel needs recorded diff text"
    assert len(summary["suspect_lines"]) >= 2, "diff needs suspect lines"
    assert len(summary["timeline"]) == summary["event_count"] > 0
    assert "canary" in summary["sandbox_output"], "sandbox panel needs output"
    assert summary["red_to_green"]["red"] is True
    assert summary["red_to_green"]["green"] is True
    assert len(summary["regression_wall"]) >= 1
    assert summary["dropped"] >= 1


def test_page_contains_every_panel_and_stream_code():
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    for panel_id in ("diff", "suspects", "timeline", "sandbox", "red", "green", "wall", "dropped"):
        assert f'id="{panel_id}"' in html, f"index.html misses #{panel_id}"
    for control_id in ("run", "speed", "file", "replay", "connect", "sample"):
        assert f'id="{control_id}"' in html, f"index.html misses #{control_id}"
    assert "nothing could be proven" in html
    js = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    assert "EventSource" in js
    assert "sample-ledger.jsonl" in js
    assert (WEB_DIR / "style.css").is_file()
