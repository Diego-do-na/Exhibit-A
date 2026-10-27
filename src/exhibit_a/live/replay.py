"""Replay helper: re-emit a finished run's ledger events in order.

The ledger is the single source of truth (SPEC.md section 9). A replay reads
the recorded events for one run and yields them oldest-first, pacing the gaps
between events by ``base_interval / speed`` seconds. The live view uses this
to show a finished run faster or slower without touching the engine.
"""

from __future__ import annotations

import math
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from ..schemas import Event

#: Seconds between events at speed 1.0. Small enough to feel live, large
#: enough that the timeline visibly grows during a demo replay.
DEFAULT_BASE_INTERVAL = 0.25


def parse_speed(value: str | None) -> float:
    """Parse a replay speed query value. Missing means 1.0.

    Raises ValueError for anything that is not a finite number above zero.
    """
    if value is None or value == "":
        return 1.0
    try:
        speed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid speed {value!r}: not a number") from exc
    if not math.isfinite(speed) or speed <= 0:
        raise ValueError(f"invalid speed {value!r}: must be above zero")
    return speed


def select_events(
    events: Sequence[Event], run_id: str | None, skip: int = 0
) -> list[Event]:
    """Filter events to one run (None keeps every run) and drop the first skip.

    Order is always preserved: the ledger is append-only, so file order is
    event order. Raises ValueError for a negative skip.
    """
    if skip < 0:
        raise ValueError(f"invalid offset {skip}: must be zero or more")
    if run_id is None:
        filtered = list(events)
    else:
        filtered = [event for event in events if event.run_id == run_id]
    return filtered[skip:]


def format_sse(event: Event, id: int | None = None) -> str:
    """Format one ledger event as a Server-Sent Events frame."""
    lines: list[str] = []
    if id is not None:
        lines.append(f"id: {id}")
    lines.append(f"event: {event.type.value}")
    for chunk in event.model_dump_json().splitlines() or [""]:
        lines.append(f"data: {chunk}")
    lines.append("")
    lines.append("")
    return "\n".join(lines)


def format_done(count: int) -> str:
    """Format the terminal frame sent when a replay (or one-shot read) ends."""
    return f"event: done\ndata: {{\"count\": {count}}}\n\n"


def parse_sse(text: str) -> list[dict[str, str | None]]:
    """Parse SSE frames into ``{"event", "data", "id"}`` dicts.

    Comment lines (starting with ":") are skipped. Frames without an
    explicit event name report ``"message"``, per the SSE convention.
    """
    frames: list[dict[str, str | None]] = []
    name = "message"
    data_lines: list[str] = []
    frame_id: str | None = None
    seen_field = False

    def flush() -> None:
        nonlocal name, data_lines, frame_id, seen_field
        if seen_field:
            frames.append(
                {"event": name, "data": "\n".join(data_lines), "id": frame_id}
            )
        name = "message"
        data_lines = []
        frame_id = None
        seen_field = False

    for line in text.splitlines():
        if line == "":
            flush()
        elif line.startswith(":"):
            continue
        else:
            field, _, raw = line.partition(":")
            value = raw[1:] if raw.startswith(" ") else raw
            if field == "event" and value:
                name = value
                seen_field = True
            elif field == "data":
                data_lines.append(value)
                seen_field = True
            elif field == "id":
                frame_id = value
                seen_field = True
    flush()
    return frames


@dataclass(frozen=True)
class Replayer:
    """An ordered event list plus the pacing for re-emitting it."""

    events: tuple[Event, ...] = ()
    speed: float = 1.0
    base_interval: float = DEFAULT_BASE_INTERVAL

    def __init__(
        self,
        events: Sequence[Event] = (),
        speed: float = 1.0,
        base_interval: float = DEFAULT_BASE_INTERVAL,
    ) -> None:
        if not math.isfinite(speed) or speed <= 0:
            raise ValueError(f"invalid speed {speed!r}: must be above zero")
        if not math.isfinite(base_interval) or base_interval < 0:
            raise ValueError(
                f"invalid base_interval {base_interval!r}: must be zero or more"
            )
        object.__setattr__(self, "events", tuple(events))
        object.__setattr__(self, "speed", float(speed))
        object.__setattr__(self, "base_interval", float(base_interval))

    @property
    def gap(self) -> float:
        """Seconds between consecutive events at the current speed."""
        return self.base_interval / self.speed

    def delays(self) -> list[float]:
        """Delay before each event: zero for the first, gap for the rest."""
        return [0.0 if i == 0 else self.gap for i in range(len(self.events))]

    def iter_with_delays(self) -> Iterator[tuple[Event, float]]:
        """Yield ``(event, delay_before)`` pairs in ledger order."""
        yield from zip(self.events, self.delays())

    def with_speed(self, speed: float) -> Replayer:
        """Return a copy paced at a different speed (same order)."""
        return Replayer(
            events=self.events, speed=speed, base_interval=self.base_interval
        )
