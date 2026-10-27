"""Append-only JSONL ledger built on the Event schema.

Guarantees:
- One line per event. Each append is a single ``os.write`` on a file opened
  with ``O_APPEND``, so two processes appending at the same time cannot
  interleave bytes inside a line. The descriptor is fsynced before close.
- Reads never modify the file, and no method exists to rewrite or delete
  lines: past events are immutable.
- Reading a ledger file that does not exist yet yields no events instead of
  raising, so a fresh run starts empty.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ..schemas import Event, EventType
from ..schemas import VerdictValue

PathLike = str | Path


class Ledger:
    """An append-only log of Event lines stored as JSONL."""

    def __init__(self, path: PathLike) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        """Filesystem location of the JSONL log."""
        return self._path

    def append(self, event: Event | dict[str, Any]) -> None:
        """Append one event as a single line, flushed to disk.

        Accepts an Event or a mapping validated against the Event schema.
        Raises pydantic.ValidationError for data that is not a valid Event.
        """
        if not isinstance(event, Event):
            event = Event.model_validate(event)
        line = event.model_dump_json() + "\n"
        data = line.encode("utf-8")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            written = os.write(fd, data)
            if written != len(data):  # pragma: no cover - tiny lines write fully
                raise OSError(f"short write appending to {self._path}")
            os.fsync(fd)
        finally:
            os.close(fd)

    def read_all(self) -> list[Event]:
        """Return every event in the log, oldest first."""
        return list(self._iter_file())

    def replay(self, run_id: str) -> Iterator[Event]:
        """Yield the events of one run, oldest first."""
        for event in self._iter_file():
            if event.run_id == run_id:
                yield event

    def totals(self, run_id: str) -> dict[str, Any]:
        """Sum usage and verdict counts for one run.

        Returns ``{"tokens_in", "tokens_out", "cost_usd", "verdicts"}`` where
        ``verdicts`` maps each known verdict value to its count among this
        run's ``verdict`` events (unknown labels are counted as observed).
        """
        totals: dict[str, Any] = {
            "tokens_in": 0,
            "tokens_out": 0,
            "cost_usd": 0.0,
            "verdicts": {value.value: 0 for value in VerdictValue},
        }
        for event in self.replay(run_id):
            totals["tokens_in"] += event.tokens_in
            totals["tokens_out"] += event.tokens_out
            totals["cost_usd"] += event.cost_usd
            if event.type == EventType.VERDICT:
                verdict = event.payload.get("verdict")
                if isinstance(verdict, str):
                    totals["verdicts"][verdict] = totals["verdicts"].get(verdict, 0) + 1
        return totals

    def _iter_file(self) -> Iterator[Event]:
        """Yield parsed events in file order, skipping blank lines."""
        try:
            handle = self._path.open("r", encoding="utf-8")
        except FileNotFoundError:
            return
        with handle:
            for lineno, raw in enumerate(handle, start=1):
                if not raw.strip():
                    continue
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"corrupt ledger {self._path} line {lineno}: not valid JSON"
                    ) from exc
                try:
                    yield Event.model_validate(payload)
                except ValidationError as exc:
                    raise ValueError(
                        f"corrupt ledger {self._path} line {lineno}: "
                        "line is not a valid Event"
                    ) from exc
