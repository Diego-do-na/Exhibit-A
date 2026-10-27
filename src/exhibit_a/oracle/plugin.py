"""Pytest plugin that observes reads of the canary file.

It runs inside the process that executes the exploit test. An audit hook watches every
``open``; when the canary is opened, the call stack is written to an events file so the
oracle can later check where the read came from. Configuration comes from environment
variables set by the oracle runner.
"""

from __future__ import annotations

import json
import os
import sys

ENV_CANARY = "EXHIBIT_A_CANARY"
ENV_EVENTS = "EXHIBIT_A_EVENTS"

_MAX_FRAMES = 200


def _stack(frame) -> list[dict[str, str]]:
    """Frames from the outermost caller to the innermost, as plain dicts."""
    frames = []
    while frame is not None and len(frames) < _MAX_FRAMES:
        code = frame.f_code
        # Pseudo files such as "<frozen runpy>" must not be resolved against the cwd.
        name = code.co_filename
        frames.append(
            {
                "file": name if name.startswith("<") else os.path.realpath(name),
                "function": code.co_name,
                "qualname": code.co_qualname,
            }
        )
        frame = frame.f_back
    frames.reverse()
    return frames


def _install(canary: str, events_path: str) -> None:
    canary = os.path.realpath(canary)

    def hook(event: str, args: tuple) -> None:
        if event != "open":
            return
        target = args[0]
        if not isinstance(target, (str, bytes, os.PathLike)):
            return  # an integer file descriptor, not a path
        try:
            if os.path.realpath(os.fsdecode(target)) != canary:
                return
        except (OSError, ValueError):
            return
        record = {"path": canary, "mode": str(args[1]), "stack": _stack(sys._getframe(1))}
        with open(events_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

    sys.addaudithook(hook)


def pytest_configure(config) -> None:
    canary = os.environ.get(ENV_CANARY)
    events_path = os.environ.get(ENV_EVENTS)
    if canary and events_path:
        _install(canary, events_path)
