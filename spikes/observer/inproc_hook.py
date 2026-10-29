"""A stripped-down copy of the product's in-process audit-hook idea.

SPIKE ONLY. This is here so the demo can show the two observers side by side:
the in-process hook records the fact of the read *and* the Python call stack
(provenance), but it writes to a file the test process can also write; the
out-of-process ptrace observer records only the fact, but the test cannot touch
its record. It is deliberately NOT the product plugin and is not imported by it.
"""
from __future__ import annotations

import json
import os
import sys
import traceback

ENV_CANARY = "SPIKE_CANARY"
ENV_EVENTS = "SPIKE_INPROC_EVENTS"


def install() -> None:
    canary = os.environ.get(ENV_CANARY)
    events = os.environ.get(ENV_EVENTS)
    if not (canary and events):
        return
    canary_real = os.path.realpath(canary)

    def hook(event: str, args: tuple) -> None:
        if event != "open":
            return
        target = args[0]
        if not isinstance(target, (str, bytes, os.PathLike)):
            return
        try:
            if os.path.realpath(os.fsdecode(target)) != canary_real:
                return
        except (OSError, ValueError):
            return
        stack = [
            {"file": fr.filename, "function": fr.name}
            for fr in traceback.extract_stack(sys._getframe(1))
        ]
        with open(events, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"observer": "inproc", "stack": stack}) + "\n")

    sys.addaudithook(hook)


install()
