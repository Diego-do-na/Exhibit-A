"""Replay provider: serves recorded completions from JSONL, records new ones on demand."""

import hashlib
import json
from pathlib import Path
from typing import Any

from .base import Completion, Provider, Role
from .cost import Pricing
from .errors import ReplayMiss


def request_key(role: Role, prompt: str, schema: dict[str, Any]) -> str:
    """Stable hash of everything that determines a model answer."""
    canonical = json.dumps(
        {"role": str(role), "prompt": prompt, "schema": schema},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class ReplayProvider:
    """Looks requests up in `path`. On a miss it asks `recorder` (a real provider) and
    appends the answer to the file; without a recorder a miss raises ReplayMiss.
    """

    name = "replay"

    def __init__(self, path: str | Path, recorder: Provider | None = None) -> None:
        self.path = Path(path)
        self.recorder = recorder
        self.pricing = recorder.pricing if recorder else Pricing()
        self._entries: dict[str, Completion] = {}
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    record = json.loads(line)
                    self._entries[record["key"]] = Completion(
                        text=record["text"],
                        tokens_in=record["tokens_in"],
                        tokens_out=record["tokens_out"],
                        latency_ms=record["latency_ms"],
                        model=record.get("model", ""),
                        cost_usd=record.get("cost_usd", 0.0),
                    )

    def complete(self, role: Role, prompt: str, schema: dict[str, Any]) -> Completion:
        key = request_key(role, prompt, schema)
        hit = self._entries.get(key)
        if hit is not None:
            return hit
        if self.recorder is None:
            raise ReplayMiss(f"no recording for {role} request {key[:12]}")
        completion = self.recorder.complete(role, prompt, schema)
        self._entries[key] = completion
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = {"key": key, "role": str(role), **completion.__dict__}
        with self.path.open("a") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        return completion
