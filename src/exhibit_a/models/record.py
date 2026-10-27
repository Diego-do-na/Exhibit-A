"""Provider wrapper that records live completions for deterministic replay."""

import json
from pathlib import Path

from .base import Completion, Provider, Role
from .replay import request_key


class RecordingProvider:
    """Delegate completions to a provider and append them to a replay JSONL file."""

    name = "record"

    def __init__(self, path: str | Path, provider: Provider) -> None:
        self.path = Path(path)
        self.provider = provider
        self.pricing = provider.pricing

    def complete(self, role: Role, prompt: str, schema: dict) -> Completion:
        completion = self.provider.complete(role, prompt, schema)
        record = {"key": request_key(role, prompt, schema), "role": str(role)}
        record.update(completion.__dict__)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        return completion


RecordProvider = RecordingProvider
