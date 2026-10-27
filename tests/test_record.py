"""Tests for recording live provider completions for replay."""

import json

from exhibit_a.models import Completion, Pricing, ReplayProvider, Role
from exhibit_a.models.record import RecordingProvider


SCHEMA = {"type": "object", "required": ["answer"]}


class ScriptedProvider:
    name = "scripted"
    pricing = Pricing()

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, role, prompt, schema):
        self.calls += 1
        return Completion('{"answer": "ok"}', 3, 2, 7, "scripted-1", 0.25)


def test_record_then_replay_round_trips(tmp_path):
    path = tmp_path / "replay.jsonl"
    live = ScriptedProvider()
    recorded = RecordingProvider(path, live)

    first = recorded.complete(Role.ADVERSARY, "hello", SCHEMA)

    assert live.calls == 1
    assert first.text == '{"answer": "ok"}'
    entry = json.loads(path.read_text())
    assert entry["key"]
    assert entry["role"] == "adversary"
    assert entry["text"] == first.text

    replayed = ReplayProvider(path)
    second = replayed.complete(Role.ADVERSARY, "hello", SCHEMA)

    assert second == first
    assert live.calls == 1
