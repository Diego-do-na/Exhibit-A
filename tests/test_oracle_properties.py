"""Seeded property checks for the oracle's fail-closed invariants."""

from __future__ import annotations

import copy
import json
import random

from exhibit_a.oracle import OracleEvent
from exhibit_a.oracle.oracle import _judge
from exhibit_a.oracle.plugin import sign_event, verify_lines


def _body(seed: int) -> dict:
    return {
        "type": "canary_read", "path": f"/outside/{seed}", "mode": "r", "op": "open",
        "access": "read", "stack": [],
    }


def test_any_altered_signed_event_is_rejected():
    rng = random.Random(134)
    key = b"k" * 32
    for seed in range(20):
        body = _body(seed)
        line = sign_event(key, 0, body)
        altered = copy.deepcopy(line)
        field = rng.choice(["body", "seq", "sig"])
        if field == "body":
            altered["body"]["path"] += "-altered"
        elif field == "seq":
            altered["seq"] = 1
        else:
            altered["sig"] = "0" * 64
        events, rejected = verify_lines([json.dumps(altered)], key)
        assert events == []
        assert rejected


def test_reordering_and_duplicates_never_create_proof():
    key = b"k" * 32
    lines = [sign_event(key, i, _body(i)) for i in range(3)]
    for order in ([2, 1, 0], [0, 0, 1], [1, 2, 1]):
        events, rejected = verify_lines([json.dumps(lines[i]) for i in order], key)
        assert rejected
        assert len(events) < len(order)


def test_no_proof_without_failed_test():
    event = OracleEvent.model_validate({
        **_body(1),
        "stack": [
            {"file": "/tests/test.py", "function": "test", "qualname": "test", "line": 1},
            {"file": "/app/app.py", "function": "handle_request",
             "qualname": "App.handle_request", "line": 2, "admitted": True},
        ],
    })
    for outcome in ("passed", "error", "timeout"):
        j = _judge(outcome, [event], __import__("pathlib").Path("/app"),
                   __import__("pathlib").Path("/tests/test.py"), {"App.handle_request"})
        assert not (j.observed_effect and j.provenance_ok)


def test_judge_is_deterministic():
    event = OracleEvent.model_validate({
        **_body(2),
        "stack": [{"file": "/tests/test.py", "function": "test", "qualname": "test", "line": 1}],
    })
    args = ("failed", [event], __import__("pathlib").Path("/app"),
            __import__("pathlib").Path("/tests/test.py"), {"App.handle_request"})
    assert _judge(*args).model_dump() == _judge(*args).model_dump()
