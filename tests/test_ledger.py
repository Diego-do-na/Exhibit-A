"""Tests for the append-only JSONL ledger."""

import json
import multiprocessing

import pytest
from pydantic import ValidationError

from exhibit_a.ledger import Ledger
from exhibit_a.schemas import Event, EventType


def make_event(run_id="r1", type="scan_done", seq=0, **overrides):
    data = {
        "ts": f"2026-10-27T12:00:{seq:02d}Z",
        "run_id": run_id,
        "type": type,
        "role": "adversary",
        "model": "replay",
        "tokens_in": 10,
        "tokens_out": 5,
        "cost_usd": 0.001,
        "latency_ms": 120,
        "payload": {"seq": seq},
    }
    data.update(overrides)
    return Event.model_validate(data)


def _append_many(path, worker, count):
    """Multiprocessing worker: append `count` uniquely marked events."""
    ledger = Ledger(path)
    for seq in range(count):
        ledger.append(
            make_event(
                run_id="concurrent",
                type=EventType.ORACLE_EVENT.value,
                seq=seq,
                payload={"worker": worker, "seq": seq},
            )
        )


def test_append_and_read_all_preserve_order(tmp_path):
    ledger = Ledger(tmp_path / "events.jsonl")
    events = [make_event(run_id="r1" if i % 2 == 0 else "r2", seq=i) for i in range(5)]
    for event in events:
        ledger.append(event)
    assert ledger.read_all() == events


def test_one_line_per_event(tmp_path):
    path = tmp_path / "events.jsonl"
    ledger = Ledger(path)
    ledger.append(make_event(seq=0))
    ledger.append(make_event(seq=1))
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["payload"] == {"seq": 0}
    assert json.loads(lines[1])["payload"] == {"seq": 1}


def test_replay_filters_by_run_in_order(tmp_path):
    ledger = Ledger(tmp_path / "events.jsonl")
    for i in range(6):
        ledger.append(make_event(run_id=f"r{i % 2}", seq=i))
    replayed = list(ledger.replay("r1"))
    assert [e.payload["seq"] for e in replayed] == [1, 3, 5]
    assert all(e.run_id == "r1" for e in replayed)


def test_replay_unknown_run_is_empty(tmp_path):
    ledger = Ledger(tmp_path / "events.jsonl")
    ledger.append(make_event(run_id="r1"))
    assert list(ledger.replay("nope")) == []


def test_totals_sum_usage_and_count_verdicts(tmp_path):
    ledger = Ledger(tmp_path / "events.jsonl")
    ledger.append(make_event(run_id="r1", type="scan_done", seq=0))
    ledger.append(
        make_event(
            run_id="r1", type="verdict", seq=1, payload={"verdict": "proven"}
        )
    )
    ledger.append(
        make_event(
            run_id="r1", type="verdict", seq=2, payload={"verdict": "proven"}
        )
    )
    ledger.append(
        make_event(
            run_id="r1",
            type="verdict",
            seq=3,
            tokens_in=4,
            tokens_out=2,
            cost_usd=0.0005,
            payload={"verdict": "flaky"},
        )
    )
    ledger.append(make_event(run_id="other", type="verdict", seq=4,
                             payload={"verdict": "proven"}))
    totals = ledger.totals("r1")
    assert totals["tokens_in"] == 34
    assert totals["tokens_out"] == 17
    assert totals["cost_usd"] == pytest.approx(0.0035)
    assert totals["verdicts"]["proven"] == 2
    assert totals["verdicts"]["flaky"] == 1
    assert totals["verdicts"]["discarded_unproven"] == 0
    assert totals["verdicts"]["invalid_test"] == 0
    assert totals["verdicts"]["env_failure"] == 0


def test_totals_unknown_run_is_zero(tmp_path):
    ledger = Ledger(tmp_path / "events.jsonl")
    ledger.append(make_event(run_id="r1"))
    totals = ledger.totals("nope")
    assert totals["tokens_in"] == 0
    assert totals["tokens_out"] == 0
    assert totals["cost_usd"] == 0.0
    assert all(count == 0 for count in totals["verdicts"].values())


def test_reads_on_missing_file_are_empty(tmp_path):
    ledger = Ledger(tmp_path / "missing" / "events.jsonl")
    assert ledger.read_all() == []
    assert list(ledger.replay("r1")) == []
    assert ledger.totals("r1")["tokens_in"] == 0


def test_append_creates_missing_parent_dirs(tmp_path):
    ledger = Ledger(tmp_path / "nested" / "dir" / "events.jsonl")
    event = make_event()
    ledger.append(event)
    assert ledger.read_all() == [event]


def test_append_rejects_invalid_event(tmp_path):
    ledger = Ledger(tmp_path / "events.jsonl")
    with pytest.raises(ValidationError):
        ledger.append({"run_id": "r1", "type": "scan_done"})  # missing ts
    assert ledger.read_all() == []


def test_malformed_line_raises_loudly(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text('{"run_id": "r1", "type": "nope"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="line 1"):
        Ledger(path).read_all()


def test_not_json_line_raises_loudly(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("this is not json\n", encoding="utf-8")
    with pytest.raises(ValueError, match="line 1"):
        Ledger(path).read_all()


def test_appends_never_rewrite_past_lines(tmp_path):
    path = tmp_path / "events.jsonl"
    ledger = Ledger(path)
    ledger.append(make_event(seq=0))
    ledger.append(make_event(seq=1))
    before = path.read_bytes()
    ledger.append(make_event(seq=2))
    ledger.append(make_event(seq=3))
    after = path.read_bytes()
    assert after[: len(before)] == before
    assert len(after) > len(before)


def test_no_api_to_edit_or_delete_lines():
    mutators = {
        "update", "delete", "edit", "rewrite", "remove",
        "truncate", "write", "clear", "pop",
    }
    exposed = {name for name in dir(Ledger) if not name.startswith("_")}
    assert exposed == {"append", "path", "read_all", "replay", "totals"}
    assert not (mutators & exposed)


def test_concurrent_appends_from_two_processes(tmp_path):
    path = str(tmp_path / "events.jsonl")
    workers, per_worker = 4, 25
    procs = [
        multiprocessing.Process(target=_append_many, args=(path, w, per_worker))
        for w in range(workers)
    ]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(60)
        assert proc.exitcode == 0
    events = Ledger(path).read_all()
    assert len(events) == workers * per_worker
    marks = {(e.payload["worker"], e.payload["seq"]) for e in events}
    assert marks == {(w, s) for w in range(workers) for s in range(per_worker)}
    assert len(pathlib_lines(path)) == workers * per_worker


def pathlib_lines(path):
    with open(path, encoding="utf-8") as handle:
        return [line for line in handle if line.strip()]
