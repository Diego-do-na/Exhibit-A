import json
import multiprocessing
import threading
from pathlib import Path

import pytest
from pydantic import ValidationError

from exhibit_a.ledger.index import MAX_LINE_BYTES, append_run, read_runs
from exhibit_a.schemas import RunRecord

SCHEMA_FILE = (Path(__file__).parent.parent / "src" / "exhibit_a" / "schemas"
               / "run_index.schema.json")


def make(run_id="run-1", **over):
    base = {
        "schema_version": "1", "run_id": run_id, "repo": "acme/app", "pr": 7,
        "commit": "abc1234", "ts": "2026-01-02T03:04:05+00:00", "status": "completed",
        "verdict_counts": {"proven": 1, "discarded_unproven": 2, "invalid_test": 0,
                           "flaky": 0, "env_failure": 0},
        "severity": "high", "discarded_suspicions": 2, "tokens_in": 100, "tokens_out": 50,
        "cost_usd": 0.12, "duration_s": 33.5, "ledger_path": "runs/run-1/ledger.jsonl",
    }
    return {**base, **over}


def _proc_writer(path, start, n):
    for i in range(start, start + n):
        append_run(path, make(run_id=f"p{i}"))


def test_round_trip(tmp_path):
    index = tmp_path / "runs.jsonl"
    append_run(index, make("a"))
    append_run(index, RunRecord.model_validate(make("b", pr=None, severity=None)))
    records, problems = read_runs(index)
    assert problems == []
    assert [r.run_id for r in records] == ["a", "b"]
    assert records[0].model_dump(mode="json")["verdict_counts"]["proven"] == 1
    assert records[1].pr is None and records[1].severity is None
    assert len(index.read_text().splitlines()) == 2


def test_missing_index_is_empty(tmp_path):
    assert read_runs(tmp_path / "nope.jsonl") == ([], [])


def test_corrupt_lines_are_reported_not_fatal(tmp_path):
    index = tmp_path / "runs.jsonl"
    append_run(index, make("good1"))
    with index.open("ab") as f:
        f.write(b"{not json\n")
        f.write(b'{"schema_version": "1"}\n')
        f.write(b"\xff\xfe\n")
        f.write(b"[1, 2]\n")
        f.write(b"x" * (MAX_LINE_BYTES + 10) + b"\n")
    append_run(index, make("good2"))
    with index.open("ab") as f:
        f.write(b'{"torn": ')  # crash mid-write: no newline
    records, problems = read_runs(index)
    assert [r.run_id for r in records] == ["good1", "good2"]
    assert len(problems) == 6
    assert any("oversized" in p and p.startswith("line 6") for p in problems)
    assert any("truncated" in p for p in problems)


def test_append_rejects_invalid_and_oversized(tmp_path):
    index = tmp_path / "runs.jsonl"
    with pytest.raises(ValueError):
        append_run(index, make(ledger_path="/etc/passwd"))
    with pytest.raises(ValueError):
        append_run(index, make(ledger_path="../x"))
    with pytest.raises(ValueError):
        append_run(index, make(ts="2026-01-02T03:04:05"))
    with pytest.raises(ValueError):
        append_run(index, make(repo="r" * (MAX_LINE_BYTES + 1)))
    assert not index.exists()


def test_concurrent_threads(tmp_path):
    index = tmp_path / "runs.jsonl"
    threads = [threading.Thread(target=lambda k=k: [
        append_run(index, make(f"t{k}-{i}", repo="r" * 5000)) for i in range(25)])
        for k in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    records, problems = read_runs(index)
    assert problems == []
    assert len({r.run_id for r in records}) == 200


def test_concurrent_processes(tmp_path):
    index = tmp_path / "runs.jsonl"
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_proc_writer, args=(str(index), k * 40, 40)) for k in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
        assert p.exitcode == 0
    records, problems = read_runs(index)
    assert problems == []
    assert len({r.run_id for r in records}) == 160


def test_schema_is_strict():
    with pytest.raises(ValidationError):
        RunRecord.model_validate(make(extra_field=1))
    with pytest.raises(ValidationError):
        RunRecord.model_validate(make(schema_version="2"))
    with pytest.raises(ValidationError):
        RunRecord.model_validate(make(verdict_counts={"proven": 1}))


def test_schema_file_matches_model():
    on_disk = json.loads(SCHEMA_FILE.read_text())
    assert on_disk == RunRecord.model_json_schema(), (
        "regenerate run_index.schema.json from exhibit_a.schemas.run_index.RunRecord")
