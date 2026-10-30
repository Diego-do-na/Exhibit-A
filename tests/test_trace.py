"""The trace of a run: ordered steps from the ledger, plain text and JSON.

Synthetic ledgers cover ordering, grouping, totals and hostile content; one docker-marked
test replays a real recorded case and traces the ledger it wrote.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from exhibit_a.cli import main
from exhibit_a.ledger import Ledger
from exhibit_a.ledger.trace import (
    MAX_DEPTH,
    MAX_ITEMS,
    MAX_STEPS,
    MAX_STRING,
    STAGES,
    build_trace,
    groups,
    render_text,
    totals,
    trace_to_dict,
)

ROOT = Path(__file__).resolve().parent.parent
RUN = "run-1"


def _ts(second: float) -> str:
    whole = int(second)
    millis = int(round((second - whole) * 1000))
    return f"2026-01-01T00:00:{whole:02d}.{millis:03d}+00:00"


def _add(ledger: Ledger, at: float, type_: str, run_id: str = RUN, **fields):
    payload = fields.pop("payload", {})
    ledger.append({"ts": _ts(at), "run_id": run_id, "type": type_, "payload": payload, **fields})


def _suspicion(sid: str, **extra) -> dict:
    return {"id": sid, "class": "path_traversal", "location": {"file": "app.py", "line": 45},
            "entry_point": "App.handle_request", "hypothesis": "h", "source": "q", **extra}


def _full_run(ledger: Ledger, run_id: str = RUN) -> None:
    """Every stage of a proven case, with the usage the loop records."""
    add = lambda at, type_, **kw: _add(ledger, at, type_, run_id, **kw)  # noqa: E731
    add(0.0, "baseline_done", payload={"ok": True, "outcome": "passed"})
    add(1.0, "suspicion_raised", role="adversary", model="m1", tokens_in=100, tokens_out=20,
        cost_usd=0.01, latency_ms=900, payload={"suspicion": _suspicion("S1")})
    add(2.0, "exploit_written", role="test_writer", model="m1", tokens_in=110, tokens_out=30,
        cost_usd=0.02, latency_ms=800, payload={"suspicion_id": "S1", "test_path": "w/test_exploit.py"})
    add(3.0, "run_started", payload={"suspicion_id": "S1", "run": 1, "of": 1})
    add(3.5, "oracle_event", payload={"suspicion_id": "S1", "run": 1, "event": {
        "type": "canary_read", "path": "/tmp/canary", "mode": "r", "access": "read", "stack": []}})
    add(4.0, "fix_proposed", role="fixer", model="m1", tokens_in=120, tokens_out=40,
        cost_usd=0.03, latency_ms=700, payload={"suspicion_id": "S1", "applied": True})
    add(5.0, "run_started", payload={"suspicion_id": "S1", "on": "fixed", "run": 1, "of": 1})
    add(5.5, "baseline_done", payload={"suspicion_id": "S1", "on": "fixed", "ok": True})
    add(6.0, "bypass_attempt", role="defender", model="m1", tokens_in=130, tokens_out=50,
        cost_usd=0.04, latency_ms=600, payload={"suspicion_id": "S1", "name": "symlink"})
    add(6.5, "bypass_result", payload={"suspicion_id": "S1", "name": "symlink", "bypassed": False})
    add(7.0, "verdict", payload={"suspicion_id": "S1", "verdict": "proven", "reason": "canary read",
                                 "reason_code": "ok", "effect": "canary_read", "fix_verified": True,
                                 "fix_incomplete": False, "fix_detail": ""})
    add(8.0, "packaged", payload={"suspicion_id": "S1", "path": "packages/S1", "fix_verified": True,
                                  "fix_incomplete": False})


# -- ordering, stages and totals --------------------------------------------------------------


def test_every_stage_of_a_proven_case_appears_in_order(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    _full_run(ledger)
    steps = build_trace(ledger.path, RUN)
    assert [s.stage for s in steps] == [
        "BASELINE", "SUSPECT", "EXPLOIT", "RUN", "RUN", "FIX", "VERIFY", "VERIFY", "VERIFY",
        "VERIFY", "VERDICT", "PACKAGE",
    ]
    assert [s.seq for s in steps] == list(range(1, 13))
    assert {s.stage for s in steps} <= set(STAGES)
    assert [s.type for s in steps][1] == "suspicion_raised"
    assert steps[1].role == "adversary" and steps[1].model == "m1"
    assert (steps[1].tokens_in, steps[1].tokens_out, steps[1].cost_usd, steps[1].latency_ms) == (
        100, 20, 0.01, 900)
    assert steps[1].suspicion_id == "S1" and steps[0].suspicion_id == ""
    assert steps[1].timestamp == _ts(1.0)
    assert "path_traversal at app.py:45 via App.handle_request" in steps[1].summary
    assert "oracle saw read access to /tmp/canary" in steps[4].summary
    assert steps[5].summary.startswith("fix proposed and applied")
    assert steps[8].summary == "bypass attempt: symlink"
    assert steps[9].summary == "bypass symlink: did not bypass the fix"
    assert steps[10].summary.startswith("verdict proven (fix verified)")
    assert steps[10].details["verdict"] == "proven"
    # Wall time is the gap to the next event; the last step has none.
    assert [s.wall_ms for s in steps][:3] == [1000, 1000, 1000]
    assert steps[-1].wall_ms is None


def test_totals_equal_the_ledger_totals(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    _full_run(ledger)
    _full_run(ledger, "other-run")  # a second run in the same file must not leak in
    steps = build_trace(ledger.path, RUN)
    summed = totals(steps)
    expected = ledger.totals(RUN)
    assert summed["tokens_in"] == expected["tokens_in"] == 460
    assert summed["tokens_out"] == expected["tokens_out"] == 140
    assert summed["cost_usd"] == expected["cost_usd"]
    assert summed["latency_ms"] == 3000
    assert summed["wall_ms"] == 8000
    assert summed["steps"] == 12
    assert all(s.seq <= 12 for s in steps)


def test_steps_are_grouped_by_suspicion_with_run_steps_first(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    _add(ledger, 0, "suspicion_raised", role="adversary", model="m", cost_usd=0.5,
         payload={"suspicion": _suspicion("S1")})
    _add(ledger, 1, "suspicion_raised", payload={"suspicion": _suspicion("S2")})
    _add(ledger, 2, "exploit_written", role="test_writer", model="m", cost_usd=0.25,
         payload={"suspicion_id": "S2", "test_path": "t2"})
    _add(ledger, 3, "exploit_written", role="test_writer", model="m", cost_usd=0.125,
         payload={"suspicion_id": "S1", "test_path": "t1"})
    _add(ledger, 4, "baseline_done", payload={"ok": True, "outcome": "passed"})
    steps = build_trace(ledger.path, RUN)
    assert [(g, [s.seq for s in members]) for g, members in groups(steps)] == [
        ("", [5]), ("S1", [1, 4]), ("S2", [2, 3]),
    ]
    data = trace_to_dict(RUN, steps)
    by_group = {g["suspicion_id"]: g["totals"]["cost_usd"] for g in data["groups"]}
    assert by_group == {"": 0.0, "S1": 0.625, "S2": 0.25}
    assert data["totals"]["cost_usd"] == ledger.totals(RUN)["cost_usd"] == 0.875


def test_failed_and_ablated_steps_are_described_plainly(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    _add(ledger, 0, "baseline_done", payload={"ok": False, "outcome": "failed"})
    _add(ledger, 1, "fix_proposed", payload={"suspicion_id": "S1", "applied": False, "error": "bad edit"})
    _add(ledger, 2, "bypass_result", payload={"suspicion_id": "S1", "name": "v", "bypassed": True})
    _add(ledger, 3, "bypass_result", payload={"suspicion_id": "S1", "name": "w", "error": True})
    _add(ledger, 4, "scan_done", payload={"status": "no_suspicions", "source_file": "a.py"})
    _add(ledger, 5, "pr_opened", payload={"number": 7})
    steps = {s.seq: s for s in build_trace(ledger.path, RUN)}
    assert steps[1].summary == "project baseline did not pass (failed)"
    assert steps[2].summary == "fix proposed but not applied: bad edit"
    assert steps[3].summary == "bypass v: BYPASSED the fix"
    assert steps[4].summary == "bypass w: could not run"
    assert steps[5].stage == "SCAN" and steps[6].stage == "INTAKE"


def test_unknown_run_gives_no_steps_and_a_clear_text(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    _full_run(ledger)
    assert build_trace(ledger.path, "nope") == []
    assert build_trace(tmp_path / "missing.jsonl", RUN) == []
    assert "no events for this run id" in render_text("nope", [])


def test_unordered_or_naive_timestamps_never_give_negative_wall_time(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    _add(ledger, 5, "baseline_done", payload={"ok": True})
    _add(ledger, 1, "baseline_done", payload={"ok": True})
    ledger.append({"ts": "not a time", "run_id": RUN, "type": "baseline_done", "payload": {}})
    ledger.append({"ts": "2026-01-01T00:00:09", "run_id": RUN, "type": "baseline_done", "payload": {}})
    steps = build_trace(ledger.path, RUN)
    assert [s.wall_ms for s in steps] == [None, None, None, None]
    assert totals(steps)["wall_ms"] == 0


# -- untrusted content ------------------------------------------------------------------------


def test_hostile_ledger_text_is_bounded_and_cannot_reach_the_terminal_raw(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    evil = "\x1b[2J\x1b]0;pwned\x07" + "A" * 10_000 + "\nINJECTED LINE\r\u2028"
    deep: object = "leaf"
    for _ in range(200):
        deep = {"k": deep}
    _add(ledger, 0, "suspicion_raised", role=evil, model=evil, payload={
        "suspicion": _suspicion(evil, hypothesis=evil, extra_list=list(range(1000)), deep=deep,
                                extra_map={str(i): i for i in range(1000)})})
    _add(ledger, 1, "verdict", payload={"suspicion_id": evil, "verdict": evil, "reason": evil,
                                        "fix_detail": evil})
    _add(ledger, 2, "oracle_event", payload={"suspicion_id": evil, "event": {
        "path": evil, "mode": evil, "stack": [{"f": evil}] * 500}, "run": evil})
    steps = build_trace(ledger.path, RUN)

    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for key, item in value.items():
                yield key
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)

    def depth(value):
        if isinstance(value, dict):
            return 1 + max((depth(v) for v in value.values()), default=0)
        if isinstance(value, list):
            return 1 + max((depth(v) for v in value), default=0)
        return 0

    for step in steps:
        for text in [step.role, step.model, step.suspicion_id, step.summary, *strings(step.details)]:
            assert len(text) <= MAX_STRING
            assert not any(ord(ch) < 32 or ord(ch) == 0x7F for ch in text)
        assert depth(step.details) <= MAX_DEPTH + 1
    details = steps[0].details["suspicion"]
    assert len(details["extra_list"]) == MAX_ITEMS + 1  # kept items plus one "more" marker
    assert len(details["extra_map"]) <= MAX_ITEMS + 1
    text = render_text(RUN, steps)
    assert "\x1b" not in text and "\x07" not in text and "\r" not in text
    # A newline inside model text cannot start a fake line of its own.
    assert not any(line.strip() == "INJECTED LINE" for line in text.splitlines())
    json.dumps(trace_to_dict(RUN, steps), allow_nan=False)


def test_ledger_content_is_never_evaluated(tmp_path):
    marker = tmp_path / "evaluated"
    code = f"__import__('pathlib').Path({str(marker)!r}).write_text('x')"
    ledger = Ledger(tmp_path / "l.jsonl")
    _add(ledger, 0, "suspicion_raised", payload={"suspicion": _suspicion(code, hypothesis=code)})
    _add(ledger, 1, "verdict", payload={"suspicion_id": code, "verdict": "{0.__class__}", "reason": "%s %(x)s {}"})
    steps = build_trace(ledger.path, RUN)
    render_text(RUN, steps)
    assert not marker.exists()
    assert steps[1].summary.startswith("verdict {0.__class__}: %s %(x)s {}")


def test_wrong_payload_types_do_not_break_the_trace(tmp_path):
    ledger = Ledger(tmp_path / "l.jsonl")
    for at, type_ in enumerate(("suspicion_raised", "oracle_event", "run_started", "verdict",
                                "bypass_result", "packaged", "scan_done", "baseline_done")):
        _add(ledger, at, type_, payload={"suspicion": 5, "event": [], "run": "x", "of": None,
                                         "verdict": 3, "reason": {}, "name": 7, "path": [],
                                         "suspicion_id": 9, "status": ["s"], "ok": "yes"})
    steps = build_trace(ledger.path, RUN)
    assert len(steps) == 8
    render_text(RUN, steps)


def test_a_run_with_too_many_events_is_refused(tmp_path, monkeypatch):
    import exhibit_a.ledger.trace as trace

    ledger = Ledger(tmp_path / "l.jsonl")
    for at in range(5):
        _add(ledger, at, "baseline_done", payload={"ok": True})
    monkeypatch.setattr(trace, "MAX_STEPS", 4)
    with pytest.raises(ValueError, match="more than 4 events"):
        trace.build_trace(ledger.path, RUN)
    assert MAX_STEPS == 20_000


# -- the CLI ----------------------------------------------------------------------------------


def test_cli_prints_aligned_text_by_default(tmp_path, capsys):
    ledger = Ledger(tmp_path / "l.jsonl")
    _full_run(ledger)
    assert main(["trace", "--ledger", str(ledger.path), RUN]) == 0
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert lines[0] == "trace of run run-1: 12 steps"
    header = next(line for line in lines if line.startswith("STEP"))
    assert header.index("STAGE") == next(l for l in lines if " BASELINE " in l).index("BASELINE")
    stages = [line.split()[1] for line in lines if line[:4].strip().isdigit()]
    assert stages == ["BASELINE", "SUSPECT", "EXPLOIT", "RUN", "RUN", "FIX", "VERIFY", "VERIFY",
                      "VERIFY", "VERIFY", "VERDICT", "PACKAGE"]
    assert "[run]" in lines and "[suspicion S1]" in lines
    total_line = next(line for line in lines if " TOTAL " in line)
    expected = Ledger(ledger.path).totals(RUN)
    assert f"{expected['cost_usd']:.6f}" in total_line
    assert str(expected["tokens_in"]) in total_line and str(expected["tokens_out"]) in total_line


def test_cli_json_matches_ledger_totals(tmp_path, capsys):
    ledger = Ledger(tmp_path / "l.jsonl")
    _full_run(ledger)
    assert main(["trace", "--ledger", str(ledger.path), RUN, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["run_id"] == RUN
    assert [s["seq"] for s in data["steps"]] == list(range(1, 13))
    expected = Ledger(ledger.path).totals(RUN)
    assert data["totals"]["cost_usd"] == expected["cost_usd"]
    assert data["totals"]["tokens_in"] == expected["tokens_in"]
    assert sum(g["totals"]["cost_usd"] for g in data["groups"]) == pytest.approx(expected["cost_usd"])
    assert set(data["steps"][1]) >= {"stage", "role", "model", "suspicion_id", "summary", "tokens_in",
                                     "tokens_out", "cost_usd", "latency_ms", "timestamp", "details"}


def test_cli_reports_a_corrupt_ledger_without_a_traceback(tmp_path, capsys):
    path = tmp_path / "l.jsonl"
    path.write_text("{not json\n", encoding="utf-8")
    assert main(["trace", "--ledger", str(path), RUN]) == 1
    captured = capsys.readouterr()
    assert "trace: cannot read" in captured.err and captured.out == ""


def test_cli_trace_of_an_unknown_run_is_not_an_error(tmp_path, capsys):
    ledger = Ledger(tmp_path / "l.jsonl")
    _full_run(ledger)
    assert main(["trace", "--ledger", str(ledger.path), "nope"]) == 0
    assert "no events for this run id" in capsys.readouterr().out


# -- demo script ------------------------------------------------------------------------------


def test_demo_script_prints_the_trace_of_each_replayed_case_without_mapfile():
    script = (ROOT / "scripts" / "demo.sh").read_text(encoding="utf-8")
    code = [line for line in script.splitlines() if not line.lstrip().startswith("#")]
    assert not any("mapfile" in line or "readarray" in line for line in code)
    assert "exhibit_a.cli trace --ledger" in script
    assert subprocess.run(["bash", "-n", str(ROOT / "scripts" / "demo.sh")]).returncode == 0


# -- a real replay ----------------------------------------------------------------------------


@pytest.mark.docker
@pytest.mark.parametrize("case_id", ["archive-extraction-pathtraversal", "starlette-cve-2023-29159"])
def test_trace_of_a_real_replay_shows_every_stage_and_sums_to_the_ledger(
    case_id, tmp_path, monkeypatch, capsys
):
    from bench.record_meta import replay_case

    monkeypatch.delenv("META_API_KEY", raising=False)
    out = tmp_path / "replay"
    outcome = replay_case(case_id, "muse-wonder-1.0", out, "compact")
    assert outcome.verdicts[0]["verdict"] == "proven"
    ledger_path = out / "ledger.jsonl"

    steps = build_trace(ledger_path, case_id)
    stages = [s.stage for s in steps]
    # The order of the loop: baseline, suspect, exploit, vulnerable runs, fix, verification,
    # the verdict and the package.
    assert stages[0] == "BASELINE" and stages[1] == "SUSPECT" and stages[2] == "EXPLOIT"
    assert stages.index("RUN") < stages.index("FIX") < stages.index("VERIFY") < stages.index("VERDICT")
    assert stages[-2:] == ["VERDICT", "PACKAGE"]
    assert [s.role for s in steps if s.role] == ["adversary", "test_writer", "fixer", "defender"]
    kinds = [s.type for s in steps]
    for kind in ("oracle_event", "bypass_attempt", "bypass_result"):
        assert kind in kinds
    assert any("on the fixed code" in s.summary for s in steps)
    assert all(s.suspicion_id in ("", "S1") for s in steps)

    # Costs and tokens add up to `exhibit-a ledger`, and to the recorded live cost.
    assert main(["ledger", "--ledger", str(ledger_path), case_id]) == 0
    ledger_totals = json.loads(capsys.readouterr().out)
    assert main(["trace", "--ledger", str(ledger_path), case_id, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["totals"]["cost_usd"] == ledger_totals["cost_usd"]
    assert data["totals"]["tokens_in"] == ledger_totals["tokens_in"]
    assert data["totals"]["tokens_out"] == ledger_totals["tokens_out"]
    assert sum(s["cost_usd"] for s in data["steps"]) == pytest.approx(ledger_totals["cost_usd"])
    meta = json.loads((ROOT / "bench" / "corpus" / case_id / "recordings"
                       / "meta-muse-wonder-1.0-compact.json").read_text(encoding="utf-8"))
    assert data["totals"]["cost_usd"] == pytest.approx(meta["cost_usd"], abs=1e-4)

    assert main(["trace", "--ledger", str(ledger_path), case_id]) == 0
    text = capsys.readouterr().out
    assert "[suspicion S1]" in text and "TOTAL" in text
