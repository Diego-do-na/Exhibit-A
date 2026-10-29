"""Dashboard view-models: rows, run detail evidence, stages, trends, wording, display caps."""

from __future__ import annotations

import json

from exhibit_a.dashboard import model
from exhibit_a.dashboard.model import STAGES, build_trends, clean, event_line, run_detail, run_row, stage_of
from exhibit_a.dashboard.sources import LocalRunsSource, RunData, RunRef, parse_ledger
from exhibit_a.schemas import Event
from test_dashboard_support import ROOT, make_samples


def rows_by_id(source):
    return {ref.run_id: run_row(source.load_run(ref.run_id)) for ref in source.list_runs()}


def test_rows_summarise_every_sample_outcome(tmp_path):
    rows = rows_by_id(LocalRunsSource(make_samples(tmp_path)))
    proven = rows["synthetic-01-starlette-proven"]
    assert proven["status"] == "completed" and proven["proven"] == 1
    assert proven["headline"] == "1 proven finding"
    assert proven["risk"] == "high" and proven["pr"] == "41" and proven["synthetic"] is True
    assert proven["duration_s"] > 0 and proven["cost_usd"] > 0
    assert proven["verdicts"]["discarded_unproven"] == 1 and proven["verdicts"]["invalid_test"] == 1
    assert rows["synthetic-02-starlette-fixed"]["headline"] == "Nothing could be proven"
    assert rows["synthetic-05-aborted-baseline"]["status"] == "aborted"
    assert rows["synthetic-06-skipped-docs"]["status"] == "skipped"
    assert rows["synthetic-06-skipped-docs"]["risk"] == "low"
    flaky = rows["synthetic-07-flaky-env"]
    assert flaky["verdicts"]["flaky"] == 1 and flaky["verdicts"]["env_failure"] == 1 and flaky["proven"] == 0


def test_no_headline_ever_says_safe(tmp_path):
    rows = rows_by_id(LocalRunsSource(make_samples(tmp_path)))
    for row in rows.values():
        assert "safe" not in row["headline"].lower()
        if row["proven"] == 0:
            assert "nothing could be proven" in row["headline"].lower()
    unreadable = run_row(RunData(ref=RunRef("x"), error="bad"))
    assert unreadable["status"] == "unreadable" and "safe" not in unreadable["headline"].lower()


def test_stages_follow_the_loop_order(tmp_path):
    source = LocalRunsSource(make_samples(tmp_path))
    detail = run_detail(source.load_run("synthetic-01-starlette-proven"))
    assert [s["name"] for s in detail["stages"]] == list(STAGES)
    assert all(s["reached"] for s in detail["stages"])
    firsts = [s["first_seq"] for s in detail["stages"]]
    assert firsts == sorted(firsts)
    aborted = run_detail(source.load_run("synthetic-05-aborted-baseline"))
    assert [s["name"] for s in aborted["stages"] if s["reached"]] == ["BASELINE"]


def test_proven_starlette_evidence_is_a_canary_read_with_provenance(tmp_path):
    source = LocalRunsSource(make_samples(tmp_path))
    detail = run_detail(source.load_run("synthetic-01-starlette-proven"))
    [finding] = detail["proven"]
    ev = finding["evidence"]
    assert ev["fails_on_vulnerable"] == {"runs": 3, "of": 3, "oracle_events": 3}
    assert ev["effect"]["type"] == "canary_read"
    entry = [f for f in ev["provenance"]["frames"] if f["entry_point"]]
    assert [f["qualname"] for f in entry] == ["StaticFiles.get_response"]
    assert ev["passes_on_fixed"] == {"runs": 3, "effect_seen_after_fix": False, "baseline_ok": True, "fix_verified": True}
    assert ev["bypass"]["tried"] == 2 and ev["bypass"]["succeeded"] == 0
    assert {d["id"]: d["verdict"] for d in detail["discarded"]} == {"S2": "discarded_unproven", "S3": "invalid_test"}


def test_archive_evidence_is_a_canary_write_and_reports_the_bypass(tmp_path):
    source = LocalRunsSource(make_samples(tmp_path))
    ev = run_detail(source.load_run("synthetic-04-archive-incomplete-fix"))["proven"][0]["evidence"]
    assert ev["effect"]["type"] == "canary_write" and ev["effect"]["mode"] == "xb"
    assert ev["bypass"]["succeeded"] == 1
    assert [v["name"] for v in ev["bypass"]["variants"] if v["bypassed"]] == ["absolute member name"]


def test_live_view_sample_ledger_shape_is_understood():
    events = parse_ledger((ROOT / "web" / "sample-ledger.jsonl").read_bytes())
    detail = run_detail(RunData(ref=RunRef("demo"), events=events))
    assert detail["run"]["proven"] == 1
    ev = detail["proven"][0]["evidence"]
    assert ev["fails_on_vulnerable"]["runs"] == 1
    assert ev["effect"]["observed"] is True
    assert ev["provenance"]["entry_point"] == "read_note"
    assert ev["package"] == "runs/demo-r1/package"
    assert [d["id"] for d in detail["discarded"]] == ["S2"]


def test_a_later_verdict_replaces_an_earlier_one():
    lines = [
        {"ts": "2026-10-20T10:00:00Z", "run_id": "r", "type": "baseline_done", "payload": {"ok": True}},
        {"ts": "2026-10-20T10:00:01Z", "run_id": "r", "type": "verdict", "payload": {"suspicion_id": "S1", "verdict": "flaky"}},
        {"ts": "2026-10-20T10:00:02Z", "run_id": "r", "type": "verdict", "payload": {"suspicion_id": "S1", "verdict": "discarded_unproven"}},
    ]
    events = [Event.model_validate(line) for line in lines]
    detail = run_detail(RunData(ref=RunRef("r"), events=events))
    assert [d["verdict"] for d in detail["discarded"]] == ["discarded_unproven"]


def test_hostile_payload_shapes_make_the_run_unreadable_not_partial():
    events = [Event.model_validate({"ts": "t", "run_id": "r", "type": "baseline_done", "payload": {"ok": True, "flags": "naive"}})]
    detail = run_detail(RunData(ref=RunRef("r"), events=events))
    assert detail["run"]["status"] == "unreadable" and detail["proven"] == [] and detail["discarded"] == []


def test_mistyped_payload_values_do_not_crash():
    weird = {"suspicion_id": ["S1"], "verdict": {"x": 1}, "run": "1", "of": None, "event": "not a dict", "name": 5}
    for kind in ("pr_opened", "scan_done", "baseline_done", "suspicion_raised", "exploit_written", "run_started",
                 "oracle_event", "verdict", "fix_proposed", "bypass_attempt", "bypass_result", "packaged"):
        event = Event.model_validate({"ts": "t", "run_id": "r", "type": kind, "payload": weird})
        assert isinstance(event_line(event), str)
        stage_of(event)
    run_detail(RunData(ref=RunRef("r"), events=[Event.model_validate({"ts": "t", "run_id": "r", "type": "verdict", "payload": weird})]))


def test_clean_bounds_strings_items_and_depth():
    deep: dict = {}
    cursor = deep
    for _ in range(20):
        cursor["k"] = {}
        cursor = cursor["k"]
    cleaned = clean({"s": "x" * 10_000, "l": list(range(1000)), "d": deep})
    assert len(cleaned["s"]) == model.MAX_STRING
    assert len(cleaned["l"]) == model.MAX_ITEMS
    assert "…" in json.dumps(cleaned["d"], ensure_ascii=False)


def test_trends_are_oldest_first_and_skip_unreadable(tmp_path):
    rows = list(rows_by_id(LocalRunsSource(make_samples(tmp_path))).values())
    rows.append(run_row(RunData(ref=RunRef("broken", started_at="2027-01-01"), error="bad")))
    points = build_trends(rows)
    assert len(points) == 10
    assert [p["started_at"] for p in points] == sorted(p["started_at"] for p in points)
    assert sum(p["proven"] for p in points) == 5
    assert all(set(model.TREND_VERDICTS) <= set(p) for p in points)
