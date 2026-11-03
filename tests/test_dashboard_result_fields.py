"""Dashboard reads the artifact-schema fields when the artifact carries them.

`result.json` may carry `provider`, `discussion_url` and `graph_summary`
(artifact-schema.md); `graph-summary.json` may also arrive as a top-level
zip/folder entry. The dashboard uses them only when they validate, and
keeps "not recorded" (""/None) for what is truly absent.
"""

from __future__ import annotations

from exhibit_a.dashboard.model import run_detail, run_row
from exhibit_a.dashboard.sources import (
    RunData,
    RunRef,
    parse_graph_summary,
    parse_result,
    valid_discussion_url,
)
from exhibit_a.schemas import Event

THREAD = "https://github.com/acme/app/pull/7#discussion_r123"


def _event(kind: str, payload: dict | None = None) -> Event:
    return Event.model_validate(
        {"ts": "2026-11-03T10:00:00Z", "run_id": "r", "type": kind,
         "payload": payload if payload is not None else {}}
    )


def _result(**over: object) -> bytes:
    import json

    base: dict[str, object] = {
        "schema_version": "1",
        "run_id": "r",
        "status": "completed",
    }
    base.update(over)
    return json.dumps(base).encode()


def test_parse_result_keeps_schema_fields():
    parsed = parse_result(_result(provider="meta", discussion_url=THREAD))
    assert parsed["provider"] == "meta"
    assert parsed["discussion_url"] == THREAD


def test_parse_result_drops_a_malformed_thread_url():
    parsed = parse_result(_result(discussion_url="https://example.com/x"))
    assert parsed["discussion_url"] == ""


def test_parse_result_treats_explicit_nulls_as_not_recorded():
    parsed = parse_result(_result(provider=None, discussion_url=None))
    assert parsed["provider"] == ""
    assert parsed["discussion_url"] == ""


def test_parse_graph_summary_treats_explicit_nulls_as_not_recorded():
    summary = parse_graph_summary({"schema_version": "1", "available": True,
                                   "status": None, "effect": None,
                                   "stats": {"files": 2}, "entries": [None, "a.py"]})
    assert summary["status"] == ""
    assert summary["effect"] == ""
    assert summary["entries"] == ["a.py"]


def test_valid_discussion_url_matches_repo_and_pr():
    assert valid_discussion_url(THREAD, "acme/app", "7") == THREAD
    assert valid_discussion_url(THREAD, "acme/app", "#7") == THREAD
    # Same thread shape, another repository or PR: dropped, never borrowed.
    assert valid_discussion_url(THREAD, "acme/other", "7") == ""
    assert valid_discussion_url(THREAD, "acme/app", "8") == ""
    assert valid_discussion_url("https://github.com/acme/app/pull/7", "acme/app", "7") == ""
    assert valid_discussion_url("", "acme/app", "7") == ""


def test_parse_graph_summary_rejects_garbage():
    assert parse_graph_summary(None) == {}
    assert parse_graph_summary([]) == {}
    assert parse_graph_summary({"available": False}) == {}


def test_run_row_uses_result_provider_and_thread_url():
    ref = RunRef("r", repo="acme/app", pr="7")
    events = [_event("baseline_done", {"ok": True})]
    row = run_row(RunData(ref=ref, events=events,
                          result=parse_result(_result(provider="meta", discussion_url=THREAD))))
    assert row["provider"] == "meta"
    assert row["discussion_url"] == THREAD


def test_run_row_falls_back_when_thread_url_names_another_pr():
    ref = RunRef("r", repo="acme/app", pr="9")
    events = [_event("baseline_done", {"ok": True})]
    row = run_row(RunData(ref=ref, events=events,
                          result=parse_result(_result(discussion_url=THREAD))))
    assert row["provider"] == ""
    assert row["discussion_url"] == "https://github.com/acme/app/pull/9"


def test_run_detail_exposes_provider_and_graph_summary():
    ref = RunRef("r", repo="acme/app", pr="7")
    events = [_event("baseline_done", {"ok": True})]
    data = RunData(ref=ref, events=events,
                   result=parse_result(_result(provider="meta", discussion_url=THREAD)),
                   graph_summary={"available": True, "status": "sliced"})
    detail = run_detail(data)
    assert detail["provider"] == "meta"
    assert detail["run"]["discussion_url"] == THREAD
    assert detail["graph_summary"] == {"available": True, "status": "sliced"}


def test_artifact_zip_carries_graph_summary():
    import io
    import json
    import zipfile

    from exhibit_a.dashboard.sources import _parse_summary_text, read_artifact_texts

    blob = io.BytesIO()
    with zipfile.ZipFile(blob, "w") as archive:
        archive.writestr("ledger.jsonl", "{}\n")
        archive.writestr("graph-summary.json", json.dumps(
            {"schema_version": "1", "available": True, "status": "sliced",
             "paths": [{"path": "a -> b", "entry_point": "ep"}]}))
    texts = read_artifact_texts(blob.getvalue())
    assert "graph-summary.json" in texts
    summary = _parse_summary_text(texts["graph-summary.json"])
    assert summary["available"] is True
    assert summary["paths"] == [{"path": "a -> b", "entry_point": "ep"}]


def test_local_run_reads_graph_summary_file(tmp_path):
    import json

    from exhibit_a.dashboard.sources import LocalRunsSource

    folder = tmp_path / "runs" / "r123"
    folder.mkdir(parents=True)
    (folder / "ledger.jsonl").write_text(
        '{"ts": "2026-11-03T10:00:00Z", "run_id": "r123", "type": "baseline_done",'
        ' "role": "", "model": "", "tokens_in": 0, "tokens_out": 0,'
        ' "cost_usd": 0.0, "latency_ms": 0, "payload": {"ok": true}}\n')
    (folder / "graph-summary.json").write_text(json.dumps(
        {"schema_version": "1", "available": True, "status": "sliced"}))
    data = LocalRunsSource(tmp_path / "runs").load_run("r123")
    assert data.error == ""
    assert data.graph_summary.get("available") is True
