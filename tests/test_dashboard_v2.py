"""Dashboard v2 graph, trace, cost and endpoint contracts."""

from __future__ import annotations

from pathlib import Path

from exhibit_a.dashboard.model import build_graph_view
from exhibit_a.dashboard.sources import RunData, RunRef
from exhibit_a.schemas import Event
from test_dashboard_support import api, local_state, make_samples


def _event(run_id: str, kind: str, payload: dict) -> Event:
    return Event.model_validate(
        {"ts": "2026-10-31T12:00:00Z", "run_id": run_id, "type": kind, "payload": payload}
    )


def test_synthetic_graph_view_marks_entry_and_proven_sink(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "class App:\n"
        "    def handle_request(self, name):\n"
        "        return self.read(name)\n"
        "    def read(self, name):\n"
        "        return open(name).read()\n",
        encoding="utf-8",
    )
    events = [
        _event("graph-run", "suspicion_raised", {"suspicion": {
            "id": "S1", "class": "path-traversal", "entry_point": "App.handle_request",
            "location": {"file": "app.py", "line": 5},
        }}),
        _event("graph-run", "verdict", {"suspicion_id": "S1", "verdict": "proven"}),
    ]
    view = build_graph_view(RunData(RunRef("graph-run"), events=events, tree=tmp_path))
    assert view["available"] is True
    assert len(view["paths"]) == 1
    assert view["paths"][0]["entry_point"] == "App.handle_request"
    assert view["paths"][0]["sink"] == "builtins.open"
    assert any(node["entry_point"] for node in view["nodes"])
    assert any(node["sink"] for node in view["nodes"])
    assert "canary_read" in view["effects"]


def test_run_detail_exposes_trace_costs_and_graph_endpoints(tmp_path: Path):
    state = local_state(make_samples(tmp_path))
    run_id = "synthetic-01-starlette-proven"
    status, _, detail = api(state, f"/api/runs/{run_id}")
    assert status == 200
    assert detail["trace"]["steps"]
    assert "by_role" in detail["costs"] and "by_stage" in detail["costs"]
    assert "graph" in detail
    assert detail["proven"][0]["evidence"]["cwe"] == ""

    for suffix, key in (("/trace", "steps"), ("/costs", "by_role"), ("/graph", "nodes")):
        status, _, payload = api(state, f"/api/runs/{run_id}{suffix}")
        assert status == 200 and key in payload


def test_all_effect_labels_are_exposed_without_frontend_hard_coding(tmp_path: Path):
    state = local_state(make_samples(tmp_path))
    status, _, graph = api(state, "/api/runs/synthetic-01-starlette-proven/graph")
    assert status == 200
    assert graph["effects"] == ["canary_read", "canary_write", "canary_exec"]
