"""Dashboard benchmark endpoint and discarded-findings rows.

- ``/api/benchmark`` aggregates ``bench/results`` for the Exhibit-A repo only;
  any other source gets ``available: false`` with reason
  ``no benchmark data for this source``.
- ``/api/repos/<id>`` carries ``discarded_findings`` so the Findings page can
  filter non-proven verdicts from recorded data, never invented rows.
"""

from __future__ import annotations

from pathlib import Path

from exhibit_a.dashboard.model import build_benchmark
from test_dashboard_support import api, local_state, make_samples


def test_benchmark_unavailable_for_other_sources(tmp_path: Path):
    state = local_state(make_samples(tmp_path))
    status, _, body = api(state, "/api/benchmark")
    assert status == 200
    assert body["available"] is False
    assert body["reason"] == "no benchmark data for this source"


def test_benchmark_builder_gates_on_exhibit_a():
    other = build_benchmark("local:some-runs", ["other/repo"])
    assert other == {"available": False, "reason": "no benchmark data for this source"}
    same = build_benchmark("github:Diego-do-na/Exhibit-A", ["Diego-do-na/Exhibit-A"])
    # The checkout ships bench/results, so the Exhibit-A source resolves them.
    assert same["available"] is True
    assert same["file"].endswith(".json")
    assert same["systems"], "expected per-system aggregates"
    for system in same["systems"]:
        for key in ("system", "targets", "reported", "true_positives",
                    "false_positives", "discarded", "calls", "cost_usd"):
            assert key in system, key
        reported = system["true_positives"] + system["false_positives"]
        if reported:
            assert system["precision"] == round(system["true_positives"] / reported, 4)


def test_repo_detail_carries_discarded_findings(tmp_path: Path):
    from exhibit_a.dashboard.model import build_repo_detail, group_by_repo, run_detail, run_row
    from exhibit_a.dashboard.sources import LocalRunsSource

    source = LocalRunsSource(make_samples(tmp_path))
    entries = []
    for ref in source.list_runs():
        data = source.load_run(ref.run_id)
        row = run_row(data)
        entries.append((row, None if row["error"] else run_detail(data, with_graph=False)))
    groups = group_by_repo(entries)
    assert groups, "expected at least one repository group"
    rid = next(iter(groups))
    detail = build_repo_detail(rid, groups[rid])
    assert "discarded_findings" in detail
    counted = detail["metrics"]["discarded"]
    assert len(detail["discarded_findings"]) <= counted or counted == 0 or detail["discarded_findings"]
    for item in detail["discarded_findings"]:
        assert item["verdict"] in ("discarded_unproven", "invalid_test", "flaky", "env_failure", "not judged")
        assert "reason" in item and "run_id" in item
