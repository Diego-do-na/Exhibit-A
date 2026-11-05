"""Dashboard API: per-source data and real costs.

Every figure the dashboard shows must be derived only from the ledger and
the run artifacts, validated with schemas, and never executed. Anything the
ledger does not record (provider, budget cap, base SHA, missing proof
artifacts) surfaces as "" or null and the UI hides the card.

The ``memos`` fixture below mirrors the shape of the real Action run
``41650269331`` of ``github:Diego-do-na/exhibit-a-testbed`` (1 proven
finding in ``memos.py`` for about US$0.063, model ``muse-wonder-1.0`` across
the four roles), so the suite pins the exact totals that run reported.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

from exhibit_a.dashboard.sources import GitHubSource
from test_dashboard_sources import FakeGh, artifact, artifact_zip, gh_listing
from test_dashboard_support import ROOT, api, local_state, make_state

WEB_DIR = ROOT / "web" / "dashboard"

#: Role, model, cost and tokens of the four model calls in run 41650269331.
ROLE_CALLS = [
    ("suspicion_raised", "adversary", "muse-wonder-1.0", 0.007396, 774, 215),
    ("exploit_written", "test_writer", "muse-wonder-1.0", 0.006836, 819, 178),
    ("fix_proposed", "fixer", "muse-wonder-1.0", 0.007364, 831, 202),
    ("bypass_attempt", "defender", "muse-wonder-1.0", 0.041288, 1037, 1857),
]

SUSPICION = {
    "id": "path-traversal-1",
    "class": "path_traversal",
    "location": {"file": "memos.py", "line": 34},
    "entry_point": "App.handle_request",
    "hypothesis": "Attacker-controlled memo name containing ../ escapes shelf_dir.",
}


def _event(run_id, seq, type_, role="", model="", cost=0.0, tin=0, tout=0, **payload):
    return {
        "ts": f"2026-11-03T14:05:{seq:02d}Z",
        "run_id": run_id,
        "type": type_,
        "role": role,
        "model": model,
        "tokens_in": tin,
        "tokens_out": tout,
        "cost_usd": cost,
        "latency_ms": 0,
        "payload": payload,
    }


def memos_ledger(run_id="pr-b30106f658c3"):
    """Ledger shaped like run 41650269331: 1 proven canary_read in memos.py."""
    oracle = {
        "type": "canary_read",
        "path": "/tmp/exhibit_a_oracle/outside/canary.txt",
        "mode": "r",
        "stack": [{"file": "memos.py", "function": "read_text", "qualname": "read_text",
                   "line": 22, "admitted": True}],
    }
    events = [
        _event(run_id, 1, "baseline_done", ok=True, outcome="passed",
               flags={"naive": False, "oracle": True, "differential": True, "defender": True}),
        _event(run_id, 2, "scan_done", status="sliced", source_file="memos.py"),
        _event(run_id, 3, "suspicion_raised", *ROLE_CALLS[0][1:], suspicion=SUSPICION),
        _event(run_id, 4, "exploit_written", *ROLE_CALLS[1][1:], suspicion_id="path-traversal-1",
               test_path="work/path-traversal-1/tests/test_exploit.py"),
        _event(run_id, 8, "fix_proposed", *ROLE_CALLS[2][1:], suspicion_id="path-traversal-1", applied=True),
        _event(run_id, 12, "baseline_done", suspicion_id="path-traversal-1", on="fixed", ok=True),
        _event(run_id, 13, "bypass_attempt", *ROLE_CALLS[3][1:], suspicion_id="path-traversal-1",
               name="absolute_canary_path"),
        _event(run_id, 14, "bypass_result", suspicion_id="path-traversal-1",
               name="absolute_canary_path", bypassed=False),
        _event(run_id, 15, "verdict", suspicion_id="path-traversal-1", verdict="proven",
               reason="canary read by application code reached through an entry point",
               reason_code="", effect="canary_read", fix_verified=True, fix_incomplete=False),
        _event(run_id, 16, "packaged", suspicion_id="path-traversal-1",
               path="packages/path-traversal-1", fix_verified=True, fix_incomplete=False),
    ]
    for run in (5, 6, 7):
        events.append(_event(run_id, run, "run_started", suspicion_id="path-traversal-1",
                             run=run - 4, of=3))
        events.append(_event(run_id, run, "oracle_event", suspicion_id="path-traversal-1",
                             run=run - 4, event=oracle))
    return "\n".join(json.dumps(e) for e in sorted(events, key=lambda e: e["ts"])) + "\n"


def memos_result(run_id="pr-b30106f658c3"):
    return {"schema_version": "1", "run_id": run_id, "status": "completed"}


def write_memos_run(root: Path, name="run-memos", with_artifacts=True):
    folder = root / name
    (folder / "packages" / "path-traversal-1").mkdir(parents=True)
    (folder / "ledger.jsonl").write_text(memos_ledger())
    (folder / "result.json").write_text(json.dumps(memos_result()))
    if with_artifacts:
        (folder / "packages" / "path-traversal-1" / "fix.patch").write_text(
            "--- a/memos.py\n+++ b/memos.py\n@@ good fix\n")
        (folder / "packages" / "path-traversal-1" / "test_exploit.py").write_text(
            "def test_traversal():\n    pass\n")
    return folder


# -- /api/info -----------------------------------------------------------------


def test_info_names_source_kind_and_marks_budget_not_recorded(tmp_path):
    from exhibit_a.dashboard.sources import LocalRunsSource

    write_memos_run(tmp_path)
    status, _, body = api(make_state(LocalRunsSource(tmp_path)), "/api/info")
    assert status == 200
    assert body["source"].startswith("local:")
    assert body["source_kind"] == "local"
    assert body["artifact"] is None
    assert body["budget_usd"] is None  # no budget cap is stored in any ledger


# -- /api/runs and /api/runs/<id> ----------------------------------------------


def test_run_row_carries_identity_cost_and_models(tmp_path):
    from exhibit_a.dashboard.sources import LocalRunsSource

    write_memos_run(tmp_path)
    status, _, body = api(make_state(LocalRunsSource(tmp_path)), "/api/runs")
    assert status == 200
    (row,) = body["runs"]
    assert row["proven"] == 1 and row["status"] == "completed"
    assert row["head_sha"] == row["commit"]
    assert row["base_sha"] == ""  # the ledger records no base SHA: not recorded
    assert row["discussion_url"] == ""  # no repo/PR recorded locally: not recorded
    assert row["models"] == ["muse-wonder-1.0"]
    assert row["provider"] == ""  # the ledger records no provider: not recorded
    assert row["cost_usd"] == 0.062884
    assert row["tokens_in"] == 3461 and row["tokens_out"] == 2452


def test_run_detail_reports_real_costs_reasons_and_artifacts(tmp_path):
    from exhibit_a.dashboard.sources import LocalRunsSource

    write_memos_run(tmp_path)
    status, _, body = api(make_state(LocalRunsSource(tmp_path)), "/api/runs/run-memos")
    assert status == 200
    by_role = body["costs"]["by_role"]
    assert set(by_role) >= {"adversary", "test_writer", "fixer", "defender"}
    assert by_role["defender"]["tokens_in"] == 1037
    assert by_role["defender"]["tokens_out"] == 1857
    assert by_role["adversary"]["models"] == ["muse-wonder-1.0"]
    assert body["costs"]["by_model"]["muse-wonder-1.0"]["cost_usd"] == 0.062884
    assert body["provider"] == "" and body["budget_usd"] is None
    assert body["artifacts"]["fix_patch"].startswith("--- a/memos.py")
    assert body["artifacts"]["exploit_test"].startswith("def test_traversal")
    assert body["run"]["duration_s"] is not None
    assert body["run"]["files_touched"] == ["memos.py"]


def test_missing_artifacts_are_not_recorded_not_invented(tmp_path):
    from exhibit_a.dashboard.sources import LocalRunsSource

    write_memos_run(tmp_path, with_artifacts=False)
    _, _, body = api(make_state(LocalRunsSource(tmp_path)), "/api/runs/run-memos")
    assert body["artifacts"] == {"fix_patch": None, "exploit_test": None}


def test_discharged_verdicts_keep_their_recorded_reason(tmp_path):
    from exhibit_a.dashboard.sources import LocalRunsSource

    lines = [
        json.dumps(_event("r", 1, "baseline_done", ok=True)),
        json.dumps(_event("r", 2, "suspicion_raised", "adversary", "m", 0.001, 10, 5,
                           suspicion={"id": "S1", "class": "x",
                                      "location": {"file": "a.py", "line": 1},
                                      "entry_point": "e", "hypothesis": "h"})),
        json.dumps(_event("r", 3, "verdict", suspicion_id="S1", verdict="env_failure",
                           reason="sandbox could not start", reason_code="sandbox_unreachable",
                           effect="canary_read")),
    ]
    folder = tmp_path / "run-env"
    folder.mkdir()
    (folder / "ledger.jsonl").write_text("\n".join(lines) + "\n")
    (folder / "result.json").write_text(json.dumps(memos_result("r")))
    _, _, body = api(make_state(LocalRunsSource(tmp_path)), "/api/runs/run-env")
    (item,) = body["discarded"]
    assert (item["verdict"], item["reason"]) == ("env_failure", "sandbox could not start")
    assert item["reason_code"] == "sandbox_unreachable" and item["effect"] == "canary_read"


def test_result_json_overlay_fills_base_sha_provider_model_budget(tmp_path):
    from exhibit_a.dashboard.sources import LocalRunsSource

    folder = write_memos_run(tmp_path)
    extra = memos_result()
    extra.update(provider="meta", model="muse-wonder-1.0",
                 base_sha="868c371832071a7ef38280a9fd66ac28a3ad", budget_usd=8.0)
    (folder / "result.json").write_text(json.dumps(extra))
    state = make_state(LocalRunsSource(tmp_path))
    _, _, runs = api(state, "/api/runs")
    (row,) = runs["runs"]
    assert row["base_sha"] == "868c371832071a7ef38280a9fd66ac28a3ad"
    assert row["provider"] == "meta"
    assert row["model"] == "muse-wonder-1.0"
    assert row["budget_usd"] == 8.0
    _, _, detail = api(state, "/api/runs/run-memos")
    assert detail["provider"] == "meta"
    assert detail["model"] == "muse-wonder-1.0"
    assert detail["budget_usd"] == 8.0
    _, _, repos = api(state, "/api/repos")
    (entry,) = repos["repos"]
    _, _, body = api(state, f"/api/repos/{entry['id']}")
    assert body["budget_usd"] == 8.0


def test_base_sha_is_recorded_when_the_ledger_has_it(tmp_path):
    from exhibit_a.dashboard.sources import LocalRunsSource

    folder = write_memos_run(tmp_path)
    first = {"ts": "2026-11-03T14:05:00Z", "run_id": "pr-b30106f658c3", "type": "pr_opened",
             "role": "", "model": "", "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0,
             "latency_ms": 0,
             "payload": {"repo": "acme/app", "pr": "7", "commit": "b30106f658c3",
                         "base": "868c371832071a7ef38280a9fd66ac28a3ad", "branch": "vuln/x"}}
    ledger = json.dumps(first) + "\n" + (folder / "ledger.jsonl").read_text()
    (folder / "ledger.jsonl").write_text(ledger)
    _, _, body = api(make_state(LocalRunsSource(tmp_path)), "/api/runs")
    (row,) = body["runs"]
    assert row["base_sha"] == "868c371832071a7ef38280a9fd66ac28a3ad"
    assert row["discussion_url"] == "https://github.com/acme/app/pull/7"


def test_discussion_url_is_never_built_from_untrusted_repo_text():
    from exhibit_a.dashboard.model import _discussion_url

    assert _discussion_url("example-org/starlette-app (synthetic)", "41") == ""
    assert _discussion_url("https://evil.example/x", "7") == ""
    assert _discussion_url("acme/app", "not-a-number") == ""
    assert _discussion_url("", "7") == ""


# -- GitHub source: the testbed run through a fake gh --------------------------


def make_testbed_responses():
    run_id, art_id = 41650269331, 13237810045
    ledger = memos_ledger().encode()
    blob = io.BytesIO()
    with zipfile.ZipFile(blob, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("ledger.jsonl", ledger)
        archive.writestr("result.json", json.dumps(memos_result()).encode())
        archive.writestr("summary.md", b"# Exhibit A\n")
    return {
        "repos/Diego-do-na/exhibit-a-testbed/actions/artifacts": gh_listing(
            artifact(art_id, run_id)),
        f"repos/Diego-do-na/exhibit-a-testbed/actions/runs/{run_id}": json.dumps(
            {"id": run_id, "head_sha": "b30106f658c37804bd29bfe9758c417ea7cda3e1",
             "head_branch": "vuln/nested-memos",
             "pull_requests": [{"number": 1}],
             "run_started_at": "2026-11-03T14:05:25Z"}).encode(),
        f"repos/Diego-do-na/exhibit-a-testbed/actions/artifacts/{art_id}/zip": blob.getvalue(),
    }


def test_github_testbed_run_reports_recorded_costs_and_links():
    source = GitHubSource("Diego-do-na/exhibit-a-testbed", gh=FakeGh(make_testbed_responses()))
    state = make_state(source)
    status, _, body = api(state, "/api/runs/41650269331")
    assert status == 200
    assert body["run"]["proven"] == 1
    assert body["run"]["discussion_url"] == \
        "https://github.com/Diego-do-na/exhibit-a-testbed/pull/1"
    assert body["run"]["models"] == ["muse-wonder-1.0"]
    assert body["run"]["cost_usd"] == 0.062884
    assert body["artifacts"] == {"fix_patch": None, "exploit_test": None}
    status, _, info = api(state, "/api/info")
    assert info["source_kind"] == "github" and info["artifact"] == "exhibit-a-ledger"


def test_repo_page_windows_newest_runs_and_reports_has_more():
    from exhibit_a.dashboard.sources import GhError

    blob = artifact_zip({
        "ledger.jsonl": memos_ledger().encode(),
        "result.json": json.dumps(memos_result()).encode(),
    })
    responses = {
        "repos/acme/app/actions/artifacts": gh_listing(artifact(21, 601), artifact(22, 602)),
        "repos/acme/app/actions/runs/601": json.dumps(
            {"id": 601, "head_sha": "abcdef1234567", "head_branch": "a",
             "pull_requests": [{"number": 1}]}).encode(),
        "repos/acme/app/actions/runs/602": json.dumps(
            {"id": 602, "head_sha": "abcdef1234568", "head_branch": "b",
             "pull_requests": [{"number": 2}]}).encode(),
        "repos/acme/app/actions/artifacts/21/zip": blob,
        "repos/acme/app/actions/artifacts/22/zip": blob,
        "pr list acme/app": b"[]",
        "repos/acme/app/contents/.exhibit-a/authors.yml": GhError("HTTP 404"),
    }
    gh = FakeGh(responses)
    state = make_state(GitHubSource("acme/app", gh=gh))
    _, _, body = api(state, "/api/repos?limit=1")
    assert body["has_more"] is True
    assert body["runs_considered"] == 1 and body["runs_total"] == 2
    zips = sum(1 for c in gh.calls if c[0][-1].endswith("/zip"))
    infos = sum(1 for c in gh.calls if "/actions/runs/" in " ".join(c[0]))
    assert zips == 1 and infos == 0
    _, _, more = api(state, "/api/repos?limit=2")
    assert more["has_more"] is False
    assert more["runs_considered"] == 2


# -- repository aggregates ------------------------------------------------------


def test_repo_detail_aggregates_rates_costs_and_cumulative(tmp_path):
    from exhibit_a.dashboard.sources import LocalRunsSource

    write_memos_run(tmp_path, "run-a")
    write_memos_run(tmp_path, "run-b", with_artifacts=False)
    state = make_state(LocalRunsSource(tmp_path))
    _, _, repos = api(state, "/api/repos")
    (entry,) = repos["repos"]
    _, _, body = api(state, f"/api/repos/{entry['id']}")
    metrics = body["metrics"]
    assert metrics["runs"] == 2 and metrics["proven"] == 2
    assert metrics["proven_rate"] == 1.0
    assert metrics["cost_usd"] == 0.125768
    assert metrics["cost_per_run"] == 0.062884
    assert metrics["cost_per_proven"] == 0.062884
    assert body["budget_usd"] is None
    assert body["cost_by_role"]["defender"]["cost_usd"] == 0.082576
    assert body["cost_by_role"]["adversary"]["models"] == ["muse-wonder-1.0"]
    assert body["cost_by_model"]["muse-wonder-1.0"]["tokens_in"] == 6922
    series = body["run_series"]
    assert [p["cumulative_cost_usd"] for p in series] == [0.062884, 0.125768]
    assert all("by_role" in p for p in series)


# -- economics page contract ----------------------------------------------------


def test_overview_donut_draws_a_full_ring_for_a_single_category():
    # A 100% slice starts and ends at the same point, which SVG renders as
    # nothing; the builder must stop a hair short, as fullchart.js does.
    js = (WEB_DIR / "views" / "index.js").read_text(encoding="utf-8")
    assert "0.001" in js


def test_overview_paints_a_skeleton_and_offers_load_more():
    js = (WEB_DIR / "views" / "index.js").read_text(encoding="utf-8")
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    css = (WEB_DIR / "dashboard.css").read_text(encoding="utf-8")
    assert "Load more" in html and "has_more" in js and "loadMore" in js
    assert 'aria-busy="true"' in html
    assert ".sk{" in css.replace(" ", "") or ".sk {" in css or "@keyframes xa-sk" in css


def test_economics_page_is_dynamic_and_marks_gaps():
    js = (WEB_DIR / "views" / "economics.js").read_text(encoding="utf-8")
    html = (WEB_DIR / "economics.html").read_text(encoding="utf-8")
    assert "fetch('/api/repos'" in js or 'fetch("/api/repos"' in js
    assert "not recorded" not in js
    assert "budget_usd" in js
    for invented in ("$2.42", "223k", "30 proven", "muse-wonder-1.0"):
        assert invented not in js, invented
    assert "How to read it" in html and "Why it matters" in html
    assert "exhibit-a run --pr-diff BASE..HEAD" in html
    assert "data-ev-click" in html  # toggles stay
    assert "title=\"{{" in html or "title='{{" in html or 'title="{{' in html  # tooltips stay


def test_run_page_serves_payload_diff_and_hides_placeholder_copy(tmp_path):
    from exhibit_a.dashboard.model import FIX_OUTSIDE_PR_DIFF, fix_hunks_outside_pr_diff
    from exhibit_a.dashboard.sources import LocalRunsSource

    diff = "--- a/memos.py\n+++ b/memos.py\n@@ -1,1 +1,2 @@\n keep\n+added line\n"
    first = {
        "ts": "2026-11-03T14:04:00Z", "run_id": "pr-b30106f658c3", "type": "pr_opened",
        "role": "", "model": "", "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0,
        "latency_ms": 0,
        "payload": {"repo": "acme/app", "pr": "15", "title": "traversal", "diff": diff},
    }
    folder = write_memos_run(tmp_path)
    (folder / "ledger.jsonl").write_text(json.dumps(first) + "\n" + (folder / "ledger.jsonl").read_text())
    _, _, body = api(make_state(LocalRunsSource(tmp_path)), "/api/runs/run-memos")
    assert body["pr_diff"].startswith("--- a/memos.py")
    assert body["pr_diff_source"] == "ledger"
    assert body["fix_outside_pr_diff"] is False
    outside = "--- a/other.py\n+++ b/other.py\n@@ -1 +1 @@\n-a\n+b\n"
    assert fix_hunks_outside_pr_diff(outside, diff) is True
    assert FIX_OUTSIDE_PR_DIFF.startswith("GitHub cannot attach a suggestion")
    js = (WEB_DIR / "views" / "pr.js").read_text(encoding="utf-8")
    html = (WEB_DIR / "pr.html").read_text(encoding="utf-8")
    assert "not recorded" not in js and "not recorded" not in html
    assert "Scrub the ledger" not in html and "Scrub the ledger" not in js
    assert "live.player" in html
    assert "gh pr diff" in html


def test_dashboard_ui_never_says_not_recorded():
    for path in sorted(WEB_DIR.rglob("*")):
        if path.suffix.lower() not in {".js", ".html", ".css", ".md"}:
            continue
        text = path.read_text(encoding="utf-8")
        assert "not recorded" not in text, path.relative_to(WEB_DIR)


def test_github_run_fills_pr_diff_from_gh():
    from exhibit_a.dashboard.sources import GitHubSource
    from test_dashboard_sources import FakeGh

    diff = b"--- a/pings.py\n+++ b/pings.py\n@@ -1 +1 @@\n-old\n+new\n"
    responses = make_testbed_responses()
    responses["pr diff 1 Diego-do-na/exhibit-a-testbed"] = diff
    source = GitHubSource("Diego-do-na/exhibit-a-testbed", gh=FakeGh(responses))
    _, _, body = api(make_state(source), "/api/runs/41650269331")
    assert body["pr_diff"].startswith("--- a/pings.py")
    assert body["pr_diff_source"] == "gh pr diff"
