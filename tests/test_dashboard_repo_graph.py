"""GET /api/graph is built from the chosen source's checkout, never a bundled tree."""

from __future__ import annotations

import json
from pathlib import Path

from exhibit_a.dashboard.repo_graph import (
    COMMAND,
    build_checkout_graph,
    clear_graph_cache,
    load_repo_graph,
    matching_checkout,
)
from exhibit_a.dashboard.sources import GitHubSource, LocalRunsSource
from test_dashboard_sources import event_line, fake_github, write_run
from test_dashboard_support import api, make_state

TESTBED = Path(__file__).resolve().parent / "fixtures" / "graph" / "pr_effects"


def _write_testbed(root: Path) -> Path:
    """Minimal exhibit-a-testbed shape: memos.py traversal + pings.py SSRF."""
    (root / "memos.py").write_text(
        "import os\n\n"
        "class App:\n"
        "    def handle_request(self, method, path, query):\n"
        "        return self.read_text(query.get('name', ''))\n"
        "    def read_text(self, name):\n"
        "        with open(os.path.join('shelf', name)) as handle:\n"
        "            return handle.read()\n",
        encoding="utf-8",
    )
    (root / "pings.py").write_text(
        (TESTBED / "ssrf" / "pings.py").read_text(encoding="utf-8")
        if (TESTBED / "ssrf" / "pings.py").is_file()
        else (
            "import urllib.request\n\n"
            "class App:\n"
            "    def handle_request(self, method, path, query):\n"
            "        url = query.get('url', '')\n"
            "        return urllib.request.urlopen(url).read()\n"
        ),
        encoding="utf-8",
    )
    return root


def setup_function() -> None:
    clear_graph_cache()


def test_testbed_checkout_graph_has_memos_pings_and_first_level_layers(tmp_path):
    checkout = tmp_path / "testbed"
    checkout.mkdir()
    _write_testbed(checkout)
    body = build_checkout_graph(checkout, commit="testbed-fixture")
    assert body["available"] is True
    assert body["from"] == "checkout"
    assert body["command"] == COMMAND
    names = {row[0] for row in body["packages"]}
    assert "memos" in names and "pings" in names
    layer_ids = {row["id"] for row in body["layers"]}
    assert "core" not in layer_ids and "Proof-core" not in {row["name"] for row in body["layers"]}
    assert "memos" in layer_ids and "pings" in layer_ids
    modules = {row[0] for row in body["modules"]}
    assert any("memos" in m for m in modules)
    assert any("pings" in m for m in modules)
    effects = {s.get("effect") for s in body["sinks"]}
    assert "canary_read" in effects or "canary_connect" in effects or body["sinks"]
    text = json.dumps(body)
    assert "oracle" not in text
    assert "29.9k" not in text


def test_two_checkouts_do_not_cross_module_strings(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "UNIQUE_MEMOS_TREE.py").write_text("def read_memo():\n    return open('x').read()\n")
    (b / "UNIQUE_PINGS_TREE.py").write_text(
        "import urllib.request\n"
        "def ping():\n    return urllib.request.urlopen('http://x').read()\n"
    )
    body_a = build_checkout_graph(a, commit="a")
    body_b = build_checkout_graph(b, commit="b")
    text_a, text_b = json.dumps(body_a), json.dumps(body_b)
    assert "UNIQUE_MEMOS_TREE" in text_a and "UNIQUE_MEMOS_TREE" not in text_b
    assert "UNIQUE_PINGS_TREE" in text_b and "UNIQUE_PINGS_TREE" not in text_a


def test_exhibit_a_checkout_uses_proof_core_analysis_surfaces(tmp_path):
    root = tmp_path / "exhibit-a"
    oracle = root / "src" / "exhibit_a" / "oracle"
    cli = root / "src" / "exhibit_a" / "cli"
    scan = root / "src" / "exhibit_a" / "scan"
    oracle.mkdir(parents=True)
    cli.mkdir(parents=True)
    scan.mkdir(parents=True)
    (oracle / "watch.py").write_text("def observe():\n    return open('canary').read()\n")
    (cli / "main.py").write_text("def main():\n    print(1)\n")
    (scan / "detect.py").write_text("def detect():\n    return None\n")
    body = build_checkout_graph(root, commit="ea")
    assert body["exhibit_a"] is True
    by_pkg = {row[0]: row[2] for row in body["packages"]}
    assert by_pkg.get("oracle") == "core"
    assert by_pkg.get("cli") == "surface"
    assert by_pkg.get("scan") == "analysis"
    names = {row["name"] for row in body["layers"]}
    assert names == {"Proof-core", "Analysis", "Surfaces"}


def test_api_graph_uses_checkout_on_the_state(tmp_path):
    checkout = tmp_path / "app"
    checkout.mkdir()
    (checkout / "UNIQUE_API_GRAPH.py").write_text("def f():\n    return 1\n")
    write_run(tmp_path, "run-a", event_line() + "\n")
    status, _, body = api(
        make_state(LocalRunsSource(tmp_path), checkout=checkout),
        "/api/graph",
    )
    assert status == 200
    assert body["available"] is True
    assert "UNIQUE_API_GRAPH" in json.dumps(body)
    assert body["from"] == "checkout"


def test_api_graph_falls_back_to_artifact_summary(tmp_path):
    write_run(tmp_path, "run-a", event_line() + "\n")
    summary = {
        "schema_version": "1",
        "available": True,
        "status": "sliced",
        "effect": "canary_read",
        "reason": "",
        "stats": {"files": 2, "nodes": 9, "edges": 4},
        "entries": ["App.handle_request"],
        "changed": ["memos:App.handle_request"],
        "paths": [{"path": "App.handle_request -> read_text", "entry_point": "App.handle_request"}],
        "source_file": "memos.py",
    }
    (tmp_path / "run-a" / "graph-summary.json").write_text(json.dumps(summary))
    status, _, body = api(make_state(LocalRunsSource(tmp_path)), "/api/graph")
    assert status == 200
    assert body["available"] is True
    assert body["from"] == "graph-summary.json"
    assert body["packages"] == []
    assert "App.handle_request" in body["entries"]
    assert body["stats"]["modules"] == 2
    assert "oracle" not in json.dumps(body)


def test_api_graph_empty_without_checkout_or_summary(tmp_path):
    write_run(tmp_path, "run-a", event_line() + "\n")
    status, _, body = api(make_state(LocalRunsSource(tmp_path)), "/api/graph")
    assert status == 200
    assert body["available"] is False
    assert body["command"] == COMMAND
    assert body["packages"] == []


def test_github_checkout_is_not_borrowed_from_another_repo(tmp_path):
    source = GitHubSource("acme/app", gh=fake_github())
    # cwd is this tmp_path, which is not the acme/app checkout.
    assert matching_checkout(source, tmp_path) is None
    body = load_repo_graph(source, checkout=None, cwd=tmp_path)
    assert body["available"] is False
    assert "checkout" in body["reason"]


def test_matching_local_checkout_only_when_cwd_is_that_source(tmp_path):
    runs = tmp_path / "proj" / "runs"
    runs.mkdir(parents=True)
    write_run(runs, "run-a", event_line() + "\n")
    (tmp_path / "proj" / "app.py").write_text("def f():\n    return 1\n")
    source = LocalRunsSource(runs)
    assert matching_checkout(source, tmp_path / "proj") == (tmp_path / "proj").resolve()
    assert matching_checkout(source, tmp_path) is None
