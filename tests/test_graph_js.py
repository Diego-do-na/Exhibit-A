import json
from pathlib import Path

import pytest

from exhibit_a.graph.js_catalog import sink_hits
from exhibit_a.graph.js_graph import _validate, build_js_graph, find_entries, find_paths
from exhibit_a.schemas.graph import CodeGraph


def _fake_graph():
    return CodeGraph.model_validate({
        "schema_version": "1", "files": ["app.ts"], "nodes": [
            {"id": "app:<module>", "kind": "module", "module": "app", "name": "<module>",
             "file": "app.ts", "line": 1, "start": 1, "end": 10, "params": [], "decorators": [], "bases": []},
            {"id": "app:handler", "kind": "function", "module": "app", "name": "handler",
             "file": "app.ts", "line": 1, "start": 1, "end": 5, "params": ["req", "res"], "decorators": [], "bases": []},
            {"id": "app:helper", "kind": "function", "module": "app", "name": "helper",
             "file": "app.ts", "line": 6, "start": 6, "end": 10, "params": ["p"], "decorators": [], "bases": []},
        ], "edges": [
            {"src": "app:handler", "dst": "app:helper", "kind": "call", "line": 2, "text": "helper", "via": "", "args": [], "kwargs": {}, "ref": False},
            {"src": "app:helper", "dst": "fs.readFile", "kind": "external", "line": 8, "text": "fs.readFile", "via": "",
             "args": ["p"], "kwargs": {}, "ref": False},
        ], "skipped": [], "truncated": False,
        "stats": {"files": 1, "nodes": 3, "edges": 2, "resolved": 1, "external": 1, "unresolved": 0},
    })


def test_js_catalog_marks_only_supported_effects_and_ignores_constant_reads():
    graph = _fake_graph()
    assert sink_hits(graph)["app:helper"][0].effect == "canary_read"
    graph.edges[1].args = ["'fixed.txt'"]
    assert sink_hits(graph) == {}


def test_js_reach_keeps_route_to_sink():
    graph = _fake_graph()
    object.__setattr__(graph, "_js_entry_points", ({"node": "app:handler", "kind": "exported_handler",
                                                       "oracle_name": "handler", "detail": ""},))
    report = find_paths(graph, ["app:helper"])
    assert report.paths[0].to_changed == ["app:handler", "app:helper"]
    assert report.paths[0].sink.target == "fs.readFile"
    assert find_entries(graph)[0][0].oracle_name == "handler"


def test_js_graph_refuses_empty_output_when_sources_exist(tmp_path, monkeypatch):
    import subprocess as sp

    import exhibit_a.graph.js_graph as js_graph

    (tmp_path / "app.ts").write_text("export function handler() {}\n")
    empty = json.dumps({
        "schema_version": "1", "files": [], "nodes": [], "edges": [],
        "skipped": [], "truncated": False,
        "stats": {"files": 0, "nodes": 0, "edges": 0, "resolved": 0, "external": 0, "unresolved": 0},
    }).encode()
    monkeypatch.setattr(js_graph, "build_node_image", lambda packages: "fake:tag")
    monkeypatch.setattr(sp, "run", lambda *a, **k: sp.CompletedProcess([], 0, empty, b""))
    with pytest.raises(ValueError, match="refusing an empty graph"):
        build_js_graph(tmp_path)


def test_gradio_harness_disables_network_checks_before_import():
    source = (
        Path(__file__).resolve().parent.parent
        / "bench/realcve/harnesses/gradio-cve-2023-51449/app.py"
    ).read_text(encoding="utf-8")
    assert source.index("GRADIO_ANALYTICS_ENABLED") < source.index("import gradio")


def test_js_builder_output_rejects_malformed_and_oversized():
    with pytest.raises(ValueError, match="schema"):
        _validate({"schema_version": "2"})
    with pytest.raises(ValueError, match="oversized"):
        _validate({"schema_version": "1", "files": ["x" * 11_000_000]})


def test_js_builder_walks_with_lstat_not_dirent_type():
    # Overlay/bind-mount filesystems leave d_type as DT_UNKNOWN, so Dirent.isFile()
    # is false for real source files. The builder must stat each name instead.
    source = (Path(__file__).resolve().parent.parent / "src/exhibit_a/graph/js/graph_builder.js").read_text(
        encoding="utf-8"
    )
    assert "lstatSync" in source
    assert "withFileTypes" not in source
    assert "entry.isFile()" not in source


def test_js_graph_collects_manifest_sources_without_mounts(tmp_path):
    import os

    import exhibit_a.graph.js_graph as js_graph

    src = tmp_path / "repo"
    (src / "sub").mkdir(parents=True)
    (src / "node_modules").mkdir()
    (src / "app.ts").write_text("export const x = 1;\n")
    (src / "sub" / "lib.js").write_text("module.exports = {};\n")
    (src / "notes.md").write_text("# not source\n")
    (src / ".hidden.ts").write_text("export const y = 2;\n")
    (src / "node_modules" / "dep.js").write_text("module.exports = {};\n")
    outside = tmp_path / "outside.ts"
    outside.write_text("export const z = 3;\n")
    os.symlink(outside, src / "link.ts")
    rels = sorted(entry["rel"] for entry in js_graph._collect_sources(src))
    assert rels == ["app.ts", "sub/lib.js"]


def test_js_builder_reads_manifest_from_stdin():
    builder = (Path(__file__).resolve().parent.parent / "src/exhibit_a/graph/js/graph_builder.js").read_text(
        encoding="utf-8"
    )
    assert "--from-stdin" in builder
    assert "unsafe path" in builder
    assert "e.code" in builder


@pytest.mark.docker
def test_typescript_graph_runs_in_node_sandbox(tmp_path):
    (tmp_path / "helpers.ts").write_text(
        "export function readValue(value: string) { return fs.readFile(value, () => {}); }\n"
        "import * as fs from 'fs';\n"
    )
    (tmp_path / "app.ts").write_text(
        "import { readValue as read } from './helpers';\n"
        "export function handler(req: Request, res: Response) { return one(req.query.name); }\n"
        "function one(value: string) { return two(value); }\n"
        "function two(value: string) { return read(value); }\n"
        "const neverCalled = () => fs.readFileSync('fixed');\n"
    )
    graph = build_js_graph(tmp_path, timeout=180)
    assert "app:handler" in {node.id for node in graph.nodes}
    assert any(edge.dst == "helpers:readValue" for edge in graph.edges)
    entries, _ = find_entries(graph)
    assert any(entry.oracle_name == "handler" for entry in entries)
    report = find_paths(graph, ["app:one"])
    assert report.paths and report.paths[0].sink.effect == "canary_read"
    assert not any(path.sink.line == 4 for path in report.paths)
