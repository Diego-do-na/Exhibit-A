"""The slice builder (SLICE, M4): only the functions on a path, numbered, under a size cap."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from exhibit_a.graph import build_graph, find_paths
from exhibit_a.graph.slicer import build_slice, make_plan

FIXTURES = Path(__file__).parent / "fixtures" / "graph"
ARCHIVE = Path(__file__).resolve().parent.parent / "bench" / "corpus" / "archive-extraction-pathtraversal"


def _archive_paths():
    graph = build_graph(ARCHIVE / "vulnerable")
    return graph, find_paths(graph, ["archive:Extractor._target"]).paths


def test_the_slice_holds_only_the_functions_on_the_path_with_line_numbers():
    graph, paths = _archive_paths()
    piece = build_slice(graph, ARCHIVE / "vulnerable", paths[:1])
    assert [f.node for f in piece.functions] == [
        "archive:App.handle_request", "archive:Extractor.extract_all",
        "archive:Extractor.extract_member", "archive:Extractor._target",
    ]
    assert not piece.truncated
    text = piece.text
    assert "PATH 1 [path_traversal_write]: App.handle_request -> " in text
    assert "ENTRY POINT 1: App.handle_request" in text
    assert "--- archive.py:60-63 Extractor._target" in text
    assert "63:         return os.path.join(self.dest_dir, name)" in text
    assert '71:         with open(target, "w", encoding="utf-8") as handle:' in text
    # functions off the path are not sent: the archive format helpers, the module docstring
    assert "def unpack" not in text and "def pack" not in text and "CVE-2007-4559" not in text
    whole = (ARCHIVE / "vulnerable" / "archive.py").read_text()
    assert len(text) < len(whole)


def test_the_size_cap_keeps_the_changed_function_first():
    graph, paths = _archive_paths()
    piece = build_slice(graph, ARCHIVE / "vulnerable", paths[:1], max_chars=700)
    assert piece.truncated and len(piece.text) <= 700
    nodes = [f.node for f in piece.functions]
    assert nodes[-1] == "archive:Extractor._target" or "archive:Extractor._target" in nodes
    assert "Extractor._target" in piece.text


def test_a_long_function_is_cut_not_dropped(tmp_path):
    body = "".join(f"    x{i} = {i}\n" for i in range(400))
    (tmp_path / "app.py").write_text(
        "class App:\n    def handle_request(self, p):\n" + body.replace("    x", "        x")
        + "        return open(p).read()\n"
    )
    graph = build_graph(tmp_path)
    paths = find_paths(graph, ["app:App.handle_request"]).paths
    piece = build_slice(graph, tmp_path, paths, max_chars=1500)
    assert piece.truncated and piece.functions[0].truncated
    assert piece.text.endswith("... [truncated]\n") and len(piece.text) <= 1500


def test_nested_functions_are_not_sent_twice(tmp_path):
    (tmp_path / "app.py").write_text(
        "def main():\n    def inner(p):\n        return open(p).read()\n    return inner('x')\n"
    )
    graph = build_graph(tmp_path)
    paths = find_paths(graph, ["app:main.<locals>.inner"]).paths
    assert paths, "main() is a CLI entry point and its local function reaches open()"
    piece = build_slice(graph, tmp_path, paths)
    assert [f.node for f in piece.functions] == ["app:main"]
    assert piece.text.count("return open(p).read()") == 1


def test_a_file_swapped_for_a_symlink_is_not_read(tmp_path):
    root = tmp_path / "repo"
    shutil.copytree(FIXTURES / "cycles", root)
    graph = build_graph(root)
    paths = find_paths(graph, ["app:read"]).paths
    secret = tmp_path / "secret.py"
    secret.write_text("TOKEN = 'do-not-send'\n" * 40)
    (root / "app.py").unlink()
    os.symlink(secret, root / "app.py")
    piece = build_slice(graph, root, paths)
    assert piece.functions == () and piece.truncated
    assert "do-not-send" not in piece.text


def test_the_plan_picks_the_entry_point_from_the_graph():
    graph = build_graph(FIXTURES / "decorated")
    paths = find_paths(graph, ["server:send"]).paths
    plan = make_plan(graph, FIXTURES / "decorated", paths)
    assert plan is not None
    assert plan.path_for("server.py", 23).oracle_entry_point == "create_app.<locals>.raw"
    assert plan.path_for("server.py", 11).oracle_entry_point == "download"
    # a location on no path (or made up by the model) still gets a graph entry point
    assert plan.path_for("elsewhere.py", 1).oracle_entry_point == paths[0].oracle_entry_point
    summary = plan.summary()
    assert [p["entry_point"] for p in summary["paths"]] == ["create_app.<locals>.raw", "download"]
    assert summary["slice"]["chars"] == len(plan.slice.text)


def test_no_path_means_no_plan():
    graph = build_graph(FIXTURES / "unreachable")
    assert make_plan(graph, FIXTURES / "unreachable", []) is None
