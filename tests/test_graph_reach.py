"""Reach (SLICE, M3): changed functions on paths from an entry point to a sink.

Reachability is not exploitability: these tests pin which paths the static graph proposes,
not whether anything is vulnerable. The proof is the sandboxed oracle's job.
"""

from __future__ import annotations

import difflib
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from exhibit_a.graph import build_graph
from exhibit_a.graph.reach import (
    changed_lines,
    changed_nodes,
    find_paths,
    functions_in,
    reach_from_diff,
    render,
)
from exhibit_a.schemas.graph import ReachReport

FIXTURES = Path(__file__).parent / "fixtures" / "graph"
CORPUS = Path(__file__).resolve().parent.parent / "bench" / "corpus"
ARCHIVE = CORPUS / "archive-extraction-pathtraversal"


def _udiff(before: Path, after: Path, name: str, context: int = 0) -> str:
    return "".join(difflib.unified_diff(
        before.read_text(encoding="utf-8").splitlines(keepends=True),
        after.read_text(encoding="utf-8").splitlines(keepends=True),
        f"a/{name}", f"b/{name}", n=context,
    ))


def _chains(report: ReachReport) -> list[list[str]]:
    return [[n.split(":", 1)[1] for n in [*p.to_changed, *p.to_sink[1 if not p.returns else 0:]]]
            + [p.sink.target] for p in report.paths]


# -- diff -> changed functions ---------------------------------------------------------------

DIFF = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -3,2 +3,3 @@ def one():
     a = 1
-    b = 2
+    b = 3
+    c = 4
@@ -20,1 +21,0 @@ def two():
-    removed = True
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1 +0,0 @@
-x = 1
diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1,2 @@
+def fresh():
+    return 1
"""


def test_changed_lines_use_the_new_side_and_skip_deleted_files():
    assert changed_lines(DIFF) == {"app.py": {4, 5, 21}, "new.py": {1, 2}}


def test_changed_lines_map_to_the_innermost_function(tmp_path):
    (tmp_path / "app.py").write_text(
        "X = 1\n\nclass A:\n    flag = True\n\n    def m(self):\n        def inner():\n"
        "            return 1\n        return inner()\n"
    )
    graph = build_graph(tmp_path)
    nodes, outside = changed_nodes(graph, {"app.py": {1, 4, 6, 8}, "other.py": {1}})
    assert nodes == ["app:A.m", "app:A.m.<locals>.inner"]
    assert outside == ["app.py:1", "app.py:4"]


# -- the corpus paths --------------------------------------------------------------------------

def test_archive_case_path_from_handle_request_to_the_open_for_write():
    graph = build_graph(ARCHIVE / "vulnerable")
    # The vulnerable tree as a PR against the fixed one: the change is in _target.
    report = reach_from_diff(graph, _udiff(ARCHIVE / "fixed" / "archive.py",
                                           ARCHIVE / "vulnerable" / "archive.py", "archive.py"))
    assert report.changed == ["archive:Extractor._target"]
    best = report.paths[0]
    assert best.oracle_entry_point == "App.handle_request" and best.entry_kind == "request_handler"
    assert best.to_changed == ["archive:App.handle_request", "archive:Extractor.extract_all",
                               "archive:Extractor.extract_member", "archive:Extractor._target"]
    assert best.returns == 1 and best.pivot == "archive:Extractor.extract_member"
    assert (best.sink.target, best.sink.access) == ("builtins.open", "write")
    assert (best.vuln_class, best.sink.effect) == ("path_traversal_write", "canary_write")
    assert best.confidence == 1.0 and best.unresolved_hops == 0
    assert render(best) == (
        "App.handle_request -> Extractor.extract_all -> Extractor.extract_member -> "
        "[Extractor._target] -> (returns to Extractor.extract_member) -> builtins.open (line 71)"
    )


def test_archive_case_with_the_declared_entry_point():
    graph = build_graph(ARCHIVE / "vulnerable")
    report = find_paths(graph, ["archive:Extractor._target"], declared_entries=["App.handle_request"])
    assert {p.entry_kind for p in report.paths} == {"declared"}
    assert report.paths[0].oracle_entry_point == "App.handle_request"


def test_the_fixed_archive_tree_still_has_the_path():
    graph = build_graph(ARCHIVE / "fixed")
    report = find_paths(graph, ["archive:Extractor._target"])
    # The fix added os.path.realpath to _target itself, which now ranks first.
    assert [p.sink.target for p in report.paths] == ["os.path.realpath", "os.path.realpath", "builtins.open"]
    assert {p.oracle_entry_point for p in report.paths} == {"App.handle_request"}


def test_a_static_files_app_reaches_its_lookup_through_a_worker_thread():
    graph = build_graph(FIXTURES / "asgi_static")
    report = find_paths(graph, ["webkit.static:StaticFiles.lookup_path"])
    assert _chains(report)[:2] == [
        ["StaticFiles.__call__", "StaticFiles.get_response", "StaticFiles.lookup_path", "os.path.realpath"],
        ["StaticFiles.__call__", "StaticFiles.get_response", "StaticFiles.lookup_path", "os.stat"],
    ]
    assert report.paths[0].oracle_entry_point == "StaticFiles.__call__"


# -- what has no path ------------------------------------------------------------------------------

def test_an_unreachable_change_has_no_path():
    graph = build_graph(FIXTURES / "unreachable")
    report = find_paths(graph, ["helpers:orphan", "helpers:_normalise"])
    assert report.paths == []
    assert {(u.node, u.reason) for u in report.unreached} == {
        ("helpers:orphan", "no entry point reaches it"),
        ("helpers:_normalise", "reaches no sink"),
    }


def test_a_helper_whose_result_feeds_its_callers_sink_has_a_path():
    graph = build_graph(FIXTURES / "unreachable")
    report = find_paths(graph, ["helpers:format_name"])
    assert _chains(report) == [["Files.__call__", "format_name", "Files.__call__", "builtins.open"]]
    assert report.paths[0].returns == 1


def test_recursion_and_cycles_terminate():
    graph = build_graph(FIXTURES / "cycles")
    report = find_paths(graph, ["app:App.walk", "app:countdown"])
    walk = [p for p in report.paths if p.changed == "app:App.walk"][0]
    assert walk.to_changed == ["app:App.handle_request", "app:App.visit", "app:App.walk"]
    assert walk.to_sink == ["app:App.walk", "app:App.visit", "app:App.serve", "app:read"]
    countdown = [p for p in report.paths if p.changed == "app:countdown"][0]
    assert countdown.returns == 1 and countdown.sink.target == "builtins.open"


def test_decorator_routed_handlers_reach_the_shared_sink():
    graph = build_graph(FIXTURES / "decorated")
    report = find_paths(graph, ["server:send"])
    assert [p.oracle_entry_point for p in report.paths] == ["create_app.<locals>.raw", "download"]
    assert {p.entry_kind for p in report.paths} == {"route_decorator"}


def test_an_unresolved_hop_lowers_the_confidence():
    graph = build_graph(FIXTURES / "weak")
    report = find_paths(graph, ["app:App.handle_request"])
    [path] = report.paths
    assert path.unresolved_hops == 1 and path.confidence == 0.5
    assert path.to_sink == ["app:App.handle_request", "app:Reader.fetch_document"]


def test_resolved_paths_rank_before_weaker_ones_of_the_same_length(tmp_path):
    (tmp_path / "app.py").write_text(
        "class Reader:\n    def load(self, n):\n        return open(n).read()\n\n"
        "class App:\n    def __init__(self, other):\n        self.reader = Reader()\n        self.other = other\n\n"
        "    def handle_request(self, n):\n        self.other.load(n)\n        return self.reader.load(n)\n"
    )
    graph = build_graph(tmp_path)
    report = find_paths(graph, ["app:App.handle_request"])
    assert [p.unresolved_hops for p in report.paths] == [0]  # the weak hop to the same node collapses


def test_depth_limit_and_node_budget(tmp_path):
    graph = build_graph(FIXTURES / "cycles")
    assert find_paths(graph, ["app:read"], max_depth=2).paths == []
    exhausted = find_paths(graph, ["app:read"], node_budget=1)
    assert exhausted.budget_exhausted and exhausted.paths == []


def test_report_is_deterministic_and_round_trips():
    graph = build_graph(FIXTURES / "cycles")
    first = find_paths(graph, functions_in(graph, "app.py"))
    second = find_paths(build_graph(FIXTURES / "cycles"), list(reversed(functions_in(graph, "app.py"))))
    assert first.model_dump_json() == second.model_dump_json()
    assert ReachReport.model_validate_json(first.model_dump_json()) == first
    assert first.schema_version == "1"
    keys = [(p.hops + p.returns, p.unresolved_hops) for p in first.paths]
    assert keys == sorted(keys)


# -- the Starlette CVE trees (needs the two pinned wheels from PyPI) ------------------------------

@pytest.fixture(scope="module")
def starlette_trees(tmp_path_factory):
    """Starlette 0.26.1 (vulnerable) and 0.27.0 (fixed) as plain files: the wheels are
    downloaded and unzipped, never installed, imported or executed."""
    base = tmp_path_factory.mktemp("starlette")
    trees = {}
    for version in ("0.26.1", "0.27.0"):
        wheels = base / f"wheels-{version}"
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "download", "--no-deps", "--only-binary=:all:",
             "-d", str(wheels), f"starlette=={version}"],
            capture_output=True, text=True, timeout=240,
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        [wheel] = wheels.glob("starlette-*.whl")
        tree = base / version
        with zipfile.ZipFile(wheel) as archive:
            for member in archive.namelist():
                assert not member.startswith("/") and ".." not in Path(member).parts
            archive.extractall(tree)
        trees[version] = tree
    return trees


STARLETTE_PATH = ["StaticFiles.__call__", "StaticFiles.get_response", "StaticFiles.lookup_path"]


@pytest.mark.integration
@pytest.mark.parametrize("tree, other", [("0.26.1", "0.27.0"), ("0.27.0", "0.26.1")])
def test_starlette_trees_have_the_static_files_path(starlette_trees, tree, other):
    # Vulnerable (0.26.1) and fixed (0.27.0) alike: reachability is not exploitability.
    name = "starlette/staticfiles.py"
    graph = build_graph(starlette_trees[tree])
    report = reach_from_diff(graph, _udiff(starlette_trees[other] / name, starlette_trees[tree] / name, name))
    assert report.changed == ["starlette.staticfiles:StaticFiles.lookup_path"]
    best = report.paths[0]
    assert [n.split(":", 1)[1] for n in best.to_changed] == STARLETTE_PATH
    assert best.oracle_entry_point == "StaticFiles.__call__" and best.entry_kind == "asgi"
    assert {p.sink.target for p in report.paths} >= {"os.path.realpath", "os.stat"}
    assert best.vuln_class == "path_traversal" and best.confidence == 1.0
