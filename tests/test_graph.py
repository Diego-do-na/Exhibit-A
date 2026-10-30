"""The static call graph (SLICE, M1): ``ast`` only, untrusted input, deterministic output."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from exhibit_a.graph import build_graph
from exhibit_a.graph.build import module_names
from exhibit_a.schemas.graph import GRAPH_SCHEMA_VERSION, CodeGraph

FIXTURES = Path(__file__).parent / "fixtures" / "graph"
ARCHIVE = Path(__file__).resolve().parent.parent / "bench" / "corpus" / "archive-extraction-pathtraversal"


def _edges(graph: CodeGraph, src: str) -> set[tuple[str, str]]:
    return {(e.kind, e.dst or e.text) for e in graph.edges if e.src == src}


@pytest.fixture(scope="module")
def edges() -> CodeGraph:
    return build_graph(FIXTURES / "edges")


# -- nodes ---------------------------------------------------------------------------------

def test_nodes_are_qualified_like_cpython_and_carry_spans(edges):
    nodes = {n.id: n for n in edges.nodes}
    assert nodes["pkg.models:Store"].kind == "class"
    assert nodes["pkg.models:Store.load"].kind == "method"
    assert nodes["app:absolute"].kind == "function"
    assert nodes["app:<module>"].kind == "module"
    later = nodes["pkg.models:Service.deferred.<locals>.later"]
    assert later.kind == "function" and later.file == "pkg/models.py"
    store = nodes["pkg.models:Store"]
    assert store.start <= nodes["pkg.models:Store.load"].start <= nodes["pkg.models:Store.load"].end <= store.end
    make = nodes["pkg.models:Store.make"]
    assert make.start == make.line - 1  # the @classmethod line belongs to the span
    assert make.decorators[0].callee == "classmethod"
    assert nodes["pkg.models:Store"].bases == ["Base"]
    assert nodes["app:annotated"].params == ["store"]


def test_module_names_follow_the_package_chain():
    names = module_names(["src/pkg/__init__.py", "src/pkg/mod.py", "tool.py", "a/x.py", "b/x.py"])
    assert names["src/pkg/__init__.py"] == "pkg"
    assert names["src/pkg/mod.py"] == "pkg.mod"
    assert names["tool.py"] == "tool"
    # two top-level modules called x: both keep their full dotted path
    assert names["a/x.py"] == "a.x" and names["b/x.py"] == "b.x"


# -- one edge kind at a time -----------------------------------------------------------------

def test_absolute_import_module_attribute(edges):
    assert ("attr", "pkg.helpers:helper") in _edges(edges, "app:absolute")


def test_aliased_import(edges):
    assert ("attr", "pkg.helpers:other") in _edges(edges, "app:aliased")


def test_reexport_through_a_package_init(edges):
    assert ("call", "pkg.helpers:helper") in _edges(edges, "app:reexported")


def test_relative_imports(edges):
    assert ("call", "pkg.helpers:helper") in _edges(edges, "pkg.sub.rel:use")
    assert ("attr", "pkg.sub.sibling:thing") in _edges(edges, "pkg.sub.rel:use_sibling")


def test_self_cls_and_super(edges):
    assert ("method", "pkg.models:Store.save") in _edges(edges, "pkg.models:Store.load")
    assert ("method", "pkg.models:Base.base_m") in _edges(edges, "pkg.models:Store.save")
    assert ("method", "pkg.models:Store.build") in _edges(edges, "pkg.models:Store.make")
    assert ("ctor", "pkg.models:Store.__init__") in _edges(edges, "pkg.models:Store.build")


def test_self_inside_a_closure(edges):
    assert ("method", "pkg.models:Service.run") in _edges(edges, "pkg.models:Service.deferred.<locals>.later")


def test_constructor_then_method(edges):
    found = _edges(edges, "app:ctor_then_method")
    assert ("ctor", "pkg.models:Store.__init__") in found
    assert ("instance", "pkg.models:Store.load") in found


def test_method_on_a_constructed_value(edges):
    assert ("instance", "pkg.models:Store.load") in _edges(edges, "app:chained")
    assert ("instance", "pkg.models:Service.run") in _edges(edges, "app:service")


def test_constructor_through_a_module_attribute(edges):
    assert ("ctor", "pkg.models:Store.__init__") in _edges(edges, "app:module_attr_class")


def test_annotated_parameter_and_typed_self_attribute(edges):
    assert ("instance", "pkg.models:Store.save") in _edges(edges, "app:annotated")
    assert ("instance", "pkg.models:Store.save") in _edges(edges, "pkg.models:Service.run")


def test_function_passed_as_an_argument_is_a_ref_edge(edges):
    refs = [e for e in edges.edges if e.src == "app:callback" and e.kind == "ref"]
    assert [(e.dst, e.via) for e in refs] == [("app:helper_cb", "run")]


def test_external_calls_keep_their_dotted_name_and_arguments(edges):
    [join] = [e for e in edges.edges if e.src == "app:external" and e.dst == "os.path.join"]
    assert join.kind == "external" and join.args == ["path", "'x'"]


def test_what_cannot_be_resolved_is_recorded_not_guessed(edges):
    assert ("unresolved", "obj.anything") in _edges(edges, "app:unknown_receiver")
    assert ("unresolved", "fn") in _edges(edges, "app:run")
    assert ("unresolved", "getattr(os, name)") in _edges(edges, "app:dynamic")
    # a parameter named open shadows the builtin: never a call of builtins.open
    assert _edges(edges, "app:shadowed") == {("unresolved", "open")}


def test_main_guard_calls_are_marked(tmp_path):
    (tmp_path / "tool.py").write_text("def main():\n    return 1\n\nif __name__ == '__main__':\n    main()\n")
    graph = build_graph(tmp_path)
    [edge] = [e for e in graph.edges if e.dst == "tool:main"]
    assert edge.src == "tool:<module>" and edge.via == "__main__"


# -- untrusted input -------------------------------------------------------------------------

def test_repository_code_is_never_executed(tmp_path):
    marker = tmp_path / "executed"
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "evil.py").write_text(
        f"open({str(marker)!r}, 'w').write('x')\nraise SystemExit(3)\n"
        "def f():\n    return open('/etc/passwd')\n"
    )
    (repo / "__init__.py").write_text(f"import os\nos.system('touch {marker}')\n")
    graph = build_graph(repo)
    assert not marker.exists()
    assert "evil:f" in {n.id for n in graph.nodes}


def test_vendored_hidden_and_symlinked_paths_are_skipped(tmp_path):
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("def leaked():\n    pass\n")
    for vendored in (".venv/lib", "venv", "node_modules/x", "site-packages", ".git/hooks", "build/.cache"):
        (repo / vendored).mkdir(parents=True)
        (repo / vendored / "dep.py").write_text("def dep():\n    pass\n")
    (repo / "app.py").write_text("def app():\n    pass\n")
    os.symlink(outside, repo / "linked_dir")
    os.symlink(outside / "secret.py", repo / "linked_file.py")
    graph = build_graph(repo)
    assert graph.files == ["app.py"]
    assert {s.file: s.reason for s in graph.skipped} == {"linked_file.py": "symlink"}


def test_special_files_are_skipped_without_blocking(tmp_path):
    os.mkfifo(tmp_path / "pipe.py")
    (tmp_path / "ok.py").write_text("x = 1\n")
    graph = build_graph(tmp_path)
    assert graph.files == ["ok.py"]
    assert [s.reason for s in graph.skipped] == ["not a regular file"]


def test_size_and_count_caps(tmp_path):
    (tmp_path / "big.py").write_text("x = 1\n" * 100)
    for i in range(5):
        (tmp_path / f"m{i}.py").write_text("y = 2\n")
    graph = build_graph(tmp_path, max_file_bytes=100)
    assert {"file": "big.py", "reason": "file too large"} in [s.model_dump() for s in graph.skipped]
    capped = build_graph(tmp_path, max_files=3)
    assert capped.truncated and len(capped.files) == 3
    total = build_graph(tmp_path, max_total_bytes=20)
    assert total.truncated


def test_unparsable_files_are_skipped_and_reported(tmp_path):
    (tmp_path / "broken.py").write_text("def (:\n")
    (tmp_path / "nul.py").write_bytes(b"x = 1\x00\n")
    (tmp_path / "deep.py").write_text("x = " + "(" * 5000 + "1" + ")" * 5000 + "\n")
    (tmp_path / "fine.py").write_text("def ok():\n    return 1\n")
    graph = build_graph(tmp_path)
    assert graph.files == ["fine.py"]
    assert {s.file for s in graph.skipped} == {"broken.py", "nul.py", "deep.py"}
    assert all(s.reason.startswith("parse error") for s in graph.skipped)


def test_a_missing_root_is_an_error(tmp_path):
    with pytest.raises(ValueError, match="not a directory"):
        build_graph(tmp_path / "nope")


# -- output ------------------------------------------------------------------------------------

def test_output_is_deterministic_and_round_trips(tmp_path):
    first = build_graph(FIXTURES / "edges")
    copy = tmp_path / "copy"
    shutil.copytree(FIXTURES / "edges", copy)
    second = build_graph(copy)
    assert first.model_dump_json() == second.model_dump_json()
    data = json.loads(first.model_dump_json())
    assert data["schema_version"] == GRAPH_SCHEMA_VERSION == "1"
    assert [n["id"] for n in data["nodes"]] == sorted(n["id"] for n in data["nodes"])
    assert CodeGraph.model_validate(data) == first
    stats = first.stats
    assert stats.edges == len(first.edges) == stats.resolved + stats.external + stats.unresolved


def test_the_archive_case_graph_has_the_extraction_chain():
    graph = build_graph(ARCHIVE / "vulnerable")
    assert ("instance", "archive:Extractor.extract_all") in _edges(graph, "archive:App.handle_request")
    assert ("method", "archive:Extractor.extract_member") in _edges(graph, "archive:Extractor.extract_all")
    assert ("method", "archive:Extractor._target") in _edges(graph, "archive:Extractor.extract_member")
    assert ("external", "builtins.open") in _edges(graph, "archive:Extractor.extract_member")
    assert ("external", "os.path.join") in _edges(graph, "archive:Extractor._target")
