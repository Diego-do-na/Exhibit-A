"""Variant hunting: after a proof, the graph lists the same bug elsewhere and the loop proves it.

Graph-level tests run on small synthetic repositories (never imported or executed): two routes
into one unsafe helper, a copied handler, and calls whose arguments are all constants, which
must never be listed. The loop tests use a scripted provider and a fake runner that answers with
synthetic oracle events (no Docker, no model, no key), so they prove the orchestration and the
links in ``variants.json``, not the sandbox.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from exhibit_a.cli import main as cli_main
from exhibit_a.graph import build_graph, find_paths
from exhibit_a.graph.slicer import make_plan
from exhibit_a.graph.variants import (
    SAME_SINK_FUNCTION,
    SAME_SINK_RULE,
    SIMILAR_CALLER,
    Frame,
    ProvenFinding,
    constant_call,
    constant_text,
    find_variants,
    hunt,
    load_findings,
)
from exhibit_a.ledger import Ledger
from exhibit_a.loop import Roles, VerificationLoop
from exhibit_a.models import Completion, ModelRole, Role
from exhibit_a.models.cost import Pricing
from exhibit_a.oracle import Judgement
from exhibit_a.oracle.oracle import OracleEvent
from exhibit_a.schemas.graph import GraphEdge

# -- synthetic repositories --------------------------------------------------------------------

ROUTER = '''\
import os

BASE = "/srv/files"


class Router:
    def get(self, path):
        def register(func):
            return func
        return register


app = Router()
'''

TWO_ROUTES = ROUTER + '''

def read_file(name):
    with open(os.path.join(BASE, name)) as handle:
        return handle.read()


@app.get("/a")
def route_a(request):
    return read_file(request.query_params["name"])


@app.get("/b")
def route_b(request):
    return read_file(request.query_params["file"])


@app.get("/about")
def about(request):
    with open("static/about.html") as handle:
        return handle.read()


@app.get("/logo")
def logo(request):
    with open("static/" + "logo.svg", "rb") as handle:
        return handle.read()
'''

COPIED = ROUTER + '''
CONFIG = os.environ.get("CONFIG", "config.ini")


@app.get("/download")
def download(request):
    name = request.query_params["f"]
    target = os.path.join(BASE, name)
    with open(target) as handle:
        return handle.read()


@app.get("/v2/download")
def download_v2(request):
    filename = request.query_params["file"]
    full = os.path.join(BASE, filename)
    with open(full) as handle:
        return handle.read()


@app.get("/config")
def config(request):
    with open(CONFIG) as handle:
        return handle.read()


def orphan(path):
    with open(path) as handle:
        return handle.read()
'''


def make_repo(root: Path, source: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text(source, encoding="utf-8")
    return root


def def_line(source: str, name: str) -> int:
    """The line the oracle records for a function: its first decorator, else its ``def``."""
    lines = source.splitlines()
    index = next(i for i, row in enumerate(lines) if row.startswith(f"def {name}("))
    while index > 0 and lines[index - 1].startswith("@"):
        index -= 1
    return index + 1


def call_line(source: str, func: str, needle: str = "open(") -> int:
    lines = source.splitlines()
    start = next(i for i, row in enumerate(lines) if row.startswith(f"def {func}("))
    return next(i for i in range(start, len(lines)) if needle in lines[i]) + 1


def finding(source: str, entry: str, sink: str, *, fid: str = "S1") -> ProvenFinding:
    return ProvenFinding(
        finding_id=fid, package=f"packages/{fid}", effect="canary_read",
        chain=(Frame("app.py", entry, def_line(source, entry)), Frame("app.py", sink, def_line(source, sink))),
        sink_line=call_line(source, sink), sink_call="builtins.open",
    )


def entries_of(listed) -> list[tuple[str | None, str]]:
    return [(v.entry_point, v.sink_node.split(":", 1)[1]) for v in listed.variants]


# -- graph level -------------------------------------------------------------------------------


def test_two_routes_into_one_unsafe_helper_list_the_other_route(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "repo", TWO_ROUTES)
    graph = build_graph(repo)
    listed = find_variants(graph, finding(TWO_ROUTES, "route_a", "read_file"), root=repo)
    assert listed.sink_node == "app:read_file" and listed.entry_node == "app:route_a"
    assert listed.rule == "builtins.open"
    first = listed.variants[0]
    assert first.kinds == [SAME_SINK_FUNCTION]
    assert first.entry_point == "route_b" and first.sink_node == "app:read_file"
    assert first.path is not None and first.path.to_changed == ["app:route_b", "app:read_file"]
    assert first.runnable and first.source_file == "app.py"
    # The proven path itself is never a candidate.
    assert ("route_a", "read_file") not in entries_of(listed)


def test_constant_argument_sinks_are_never_listed(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "repo", TWO_ROUTES)
    listed = find_variants(build_graph(repo), finding(TWO_ROUTES, "route_a", "read_file"), root=repo)
    sinks = {v.sink_node for v in listed.variants}
    assert "app:about" not in sinks and "app:logo" not in sinks
    assert listed.constant_sites == 2
    assert entries_of(listed) == [("route_b", "read_file")]


def test_constant_text_and_constant_call() -> None:
    for text in ('"static/a.html"', "'a' + 'b'", 'f"plain"', '["ls", "-l"]', "3", "(1, 'x')", "{'a': 1}"):
        assert constant_text(text), text
    for text in ("name", "BASE + name", 'f"{name}"', "os.path.join(BASE, name)", "*args", "request.path",
                 'os.path.join("a", "b...'):
        assert not constant_text(text), text
    from exhibit_a.graph.catalog import match_sink

    def edge(dst: str, *args: str, **kwargs: str) -> GraphEdge:
        return GraphEdge(src="m:f", dst=dst, kind="external", line=1, args=list(args), kwargs=kwargs)

    opener = match_sink("builtins.open")
    assert constant_call(edge("builtins.open", '"x"', "mode"), opener)  # a computed mode is not data
    assert constant_call(edge("builtins.open", '"x"', encoding="enc"), opener)
    assert not constant_call(edge("builtins.open", "name"), opener)
    run = match_sink("subprocess.run")
    assert constant_call(edge("subprocess.run", '["ls", "-l"]', check="True"), run)
    assert not constant_call(edge("subprocess.run", "cmd", shell="True"), run)
    assert not constant_call(edge("subprocess.run", '["ls"]', cwd="where"), run)
    # Nothing kept to show it is constant (a method on a computed value): listed, not skipped.
    assert not constant_call(edge("pathlib.Path.read_text"), match_sink("pathlib.Path.read_text"))


def test_a_copied_handler_is_a_similar_caller(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "repo", COPIED)
    listed = find_variants(build_graph(repo), finding(COPIED, "download", "download"), root=repo)
    by_sink = {v.sink_node: v for v in listed.variants}
    copy = by_sink["app:download_v2"]
    assert copy.kinds == [SIMILAR_CALLER, SAME_SINK_RULE]
    assert copy.similarity is not None and copy.similarity >= 0.9
    assert copy.param_flow == [0] and copy.entry_point == "download_v2"
    # Same rule and a non-constant argument, but no parameter reaches it: listed, not a copy.
    other = by_sink["app:config"]
    assert other.kinds == [SAME_SINK_RULE] and other.param_flow == []
    # A same-rule call no entry point reaches is listed, but cannot be run.
    orphan = by_sink["app:orphan"]
    assert not orphan.runnable and orphan.entry_point is None
    # Ranked: the copy first, then reachable same-rule sites, then unreachable ones.
    assert [v.sink_node for v in listed.variants] == ["app:download_v2", "app:config", "app:orphan"]
    assert "app:download" not in by_sink


def test_the_cap_keeps_the_best_ranked_and_counts_the_rest(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "repo", COPIED)
    listed = find_variants(build_graph(repo), finding(COPIED, "download", "download"), root=repo, max_count=1)
    assert [v.sink_node for v in listed.variants] == ["app:download_v2"]
    assert listed.considered == 3
    with pytest.raises(ValueError):
        find_variants(build_graph(repo), finding(COPIED, "download", "download"), max_count=0)


def test_without_the_source_no_candidate_is_called_similar(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "repo", COPIED)
    listed = find_variants(build_graph(repo), finding(COPIED, "download", "download"), root=None)
    assert all(SIMILAR_CALLER not in v.kinds for v in listed.variants)
    assert {v.sink_node for v in listed.variants} == {"app:download_v2", "app:config", "app:orphan"}


def test_every_proven_path_of_the_run_is_excluded(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "repo", TWO_ROUTES)
    graph = build_graph(repo)
    both = [finding(TWO_ROUTES, "route_a", "read_file", fid="S1"),
            finding(TWO_ROUTES, "route_b", "read_file", fid="S2")]
    lists = hunt(graph, both, root=repo)
    assert [entries_of(listed) for listed in lists] == [[], []]


def test_a_finding_the_graph_cannot_place_lists_nothing_and_says_why(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "repo", TWO_ROUTES)
    lost = ProvenFinding(finding_id="S9", package="packages/S9", effect="canary_exec",
                         chain=(Frame("gone.py", "nowhere", 1),))
    listed = find_variants(build_graph(repo), lost, root=repo)
    assert listed.variants == [] and listed.sink_node is None and "no rule" in listed.note


# -- the run directory -------------------------------------------------------------------------


def write_package(run: Path, sid: str, *, verdict: str = "proven", facts: dict | None = None,
                  duplicate_of: str | None = None) -> None:
    pkg = run / "packages" / sid
    pkg.mkdir(parents=True, exist_ok=True)
    body = {"verdict": verdict, **({"duplicate_of": duplicate_of} if duplicate_of else {})}
    (pkg / "verdict.json").write_text(json.dumps(body), encoding="utf-8")
    evidence = {"suspicion": {"id": sid}, "fix_verified": True, **({"facts": facts} if facts else {})}
    (pkg / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")


def facts_for(source: str, entry: str, sink: str) -> dict:
    return {
        "effect": "canary_read", "entry_point": entry, "sink_function": sink,
        "chain": [{"file": "app.py", "qualname": q, "line": def_line(source, q)} for q in (entry, sink)],
        "observed_location": {"file": "app.py", "line": call_line(source, sink), "function": sink,
                              "line_source": "graph_sink_call", "sink_call": "builtins.open"},
    }


def test_load_findings_keeps_proven_primaries_with_oracle_facts(tmp_path: Path) -> None:
    run = tmp_path / "run"
    write_package(run, "S1", facts=facts_for(TWO_ROUTES, "route_a", "read_file"))
    write_package(run, "S2", facts=facts_for(TWO_ROUTES, "route_a", "read_file"), duplicate_of="S1")
    write_package(run, "S3", verdict="discarded_unproven")
    write_package(run, "S4")  # proven, but no oracle facts
    found, skipped = load_findings(run)
    assert [f.finding_id for f in found] == ["S1"]
    s1 = found[0]
    assert s1.package == "packages/S1" and s1.entry.qualname == "route_a" and s1.sink.qualname == "read_file"
    assert s1.sink_call == "builtins.open" and s1.fix_verified
    reasons = {s["package"]: s["reason"] for s in skipped}
    assert set(reasons) == {"packages/S2", "packages/S3", "packages/S4"}
    assert "duplicate of S1" in reasons["packages/S2"] and "no oracle facts" in reasons["packages/S4"]


def test_load_findings_rejects_malformed_facts(tmp_path: Path) -> None:
    run = tmp_path / "run"
    write_package(run, "S1", facts={"effect": "canary_read", "chain": [{"file": 1, "qualname": "x", "line": 2}]})
    write_package(run, "S2", facts={"effect": "telepathy", "chain": [{"file": "a", "qualname": "x", "line": 2}]})
    (run / "packages" / "S3").mkdir()
    (run / "packages" / "S3" / "verdict.json").write_text("{not json", encoding="utf-8")
    found, skipped = load_findings(run)
    assert found == [] and len(skipped) == 3
    reasons = {s["package"]: s["reason"] for s in skipped}
    assert "no oracle facts" in reasons["packages/S1"]
    assert reasons["packages/S2"] == "effect 'telepathy' has no frame identity in findings.dedupe yet"
    assert load_findings(tmp_path / "missing") == ([], [])


def test_list_only_prints_the_other_route_and_calls_no_model(tmp_path: Path, capsys, monkeypatch) -> None:
    repo = make_repo(tmp_path / "repo", TWO_ROUTES)
    run = tmp_path / "run"
    write_package(run, "S1", facts=facts_for(TWO_ROUTES, "route_a", "read_file"))
    import exhibit_a.cli.ext.variants as variants_ext

    def boom(*args, **kwargs):  # pragma: no cover - must never run under --list-only
        raise AssertionError("a model or a runner was built for --list-only")

    monkeypatch.setattr(variants_ext, "_build_roles", boom)
    monkeypatch.setattr(variants_ext, "_default_runner", boom)
    for key in ("OPENAI_API_KEY", "META_API_KEY", "EXHIBIT_A_PROVIDER"):
        monkeypatch.delenv(key, raising=False)
    rc = cli_main(["variants", "--run-dir", str(run), "--repo", str(repo), "--list-only"])
    assert rc == 0
    text = capsys.readouterr().out
    assert "finding S1 [canary_read] route_a -> read_file" in text
    assert "1. [same_sink_function] route_b -> [read_file] -> builtins.open (line 17)" in text
    assert "about" not in text and "logo" not in text
    assert "2 same-rule call(s) with only constant arguments not listed" in text
    doc = json.loads((run / "variants.json").read_text(encoding="utf-8"))
    assert doc["mode"] == "list-only" and doc["stopped"] == "list-only" and doc["variants"] == []
    [entry] = doc["findings"]
    assert entry["finding_id"] == "S1" and entry["package"] == "packages/S1"
    assert [(c["n"], c["entry_point"], c["status"], c["variant_of"]) for c in entry["candidates"]] == \
        [(1, "route_b", "listed", "S1")]


def test_cli_refuses_bad_arguments(tmp_path: Path, capsys) -> None:
    assert cli_main(["variants", "--run-dir", str(tmp_path / "none"), "--list-only"]) == 2
    run = tmp_path / "run"
    run.mkdir()
    assert cli_main(["variants", "--run-dir", str(run), "--list-only"]) == 2  # no RUN/clone, no --repo
    repo = make_repo(tmp_path / "repo", TWO_ROUTES)
    assert cli_main(["variants", "--run-dir", str(run), "--repo", str(repo), "--max", "0"]) == 2
    assert cli_main(["variants", "--run-dir", str(run), "--repo", str(repo), "--budget-usd", "0"]) == 2


# -- the loop, with a scripted provider and a fake runner --------------------------------------

FIXED = TWO_ROUTES.replace(
    "    with open(os.path.join(BASE, name)) as handle:",
    "    if os.path.basename(name) != name:\n        raise ValueError(name)\n"
    "    with open(os.path.join(BASE, name)) as handle:",
)


class Scripted:
    """Suspects ``read_file``; writes a failing test, a fix and a bypass variant that passes."""

    name = "scripted"
    pricing = Pricing()

    def __init__(self, cost_usd: float = 0.0, suspicions: bool = True) -> None:
        self.cost_usd, self.suspicions, self.calls = cost_usd, suspicions, []

    def complete(self, role, prompt, schema):
        self.calls.append(role)
        if role == Role.ADVERSARY:
            raised = [{"id": "V1", "class": "path_traversal",
                       "location": {"file": "app.py", "line": call_line(TWO_ROUTES, "read_file")},
                       "entry_point": "whatever the model says", "hypothesis": "name is joined unchecked",
                       "source": "query_params"}] if self.suspicions else []
            body = {"suspicions": raised}
        elif role == Role.TEST_WRITER:
            body = {"test_source": "def test_x():\n    assert False\n"}
        elif role == Role.FIXER:
            body = {"files": [{"path": "app.py", "content": FIXED}]}
        else:
            body = {"variants": [{"name": "v", "test_source": "def test_v():\n    assert True\n"}]}
        return Completion(json.dumps(body), 10, 10, 1, model="scripted", cost_usd=self.cost_usd)


class FakeRunner:
    """No Docker: the exploit reads the canary through whichever entry point the oracle was given."""

    def __init__(self) -> None:
        self.entry_points: list[set[str]] = []

    def run_baseline(self, clone, test_path, timeout):
        return {"outcome": "passed", "exit_code": 0, "stdout": "", "stderr": "", "oracle_events": []}

    def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect="canary_read"):
        if Path(app_root).name == "fixed" or Path(test_path).name != "test_exploit.py":
            return Judgement(observed_effect=False, provenance_ok=False, reason="passed",
                             test_outcome="passed", reason_code="no_effect")
        self.entry_points.append(set(entry_points))
        entry = sorted(entry_points)[0]

        def frame(qualname: str) -> dict:
            return {"file": "/workspace/app.py", "function": qualname, "qualname": qualname,
                    "line": def_line(TWO_ROUTES, qualname), "admitted": True}

        stack = [{"file": "/tmp/w/tests/test_exploit.py", "function": "test_x", "qualname": "test_x",
                  "line": 1, "admitted": None}, frame(entry), frame("read_file")]
        event = {"type": "canary_read", "path": "/tmp/outside/canary.txt", "mode": "r", "stack": stack,
                 "op": "open", "access": "read", "requested": "/tmp/allowed/../outside/canary.txt"}
        return Judgement(observed_effect=True, provenance_ok=True, reason="canary read through the entry point",
                         test_outcome="failed", events=[OracleEvent.model_validate(event)])


def roles_with(provider, meter=None) -> Roles:
    return Roles(*(ModelRole(r, provider, meter) for r in (Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))


def original_run(tmp_path: Path) -> tuple[Path, Path]:
    """Prove the bug through route_a with the normal loop and a slice, as `run --slice` would."""
    repo = make_repo(tmp_path / "repo", TWO_ROUTES)
    (repo / "test_baseline.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    graph = build_graph(repo)
    report = find_paths(graph, ["app:read_file"])
    path = next(p for p in report.paths if p.entry == "app:route_a" and p.sink.node == "app:read_file")
    run = tmp_path / "run"
    loop = VerificationLoop(repo, run, Ledger(run / "ledger.jsonl"), roles_with(Scripted()), "test_baseline.py",
                            run_id="orig", runner=FakeRunner(), slice_plan=make_plan(graph, repo, [path]))
    result = loop.run("app.py")
    assert [r.suspicion.id for r in result.findings] == ["V1"]
    assert result.findings[0].facts["entry_point"] == "route_a"
    return repo, run


def test_a_proven_variant_is_linked_to_the_original_finding(tmp_path: Path) -> None:
    from exhibit_a.cli.ext.variants import run_variants

    repo, run = original_run(tmp_path)
    runner = FakeRunner()
    provider = Scripted()
    doc = run_variants(run, repo, roles_factory=lambda meter: roles_with(provider, meter),
                       runner_factory=lambda: runner, max_count=5)
    assert doc["mode"] == "run" and doc["stopped"] == "completed"
    # The oracle judged with the graph's entry point, never the model's text.
    assert runner.entry_points and all(e == {"route_b"} for e in runner.entry_points)
    [tried] = doc["variants"]
    assert tried["n"] == 1 and tried["status"] == "proven_variant" and tried["variant_of"] == "V1"
    assert tried["original_package"] == "packages/V1" and tried["dir"] == "variants/1"
    [proven] = doc["proven_variants"]
    assert proven["variant_of"] == "V1" and proven["entry_point"] == "route_b"
    assert proven["sink_function"] == "read_file" and proven["distinct_from_original"] is True
    assert proven["package"] == "variants/1/packages/V1" and proven["fix_verified"] is True
    out = run / "variants" / "1"
    assert (out / "packages" / "V1" / "evidence.json").is_file() and (out / "ledger.jsonl").is_file()
    assert json.loads((out / "variant.json").read_text())["outcome"]["variant_of"] == "V1"
    on_disk = json.loads((run / "variants.json").read_text(encoding="utf-8"))
    assert on_disk["proven_variants"] == doc["proven_variants"]
    assert on_disk["findings"][0]["candidates"][0]["status"] == "proven_variant"
    # The original run is untouched.
    assert (run / "packages" / "V1" / "evidence.json").is_file()
    assert (repo / "app.py").read_text(encoding="utf-8") == TWO_ROUTES


def test_a_variant_proof_that_repeats_the_original_is_not_a_new_finding(tmp_path: Path) -> None:
    from exhibit_a.cli.ext.variants import _same_as

    original = finding(TWO_ROUTES, "route_a", "read_file")
    assert _same_as(original.facts(), [original]) == "S1"
    other = finding(TWO_ROUTES, "route_b", "read_file", fid="S2")
    assert _same_as(other.facts(), [original]) is None
    assert _same_as(None, [original]) is None


def test_the_budget_stops_the_hunt_and_says_what_was_not_run(tmp_path: Path) -> None:
    from exhibit_a.cli.ext.variants import run_variants

    source = TWO_ROUTES + '''

@app.get("/c")
def route_c(request):
    return read_file(request.query_params["c"])
'''
    repo = make_repo(tmp_path / "repo", source)
    (repo / "test_baseline.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    run = tmp_path / "run"
    write_package(run, "S1", facts=facts_for(source, "route_a", "read_file"))
    provider = Scripted(cost_usd=0.10, suspicions=False)
    doc = run_variants(run, repo, roles_factory=lambda meter: roles_with(provider, meter),
                       runner_factory=FakeRunner, budget_usd=0.15, max_count=5)
    assert doc["stopped"] == "budget"
    statuses = [c["status"] for c in doc["findings"][0]["candidates"]]
    assert statuses == ["nothing_proven", "budget_exceeded"]
    assert doc["spent_usd"] <= 0.15 + 0.10 + 1e-9
    assert doc["proven_variants"] == []


def test_max_caps_the_runs_and_unreachable_sites_are_never_run(tmp_path: Path) -> None:
    from exhibit_a.cli.ext.variants import run_variants

    repo = make_repo(tmp_path / "repo", COPIED)
    run = tmp_path / "run"
    write_package(run, "S1", facts=facts_for(COPIED, "download", "download"))
    provider = Scripted(suspicions=False)
    doc = run_variants(run, repo, roles_factory=lambda meter: roles_with(provider, meter),
                       runner_factory=FakeRunner, max_count=1, baseline=".")
    statuses = [(c["sink_node"], c["status"]) for c in doc["findings"][0]["candidates"]]
    assert statuses == [("app:download_v2", "nothing_proven")]
    doc = run_variants(run, repo, roles_factory=lambda meter: roles_with(provider, meter),
                       runner_factory=FakeRunner, max_count=5, baseline=".")
    statuses = {c["sink_node"]: c["status"] for c in doc["findings"][0]["candidates"]}
    assert statuses == {"app:download_v2": "nothing_proven", "app:config": "nothing_proven",
                        "app:orphan": "not_run: no entry point reaches the call site"}
    assert len(doc["variants"]) == 2 and doc["stopped"] == "completed"
