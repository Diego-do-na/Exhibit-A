"""The slice builder (SLICE, M4): only the functions on a path, numbered, under a size cap;
and its opt-in use in the loop, ``exhibit-a run --slice`` (M5)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from bench.corpus import load_corpus
from bench.loop_pipeline import CaseMaterialsProvider
from exhibit_a.cli import main
from exhibit_a.cli import run as run_mod
from exhibit_a.cli.parser import build_parser
from exhibit_a.graph import build_graph, find_paths
from exhibit_a.graph.slicer import build_slice, make_plan
from exhibit_a.ledger import Ledger
from exhibit_a.loop import Roles, VerificationLoop, prompts
from exhibit_a.models import Completion, ModelRole, Role
from exhibit_a.models.cost import Pricing
from tests.test_run_live import FakeRunner

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


# -- the opt-in loop integration: exhibit-a run --slice (M5) ----------------------------------

CORPUS = ARCHIVE.parent
ROLES = (Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)


class Scripted:
    """Answers each role from a fixed script and records every prompt (no model, no key)."""

    name = "scripted"
    pricing = Pricing()

    def __init__(self, answer):
        self.answer = answer
        self.prompts: list[tuple[Role, str, dict]] = []

    def complete(self, role, prompt, schema):
        self.prompts.append((role, prompt, schema))
        return Completion(self.answer(role, prompt, schema), 1, 1, 1, model="scripted")


def _roles(provider) -> Roles:
    return Roles(*(ModelRole(role, provider) for role in ROLES))


def _no_model(*args, **kwargs):
    raise AssertionError("a model role was built although nothing is reachable")


def _events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_slice_is_off_by_default_for_the_standard_profile_and_on_for_compact():
    from exhibit_a.cli.run import _slice

    parse = build_parser().parse_args
    assert parse(["run"]).slice is None
    assert _slice(parse(["run"])) is False
    assert _slice(parse(["run", "--profile", "standard"])) is False
    assert _slice(parse(["run", "--profile", "compact"])) is True
    assert _slice(parse(["run", "--profile", "compact", "--no-slice"])) is False
    assert _slice(parse(["run", "--slice"])) is True
    assert build_parser().parse_args(["run", "--slice"]).slice is True


def test_slice_cannot_replay_the_recordings(capsys):
    case = CORPUS / "starlette-cve-2023-29159"
    assert main(["run", "--case", str(case), "--replay", "--slice"]) == 2
    assert "--slice cannot be combined with --replay" in capsys.readouterr().err


def _stage_case(root: Path, effect: str = "canary_read") -> Path:
    tree = root / "case" / "tree"
    shutil.copytree(FIXTURES / "unreachable", tree)
    (tree / "util.py").write_text("def slugify(text):\n    return text.lower().replace(' ', '-')\n")
    (root / "case" / "baseline_test.py").write_text("def test_ok():\n    assert True\n")
    (root / "case" / "case.json").write_text(json.dumps({
        "cases": [{"id": "graph-case", "kind": "vulnerable", "repo": "", "commit": ""}],
        "run": {"tree": "tree", "source_file": "util.py", "baseline_test": "baseline_test.py",
                "effect": effect},
    }))
    return root / "case"


def test_nothing_reachable_makes_no_model_call_and_exits_zero(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run_mod, "_live_roles", _no_model)
    monkeypatch.setattr(run_mod, "SandboxRunner", _no_model)
    case = _stage_case(tmp_path)
    out = tmp_path / "out"
    assert main(["run", "--case", str(case), "--slice", "--out", str(out)]) == 0
    assert "nothing reachable" in capsys.readouterr().out
    [event] = _events(out / "ledger.jsonl")  # no baseline, no model call: only the scan
    assert event["type"] == "scan_done" and event["run_id"] == "graph-case"
    assert event["payload"]["status"] == "nothing_reachable"
    assert event["payload"]["changed"] == ["util:slugify"]
    assert event["payload"]["unreached"] == [{"node": "util:slugify", "reason": "no entry point reaches it"}]
    assert event["tokens_in"] == event["tokens_out"] == 0 and event["cost_usd"] == 0


def test_a_path_to_a_sink_the_effect_cannot_prove_is_not_worth_a_call(tmp_path, monkeypatch):
    # helpers.format_name reaches an open() for reading; a write-effect case cannot prove it.
    monkeypatch.setattr(run_mod, "_live_roles", _no_model)
    monkeypatch.setattr(run_mod, "SandboxRunner", _no_model)
    case = _stage_case(tmp_path, effect="canary_write")
    settings = json.loads((case / "case.json").read_text())
    settings["run"]["source_file"] = "helpers.py"
    (case / "case.json").write_text(json.dumps(settings))
    out = tmp_path / "out"
    assert main(["run", "--case", str(case), "--slice", "--out", str(out)]) == 0
    [event] = _events(out / "ledger.jsonl")
    assert event["payload"]["status"] == "nothing_reachable"
    assert event["payload"]["paths_to_other_sinks"] == 1


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "commit.gpgsign=false", *args],
        capture_output=True, text=True, check=True,
    ).stdout.strip()


def test_pr_diff_with_nothing_reachable_makes_no_model_call(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run_mod, "_live_roles", _no_model)
    monkeypatch.setattr(run_mod, "_pr_roles", _no_model)
    monkeypatch.setattr(run_mod, "SandboxRunner", _no_model)
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "unreachable", repo)
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    helpers = repo / "helpers.py"
    helpers.write_text(helpers.read_text().replace("open(value).read()", "open(value).read(64)"))
    _git(repo, "commit", "-q", "-am", "head")
    head = _git(repo, "rev-parse", "HEAD")
    out = tmp_path / "out"
    code = main(["run", "--repo", str(repo), "--pr-diff", f"{base}..{head}", "--out", str(out), "--slice"])
    assert code == 0
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["slice"] == "nothing_reachable"
    [event] = _events(out / "ledger.jsonl")
    assert event["payload"]["status"] == "nothing_reachable"
    assert event["payload"]["changed"] == ["helpers:orphan"]
    result = json.loads((out / "result.json").read_text())
    assert result["proven"] == 0 and result["tokens_in"] == 0


def _archive_provider() -> tuple[Scripted, CaseMaterialsProvider]:
    materials = CaseMaterialsProvider(load_corpus(ARCHIVE / "case.json")[0])
    return Scripted(lambda role, prompt, schema: materials.complete(role, prompt, schema).text), materials


def test_archive_case_with_slice_sends_the_slice_and_proves_with_the_graph_entry(
        tmp_path, monkeypatch, capsys):
    provider, _ = _archive_provider()
    seen: list[set[str]] = []

    class Recording(FakeRunner):
        def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect="canary_read"):
            seen.append(set(entry_points))
            return super().run_exploit(app_root, test_path, entry_points, timeout=timeout, effect=effect)

    monkeypatch.setattr(run_mod, "_live_roles", lambda args, meter: _roles(provider))
    monkeypatch.setattr(run_mod, "SandboxRunner", Recording)
    out = tmp_path / "out"
    assert main(["run", "--case", str(ARCHIVE), "--slice", "--out", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "slice: " in printed and "from App.handle_request" in printed
    [(_, adversary, schema)] = [p for p in provider.prompts if p[0] == Role.ADVERSARY]
    # The builder is the standard one, unchanged; only its input is the slice.
    events = _events(out / "ledger.jsonl")
    sliced = [e for e in events if e["type"] == "scan_done"]
    assert [e["payload"]["status"] for e in sliced] == ["sliced"]
    assert schema is prompts.SUSPICIONS_SCHEMA
    assert adversary.startswith(prompts.adversary_prompt("CALL GRAPH SLICE", "archive.py")[:-len("CALL GRAPH SLICE")])
    assert "ENTRY POINT 1: App.handle_request" in adversary
    assert "def unpack" not in adversary and "def pack" not in adversary
    assert seen and all(s == {"App.handle_request"} for s in seen)
    verdicts = [e["payload"] for e in events if e["type"] == "verdict"]
    assert [(v["verdict"], v["fix_verified"]) for v in verdicts] == [("proven", True)]
    raised = [e["payload"] for e in events if e["type"] == "suspicion_raised"]
    assert raised[0]["graph"]["entry_point"] == "App.handle_request"


def _cheat_loop(tmp_path: Path, slice_plan) -> tuple[list[set[str]], list[dict], Scripted]:
    """The model names the sink's caller as the entry point and calls it directly."""
    clone = tmp_path / "clone"
    shutil.copytree(ARCHIVE / "vulnerable", clone)
    shutil.copyfile(ARCHIVE / "baseline_test.py", clone / "test_baseline.py")
    cheat = (ARCHIVE / "exploits" / "exploit_cheat_calls_sink_directly.py").read_text()
    fixed = (ARCHIVE / "fixed" / "archive.py").read_text()

    def answer(role, prompt, schema):
        if role == Role.ADVERSARY:
            return json.dumps({"suspicions": [{
                "id": "S1", "class": "archive_extraction_path_traversal",
                "location": {"file": "archive.py", "line": 63},
                "entry_point": "Extractor.extract_member", "hypothesis": "h", "source": "member.name"}]})
        if role == Role.TEST_WRITER:
            return json.dumps({"test_source": cheat})
        if role == Role.FIXER:
            return json.dumps({"files": [{"path": "archive.py", "content": fixed}]})
        return json.dumps({"variants": []})

    provider = Scripted(answer)
    seen: list[set[str]] = []

    class Recording(FakeRunner):
        def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect="canary_read"):
            seen.append(set(entry_points))
            return super().run_exploit(app_root, test_path, entry_points, timeout=timeout, effect=effect)

    ledger = Ledger(tmp_path / "ledger.jsonl")
    loop = VerificationLoop(clone, tmp_path / "out", ledger, _roles(provider), "test_baseline.py",
                            run_id="cheat", runner=Recording(), effect="canary_write",
                            slice_plan=slice_plan)
    loop.run("archive.py")
    return seen, [e.payload for e in ledger.read_all() if e.type.value == "verdict"], provider


def test_the_model_entry_point_cannot_widen_what_the_oracle_accepts(tmp_path):
    graph = build_graph(ARCHIVE / "vulnerable")
    plan = make_plan(graph, ARCHIVE / "vulnerable",
                     find_paths(graph, ["archive:Extractor._target"], declared_entries=["App.handle_request"]).paths)
    seen, verdicts, _ = _cheat_loop(tmp_path / "sliced", plan)
    assert seen == [{"App.handle_request"}]
    [verdict] = verdicts
    assert (verdict["verdict"], verdict["reason_code"]) == ("invalid_test", "provenance")
    assert "not a declared entry point" in verdict["reason"]

    # Without --slice the model's own entry point is what the oracle accepts: the same
    # test that calls the sink's caller directly gets past the oracle on vulnerable code.
    seen, verdicts, _ = _cheat_loop(tmp_path / "standard", None)
    assert seen[0] == {"Extractor.extract_member"}
    assert verdicts[0]["verdict"] != "invalid_test"


def test_without_slice_the_adversary_still_gets_the_whole_file(tmp_path):
    _, _, provider = _cheat_loop(tmp_path, None)
    [(_, adversary, _)] = [p for p in provider.prompts if p[0] == Role.ADVERSARY]
    source = (ARCHIVE / "vulnerable" / "archive.py").read_text()
    assert adversary == prompts.adversary_prompt(source, "archive.py")


# -- Docker: both corpus cases through the CLI with --slice and a scripted provider ----------

def _starlette_provider() -> Scripted:
    recorded = {}
    for line in (CORPUS / "starlette-cve-2023-29159" / "replay.jsonl").read_text().splitlines():
        record = json.loads(line)
        recorded[record["role"]] = record["text"]  # hand-authored answers, served by role
    return Scripted(lambda role, prompt, schema: recorded[role.value])


@pytest.mark.docker
@pytest.mark.parametrize("case, entry", [
    ("archive-extraction-pathtraversal", "App.handle_request"),
    ("starlette-cve-2023-29159", "StaticFiles.__call__"),
])
def test_corpus_case_with_slice_in_the_sandbox(case, entry, tmp_path, monkeypatch, capsys):
    provider = _archive_provider()[0] if case.startswith("archive") else _starlette_provider()
    monkeypatch.setattr(run_mod, "_live_roles", lambda args, meter: _roles(provider))
    out = tmp_path / "out"
    code = main(["run", "--case", str(CORPUS / case), "--slice", "--out", str(out)])
    printed = capsys.readouterr()
    assert code == 0, printed.out + printed.err
    events = _events(out / "ledger.jsonl")
    [sliced] = [e["payload"] for e in events if e["type"] == "scan_done"]
    assert sliced["status"] == "sliced" and sliced["paths"][0]["entry_point"] == entry
    raised = [e["payload"] for e in events if e["type"] == "suspicion_raised"]
    assert {r["suspicion"]["entry_point"] for r in raised} == {entry}
    verdicts = [e["payload"] for e in events if e["type"] == "verdict"]
    assert [(v["verdict"], v["fix_verified"]) for v in verdicts] == [("proven", True)]
    [(_, adversary, _)] = [p for p in provider.prompts if p[0] == Role.ADVERSARY]
    assert adversary.count("CALL GRAPH SLICE") == 1
