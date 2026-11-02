"""Loop integration for JavaScript/TypeScript (T128).

The proof loop speaks Node end to end: language detection, the node:test proof
contract, exploit files with JS/TS suffixes routed through the Node sandbox and
oracle, search/replace fixes on .js/.ts files, and slice plans from the JS
graph. Execution goes through a fake runner so these tests need no Docker; the
fake answers come from the corpus cases' own labelled materials.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import pytest

from exhibit_a.cli import main as cli_main
from exhibit_a.cli.parser import build_parser
from exhibit_a.graph.slicer import SlicePlan
from exhibit_a.graph.slicer import CodeSlice, SliceFunction
from exhibit_a.ledger import Ledger
from exhibit_a.loop import Roles, VerificationLoop, exploit_suffix
from exhibit_a.loop import prompts
from exhibit_a.models import Completion, ModelRole, ReplayProvider, Role
from exhibit_a.models.cost import Pricing
from exhibit_a.oracle import Judgement
from exhibit_a.schemas import EventType
from exhibit_a.schemas.graph import ReachPath, SinkHit

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "bench" / "corpus"
JS_CASE = CORPUS / "express-download-traversal"
TS_CASE = CORPUS / "express-download-traversal-ts"

JS_SUSPICION = {
    "id": "S-JS",
    "class": "path_traversal",
    "location": {"file": "app.js", "line": 8},
    "entry_point": "downloadHandler",
    "hypothesis": "the requested name is joined onto the base directory unchecked",
    "source": "req.query.name",
}

TS_SUSPICION = {
    "id": "S-TS",
    "class": "path_traversal",
    "location": {"file": "app.ts", "line": 8},
    "entry_point": "downloadHandler",
    "hypothesis": "the requested name is joined onto the base directory unchecked",
    "source": "req.query.name",
}


class FakeNodeRunner:
    """No-Docker stand-in for the Node sandbox: proven on vulnerable, passed on fixed."""

    def __init__(self) -> None:
        self.baselines: list[tuple[str, str, float]] = []
        self.exploits: list[tuple[str, str, set[str], float, str]] = []

    def run_baseline(self, clone_path: str, test_path: str, timeout: float) -> dict:
        self.baselines.append((clone_path, test_path, timeout))
        return {"outcome": "passed", "exit_code": 0, "stdout": "ok",
                "stderr": "", "oracle_events": []}

    def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect="canary_read"):
        from exhibit_a.oracle import OracleEvent

        self.exploits.append((str(app_root), str(test_path), set(entry_points), timeout, effect))
        if Path(app_root).name == "fixed":
            return Judgement(observed_effect=False, provenance_ok=False,
                             reason="exploit passed on fixed code",
                             test_outcome="passed", events=[])
        ep = next(iter(entry_points), "downloadHandler")
        app_file = "/workspace/app.ts" if str(test_path).endswith(".ts") else "/workspace/app.js"
        event = OracleEvent.model_validate(
            {
                "path": "/tmp/exhibit_a_oracle/outside/canary.txt",
                "mode": "r",
                "flags": 0,
                "access": "read",
                "requested": "/tmp/exhibit_a_oracle/outside/canary.txt",
                "stack": [
                    {
                        "file": "/workspace/_exhibit_a_oracle/test_exploit.js",
                        "line": 10,
                        "function": "test_exploit",
                        "qualname": "test_exploit",
                    },
                    {
                        "file": app_file,
                        "line": 13,
                        "function": ep.split(".")[-1],
                        "qualname": ep,
                        "admitted": True,
                    },
                    {
                        "file": app_file,
                        "line": 8,
                        "function": "resolveName",
                        "qualname": "resolveName",
                        "admitted": True,
                    },
                ],
            }
        )
        return Judgement(observed_effect=True, provenance_ok=True,
                         reason="canary read through the entry point",
                         test_outcome="failed", events=[event])


def _stage(root: Path, case_dir: Path, tree: str, source: str, baseline: str) -> Path:
    clone = root / "clone"
    if clone.exists():
        shutil.rmtree(clone)
    shutil.copytree(case_dir / tree, clone)
    shutil.copyfile(case_dir / baseline, clone / baseline)
    return clone


def _roles(provider) -> Roles:
    return Roles(*(ModelRole(r, provider)
                   for r in (Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))


class ScriptedNode:
    """Scripted answers from the case materials (standard profile: whole files)."""

    name = "scripted"
    pricing = Pricing()

    def __init__(self, case_dir: Path, suspicion: dict, source: str) -> None:
        run = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))["run"]
        first_true = next(
            item for item in run["exploits"]
            if item.get("label") == "true-exploit")
        self.exploit = (case_dir / first_true["file"]).read_text(encoding="utf-8")
        bypass = (run.get("bypass") or {}).get("exploit", "")
        self.variant = (case_dir / bypass).read_text(encoding="utf-8") if bypass else ""
        self.variant_name = Path(bypass).stem if bypass else "bypass"
        trees = run.get("trees") or {}
        self.fix_path = source
        self.fixed = (case_dir / trees.get("fixed", "fixed") / source).read_text(encoding="utf-8")
        self.suspicion = suspicion

    def complete(self, role, prompt, schema):
        if role == Role.ADVERSARY:
            body = {"suspicions": [self.suspicion]}
        elif role == Role.TEST_WRITER:
            body = {"test_source": self.exploit}
        elif role == Role.FIXER:
            body = {"files": [{"path": self.fix_path, "content": self.fixed}]}
        else:
            body = {"variants": [{"name": self.variant_name, "test_source": self.variant}]}
        return Completion(json.dumps(body), 10, 10, 1, model="scripted")


def _run_case_loop(tmp_path: Path, case_dir: Path, suspicion: dict, source: str,
                   baseline: str, language: str, profile: str = "standard",
                   provider=None, tree: str = "vulnerable"):
    clone = _stage(tmp_path, case_dir, tree, source, baseline)
    scripted = provider or ScriptedNode(case_dir, suspicion, source)
    loop = VerificationLoop(
        clone, tmp_path / "out", Ledger(tmp_path / "ledger.jsonl"), _roles(scripted),
        baseline, run_id="r-js", runner=FakeNodeRunner(),
        effect="canary_read", prompt_profile=profile, language=language,
    )
    return loop.run(source), loop


# -- scripted proof loops ---------------------------------------------------------------

def test_js_proof_loop_ends_proven_with_fix_verified(tmp_path):
    result, loop = _run_case_loop(tmp_path, JS_CASE, JS_SUSPICION, "app.js",
                                  "baseline_test.js", "javascript")
    proven = next(r for r in result.results if r.suspicion.id == "S-JS")
    assert proven.verdict.verdict == "proven"
    assert proven.fix_verified
    assert not proven.fix_incomplete
    names = {p.name for p in proven.package_dir.iterdir()}
    assert names == {"test_exploit.js", "fix.patch", "verdict.json", "evidence.json", "manifest.json"}
    assert "startsWith(base + path.sep)" in (proven.package_dir / "fix.patch").read_text()
    assert (proven.package_dir / "test_exploit.js").read_text().startswith('"use strict";')
    assert proven.verdict.evidence.test_path == "test_exploit.js"
    assert proven.facts["test"] == "test_exploit.js"
    runner = loop.runner
    assert isinstance(runner, FakeNodeRunner)
    exploit_paths = [Path(p[1]).name for p in runner.exploits]
    assert exploit_paths and "test_exploit.js" in exploit_paths
    assert "variant_0.js" in exploit_paths
    assert runner.baselines and all(name == "baseline_test.js" for _, name, _ in runner.baselines)


def test_ts_proof_loop_ends_proven_with_fix_verified(tmp_path):
    result, loop = _run_case_loop(tmp_path, TS_CASE, TS_SUSPICION, "app.ts",
                                  "baseline_test.ts", "typescript")
    proven = next(r for r in result.results if r.suspicion.id == "S-TS")
    assert proven.verdict.verdict == "proven"
    assert proven.fix_verified
    assert (proven.package_dir / "test_exploit.ts").exists()
    assert proven.verdict.evidence.test_path == "test_exploit.ts"
    exploit_paths = [Path(p[1]).name for p in loop.runner.exploits]
    assert exploit_paths and "test_exploit.ts" in exploit_paths


def test_a_fixed_tree_ends_discarded_unproven(tmp_path):
    result, _ = _run_case_loop(tmp_path, JS_CASE, JS_SUSPICION, "app.js",
                               "baseline_test.js", "javascript", tree="fixed")
    assert len(result.results) == 1
    outcome = result.results[0]
    assert outcome.verdict.verdict == "discarded_unproven"
    assert not outcome.fix_verified
    assert outcome.package_dir is None


def test_python_behaviour_is_unchanged(tmp_path):
    assert exploit_suffix("python") == ".py"
    assert exploit_suffix("javascript") == ".js"
    assert exploit_suffix("typescript") == ".ts"
    with pytest.raises(ValueError, match="unknown loop language"):
        exploit_suffix("java")
    loop = VerificationLoop(tmp_path, tmp_path / "out", Ledger(tmp_path / "ledger.jsonl"),
                            None, "test_baseline.py", runner=FakeNodeRunner())  # type: ignore[arg-type]
    assert loop.language == "python"
    with pytest.raises(ValueError, match="unknown loop language"):
        VerificationLoop(tmp_path, tmp_path / "out", Ledger(tmp_path / "ledger.jsonl"),
                         None, "test_baseline.py", runner=FakeNodeRunner(),  # type: ignore[arg-type]
                         language="ruby")


# -- the compact profile fixes .js/.ts with search/replace --------------------------------

class EditsNode(ScriptedNode):
    """The compact fixer answers search/replace edits derived from the case trees."""

    def complete(self, role, prompt, schema):
        if role == Role.FIXER:
            from bench.loop_pipeline import _minimal_edits

            case_dir = JS_CASE
            run = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))["run"]
            trees = run.get("trees") or {}
            before = (case_dir / trees.get("vulnerable", "vulnerable") / self.fix_path).read_text()
            body = {"edits": _minimal_edits(self.fix_path, before, self.fixed)}
            return Completion(json.dumps(body), 10, 10, 1, model="scripted")
        return super().complete(role, prompt, schema)


class PromptSpy(EditsNode):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.seen: dict = {}

    def complete(self, role, prompt, schema):
        self.seen[role] = prompt
        return super().complete(role, prompt, schema)


def test_compact_js_loop_fixes_with_search_replace_edits(tmp_path):
    spy = PromptSpy(JS_CASE, JS_SUSPICION, "app.js")
    result, _ = _run_case_loop(tmp_path, JS_CASE, JS_SUSPICION, "app.js",
                               "baseline_test.js", "javascript",
                               profile="compact", provider=spy)
    proven = next(r for r in result.results if r.suspicion.id == "S-JS")
    assert proven.verdict.verdict == "proven"
    assert proven.fix_verified
    assert "startsWith(base + path.sep)" in (proven.package_dir / "fix.patch").read_text()
    # The writer and defender were told the Node proof contract, not the Python one.
    for role in (Role.TEST_WRITER, Role.DEFENDER):
        assert "PROOF CONTRACT" in spy.seen[role]
        assert 'require("node:test")' in spy.seen[role]
        assert "os.environ" not in spy.seen[role]


# -- the Node proof contract ----------------------------------------------------------------

def test_the_node_contract_names_node_test_and_the_entry_shapes():
    for language, suffix in (("javascript", "js"), ("typescript", "ts")):
        text = prompts.test_contract("canary_read", ["express@4.18.2"], language)
        assert f"a .{suffix} file" in text
        assert 'require("node:test")' in text
        assert "process.env.EXHIBIT_A_ALLOWED_DIR" in text
        assert "process.env.EXHIBIT_A_CANARY_TOKEN" in text
        assert "Shape 1" in text and "Shape 2" in text
        assert "server's request turn" in text
        assert "express@4.18.2" in text
    text = prompts.test_contract("canary_exec", [], "javascript")
    assert '"canary_ran"' in text and '"outside"' in text
    assert "must not start any process" in text


def test_the_node_contract_says_where_the_canary_and_the_application_are():
    # The first real Meta run on a Node case guessed both (./app.js from tests/, and a
    # canary beside the allowed directory instead of in its "outside" sibling).
    text = prompts.test_contract("canary_read", [], "javascript")
    assert 'path.join(path.dirname(process.env.EXHIBIT_A_ALLOWED_DIR), "outside")' in text
    assert '"canary.txt"' in text
    assert "process.cwd()" in text and "never a relative ./ path" in text


def test_the_node_contract_labels_model_output_untrusted():
    text = prompts.test_contract("canary_read", [], "javascript")
    assert "untrusted data" in text
    for forbidden in ("child_process", "monkeypatch", "never open, read, create or write the canary"):
        assert forbidden in text
    assert "NOT in the application's response" in text
    assert "PASS once the flaw is fixed" in text


def test_the_node_contract_covers_only_what_the_node_oracle_judges():
    with pytest.raises(ValueError, match="only judges canary_read and canary_exec"):
        prompts.test_contract("canary_sql", [], "javascript")
    with pytest.raises(ValueError, match="only judges canary_read and canary_exec"):
        prompts.test_contract("canary_delete", [], "typescript")


def test_the_python_contract_has_no_node_text():
    text = prompts.test_contract("canary_read", ["example-pkg==1.0"])
    assert "node:test" not in text
    assert "Shape 1" not in text


# -- language detection and the --lang flag ---------------------------------------------------

def test_detect_prefers_the_case_language_over_package_json(tmp_path):
    repo = tmp_path / "case"
    repo.mkdir()
    (repo / "package.json").write_text('{"name":"x","dependencies":{"express":"4.18.2"}}')
    (repo / "app.ts").write_text("export {};\n")
    shutil.copyfile(TS_CASE / "case.json", repo / "case.json")
    from exhibit_a.scan import detect

    res = detect(str(repo))
    assert res.profile.language == "typescript"
    assert "typescript" in res.languages and "javascript" in res.languages


def test_detect_counts_extensions_without_markers(tmp_path):
    repo = tmp_path / "bare"
    repo.mkdir()
    (repo / "app.js").write_text("module.exports = {};\n")
    from exhibit_a.scan import detect

    res = detect(str(repo))
    assert res.profile.language == "javascript"
    assert res.languages == ["javascript"]


def test_detect_rejects_an_unknown_language_override(tmp_path):
    from exhibit_a.scan import detect

    with pytest.raises(ValueError, match="unknown language"):
        detect(str(tmp_path), language="ruby")


def test_scan_reports_the_detected_profile_language(tmp_path, capsys):
    repo = tmp_path / "jsrepo"
    repo.mkdir()
    (repo / "package.json").write_text('{"name":"x"}')
    (repo / "app.js").write_text("module.exports = {};\n")
    assert cli_main(["scan", str(repo)]) == 0
    profile = json.loads(capsys.readouterr().out)
    assert profile["language"] == "javascript"
    assert profile["interpreter"] == "node"


def test_run_and_scan_accept_lang():
    parser = build_parser()
    assert parser.parse_args(["run", "--case", "c", "--lang", "typescript"]).lang == "typescript"
    assert parser.parse_args(["run", "--case", "c"]).lang == "auto"
    assert parser.parse_args(["scan", "--lang", "javascript"]).lang == "javascript"


def test_resolve_language_prefers_flag_then_case_then_clone(tmp_path):
    from exhibit_a.cli.run import _resolve_language

    assert _resolve_language("typescript", "javascript") == "typescript"
    assert _resolve_language("auto", "javascript") == "javascript"
    assert _resolve_language(None, "") == "python"
    repo = tmp_path / "py"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[project]\nname='x'\n")
    assert _resolve_language("auto", "", repo) == "python"
    js = tmp_path / "js"
    js.mkdir()
    (js / "package.json").write_text("{}")
    assert _resolve_language("auto", "", js) == "javascript"


# -- slice wiring: the graph's entry point judges, never the model's --------------------------

def _js_slice_plan() -> SlicePlan:
    sink = SinkHit(node="app:resolveName", target="path.join", line=8, category="sink",
                   vuln_class="path_traversal", effect="canary_read")
    path = ReachPath(entry="app:downloadHandler", entry_kind="declared",
                     oracle_entry_point="downloadHandler", changed="app:resolveName",
                     pivot="app:resolveName", to_changed=["app:downloadHandler", "app:resolveName"],
                     to_sink=["app:resolveName"], sink=sink, hops=2,
                     returns=0, unresolved_hops=0, confidence=1.0, vuln_class="path_traversal")
    text = "function downloadHandler(base) {}\nfunction resolveName(base, name) {}\n"
    functions = (
        SliceFunction(node="app:downloadHandler", file="app.js", start=1, end=1, truncated=False),
        SliceFunction(node="app:resolveName", file="app.js", start=2, end=2, truncated=False),
    )
    spans = {"app:downloadHandler": ("app.js", 1, 1), "app:resolveName": ("app.js", 2, 2)}
    return SlicePlan(paths=(path,), slice=CodeSlice(text=text, functions=functions, truncated=False),
                     spans=spans)


def test_slice_judges_with_the_graph_entry_point(tmp_path):
    clone = _stage(tmp_path, JS_CASE, "vulnerable", "app.js", "baseline_test.js")
    seen: list[set[str]] = []

    class Recording(FakeNodeRunner):
        def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect="canary_read"):
            seen.append(set(entry_points))
            return super().run_exploit(app_root, test_path, entry_points,
                                       timeout=timeout, effect=effect)

    # The model names a decorated entry point; the graph path says downloadHandler.
    suspicion = dict(JS_SUSPICION, entry_point="downloadHandler(GET, /download, name)")
    loop = VerificationLoop(
        clone, tmp_path / "out", Ledger(tmp_path / "ledger.jsonl"),
        _roles(ScriptedNode(JS_CASE, suspicion, "app.js")),
        "baseline_test.js", run_id="r-slice", runner=Recording(),
        effect="canary_read", slice_plan=_js_slice_plan(), language="javascript",
    )
    result = loop.run("app.js")
    assert seen and all(entry == {"downloadHandler"} for entry in seen)
    assert result.results[0].suspicion.entry_point == "downloadHandler"
    verdicts = [e for e in Ledger(tmp_path / "ledger.jsonl").replay("r-slice")
                if e.type == EventType.VERDICT]
    assert verdicts and verdicts[0].payload["verdict"] == "proven"


# -- replay files -----------------------------------------------------------------------------

def test_each_js_case_ships_a_replay_recording():
    for case_dir in (JS_CASE, TS_CASE, CORPUS / "express-command-injection",
                     CORPUS / "express-command-injection-ts"):
        recording = case_dir / "replay.jsonl"
        assert recording.is_file(), f"missing recording for {case_dir.name}"
        provider = ReplayProvider(recording)
        assert provider._entries, f"empty recording for {case_dir.name}"


class CanonicalRunner(FakeNodeRunner):
    """FakeNodeRunner with the oracle's own deterministic proven reasons.

    The proven reason is a fixed literal in the oracle (no paths, no token), so a
    recording made against it replays key-for-key against the real sandbox run.
    """

    REASONS = {
        "canary_read": "canary read by application code reached through an entry point; test failed",
        "canary_exec": ("canary executed by a process application code started through an "
                        "entry point; test failed"),
    }

    def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect="canary_read"):
        judgement = super().run_exploit(app_root, test_path, entry_points,
                                        timeout=timeout, effect=effect)
        if judgement.test_outcome == "failed":
            judgement = Judgement(observed_effect=True, provenance_ok=True,
                                  reason=self.REASONS[effect],
                                  test_outcome="failed", events=judgement.events)
        return judgement


@pytest.mark.parametrize("case_id", [
    "express-download-traversal",
    "express-download-traversal-ts",
    "express-command-injection",
    "express-command-injection-ts",
])
def test_recordings_strictly_replay_to_proven_with_fix_verified(tmp_path, case_id):
    """`exhibit-a run --case <js> --replay` answers every model call from the recording.

    Strict replay (no recorder): any prompt drift raises instead of answering. The
    runner stands in for the sandbox with the oracle's canonical reasons; with
    Docker the same keys meet the real sandbox judgements.
    """
    from bench.corpus import load_corpus
    from bench.loop_pipeline import _stage_case, _staged_baseline

    case = load_corpus(CORPUS / case_id / "case.json")[0]
    clone = _stage_case(case, tmp_path)
    provider = ReplayProvider(CORPUS / case_id / "replay.jsonl")
    loop = VerificationLoop(
        clone, tmp_path / "out", Ledger(tmp_path / "ledger.jsonl"), _roles(provider),
        _staged_baseline(case), run_id=case.id, runner=CanonicalRunner(),
        requirements=tuple(case.requirements), effect=case.effect, language=case.language,
    )
    result = loop.run(case.source_file)
    assert len(result.proven) == 1
    assert result.proven[0].fix_verified
