"""Duplicate proofs of one effect are one finding; the oracle's frames place it.

Synthetic evidence covers the grouping rule and the observed location. The loop tests use a fake
``TestRunner`` that answers with synthetic oracle events (no Docker, no model), and one test runs
the host oracle for real on the fixture app. A model's text never takes part in grouping, and
findings that differ in effect, entry point or any sink frame never merge.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from exhibit_a.ci.summary import build_result, render_markdown as render_ci
from exhibit_a.cli.run import _append_run_index
from exhibit_a.findings import (
    MODEL_GUESS_LABEL,
    clean_facts,
    explain,
    group_findings,
    model_guess,
    proof_facts,
    refine_with_graph,
    summarize_patch,
)
from exhibit_a.graph import build_graph
from exhibit_a.ledger import Ledger, read_runs
from exhibit_a.loop import Roles, VerificationLoop
from exhibit_a.loop.pipeline import FullSystem
from exhibit_a.models import Completion, ModelRole, ReplayProvider, Role
from exhibit_a.models.cost import Pricing
from exhibit_a.oracle import Judgement, run_oracle
from exhibit_a.report import render_html, render_markdown
from exhibit_a.schemas import EventType

FIXTURES = Path(__file__).parent / "fixtures" / "oracle"
ENTRY = "App.handle_request"

BASELINE_TEST = '''\
from app import create_app


def test_known_file_is_served(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    app = create_app(str(tmp_path))
    assert app.handle_request("GET", "/download", {"name": "a.txt"}).body == "hello"
'''

# The fixture app's frames, as the oracle records them (qualname, line the function starts on).
HANDLE = ("App.handle_request", 31)
DOWNLOAD = ("create_app.<locals>.download", 42)
READ_FILE = ("read_file", 13)


def frame(file: str, qualname: str, line: int, *, admitted: bool | None = True) -> dict:
    return {"file": file, "function": qualname.rsplit(".", 1)[-1], "qualname": qualname, "line": line,
            "admitted": admitted}


TEST_FRAME = frame("/tmp/work/tests/test_exploit.py", "test_it", 5, admitted=None)


def read_event(*chain, root: str = "/workspace", access: str = "read", extra: dict | None = None) -> dict:
    """An oracle event whose stack is the test, then the admitted app frames of ``chain``."""
    stack = [TEST_FRAME, *(frame(f"{root}/app.py", name, line) for name, line in chain)]
    return {"type": "canary_read", "path": "/tmp/outside/canary.txt", "mode": "r", "stack": stack,
            "op": "open", "access": access, "requested": "/tmp/allowed/../outside/canary.txt",
            **(extra or {})}


def evidence(*events: dict, effect: str = "canary_read", provenance: dict | None = None) -> dict:
    return {"test_path": "test_exploit.py", "fails_on": "vulnerable", "passes_on": "fixed", "runs": 3,
            "oracle": {"effect": effect, "events": list(events)},
            "provenance": provenance or {"ok": True, "entry_point": ENTRY}}


FULL_CHAIN = (HANDLE, DOWNLOAD, READ_FILE)


def facts_of(*chain, effect: str = "canary_read", **kw) -> dict:
    proof = proof_facts(evidence(read_event(*chain), effect=effect), **kw)
    assert proof is not None
    return proof.to_dict()


# -- synthetic evidence: facts and the observed location ---------------------------------------


def test_facts_name_the_effect_the_entry_point_and_the_sink_caller() -> None:
    proof = proof_facts(evidence(read_event(*FULL_CHAIN)), roots=["/workspace"])
    assert proof is not None
    assert proof.effect == "canary_read" and proof.access == "read"
    assert proof.entry.qualname == "App.handle_request"
    assert proof.sink.qualname == "read_file"
    assert [f.file for f in proof.chain] == ["app.py"] * 3  # relative to the app root
    # Without a graph the observed line is where the sink caller starts, and says so.
    assert proof.observed_location() == {
        "file": "app.py", "line": 13, "function": "read_file", "line_source": "function_start"}


def test_only_admitted_frames_make_the_chain_and_test_frames_never_do() -> None:
    event = read_event(*FULL_CHAIN)
    event["stack"].insert(2, frame("/workspace/vendor.py", "helper", 7, admitted=False))
    proof = proof_facts(evidence(event), roots=["/workspace"])
    assert [f.qualname for f in proof.chain] == [HANDLE[0], DOWNLOAD[0], READ_FILE[0]]
    unadmitted = read_event(*FULL_CHAIN)
    for f in unadmitted["stack"]:
        f["admitted"] = None
    assert proof_facts(evidence(unadmitted)) is None  # nothing admitted: no facts, never grouped


def test_the_graph_places_the_observed_line_on_the_sink_call() -> None:
    graph = build_graph(FIXTURES / "vulnerable")
    proof = proof_facts(evidence(read_event(*FULL_CHAIN)), roots=["/workspace"])
    refined = refine_with_graph(proof, graph)
    # read_file starts on line 13 (def) and calls open() on line 15.
    assert refined.observed_location() == {
        "file": "app.py", "line": 15, "function": "read_file", "line_source": "graph_sink_call",
        "sink_call": "builtins.open"}
    assert refined.chain == proof.chain  # the identity of the proof does not move


def test_an_unidentified_function_keeps_the_oracles_own_line() -> None:
    graph = build_graph(FIXTURES / "vulnerable")
    wrong_start = proof_facts(evidence(read_event(HANDLE, ("read_file", 99))), roots=["/workspace"])
    assert refine_with_graph(wrong_start, graph).line == 99
    other_file = proof_facts(evidence(read_event(*FULL_CHAIN, root="/elsewhere")), roots=["/workspace"])
    assert refine_with_graph(other_file, graph).line_source == "function_start"


def test_access_must_fit_the_effect() -> None:
    write_only = evidence(read_event(*FULL_CHAIN, access="write"))
    assert proof_facts(write_only) is None  # a read effect is not proven by a write
    assert proof_facts(evidence(read_event(*FULL_CHAIN, access="write"), effect="canary_write")) is not None
    assert proof_facts(evidence(read_event(*FULL_CHAIN), effect="canary_made_up")) is None
    linked = read_event(*FULL_CHAIN, extra={"via_symlink": True})
    assert proof_facts(evidence(linked)) is None


def test_exec_effect_needs_a_process_from_a_sink_that_names_the_canary() -> None:
    process = read_event(*FULL_CHAIN, access="exec",
                         extra={"op": "process", "names_canary": True, "sink_named": True})
    assert proof_facts(evidence(process, effect="canary_exec")) is not None
    process["sink_named"] = False
    assert proof_facts(evidence(process, effect="canary_exec")) is None


def test_the_deciding_event_must_start_at_a_declared_entry_point() -> None:
    event = read_event(DOWNLOAD, READ_FILE)  # reached the sink without the entry point
    assert proof_facts(evidence(event), entry_points={ENTRY}) is None
    assert proof_facts(evidence(read_event(*FULL_CHAIN)), entry_points={ENTRY}) is not None
    assert proof_facts(evidence(read_event(*FULL_CHAIN)), entry_points={"handle_request"}) is not None


# -- grouping ----------------------------------------------------------------------------------


def test_two_proofs_of_one_effect_are_one_finding_with_one_duplicate() -> None:
    first, second = facts_of(*FULL_CHAIN), facts_of(*FULL_CHAIN)
    groups = group_findings([("S1", first), ("S3", second)])
    assert [(g.primary, g.duplicates) for g in groups] == [("S1", ("S3",))]


def test_the_first_proven_is_the_primary_and_order_is_kept() -> None:
    other = facts_of(HANDLE, READ_FILE)
    groups = group_findings([("B", facts_of(*FULL_CHAIN)), ("X", other), ("A", facts_of(*FULL_CHAIN))])
    assert [(g.primary, g.duplicates) for g in groups] == [("B", ("A",)), ("X", ())]


def test_different_effects_never_merge() -> None:
    read = facts_of(*FULL_CHAIN)
    write = proof_facts(evidence(read_event(*FULL_CHAIN, access="write"), effect="canary_write")).to_dict()
    groups = group_findings([("R", read), ("W", write)])
    assert [(g.primary, g.duplicates) for g in groups] == [("R", ()), ("W", ())]


def test_different_entry_points_never_merge() -> None:
    a = facts_of(HANDLE, DOWNLOAD, READ_FILE)
    b = facts_of(("App.dispatch", 50), DOWNLOAD, READ_FILE)
    assert [g.duplicates for g in group_findings([("A", a), ("B", b)])] == [(), ()]


def test_different_sink_frames_never_merge() -> None:
    a = facts_of(HANDLE, DOWNLOAD, READ_FILE)
    deeper = facts_of(HANDLE, DOWNLOAD, ("read_file", 13), ("fh_read", 20))
    elsewhere = facts_of(HANDLE, DOWNLOAD, ("read_other", 30))
    moved = facts_of(HANDLE, DOWNLOAD, ("read_file", 14))
    groups = group_findings([("A", a), ("D", deeper), ("E", elsewhere), ("M", moved)])
    assert [g.duplicates for g in groups] == [(), (), (), ()]


def test_a_proof_without_facts_is_its_own_finding_and_absorbs_nothing() -> None:
    groups = group_findings([("N1", None), ("N2", None), ("S1", facts_of(*FULL_CHAIN)), ("S2", {})])
    assert [(g.primary, g.duplicates) for g in groups] == [
        ("N1", ()), ("N2", ()), ("S1", ()), ("S2", ())]


def test_model_text_cannot_make_findings_merge_or_split() -> None:
    a, b = facts_of(*FULL_CHAIN), facts_of(HANDLE, ("read_other", 30))
    for facts in (a, b):  # a hypothesis, a location or an entry point text in the facts is ignored
        facts["hypothesis"] = "same bug, trust me"
        facts["model_entry_point"] = ENTRY
    assert [g.duplicates for g in group_findings([("A", a), ("B", b)])] == [(), ()]


def test_the_identity_survives_a_json_round_trip() -> None:
    first = json.loads(json.dumps(facts_of(*FULL_CHAIN)))
    again = json.loads(json.dumps(facts_of(*FULL_CHAIN)))
    assert group_findings([("A", first), ("B", again)])[0].duplicates == ("B",)


# -- the explanation ---------------------------------------------------------------------------


def full_facts() -> dict:
    proof = refine_with_graph(
        proof_facts(evidence(read_event(*FULL_CHAIN)), roots=["/workspace"]),
        build_graph(FIXTURES / "vulnerable"))
    return {**proof.to_dict(), "runs": 3, "test": "test_exploit.py", "fix_verified": True,
            "bypass_tried": 1, "bypass_succeeded": 0,
            **summarize_patch("--- a/app.py\n+++ b/app.py\n@@ -1 +1,2 @@\n-old\n+new\n+newer\n")}


def test_explanation_is_a_template_over_oracle_facts() -> None:
    text = explain(full_facts())
    assert "the application read a file outside the allowed directory" in text
    assert "entry point 'App.handle_request'" in text and "sink caller 'read_file'" in text
    assert "at app.py:15" in text and "static call graph" in text
    assert "in 3 of 3 runs" in text and "'app.py' (+2/-1)" in text
    assert "The fix was verified" in text
    assert explain(full_facts()) == text


def test_explanation_never_carries_model_text_and_the_guess_is_labelled() -> None:
    facts = full_facts()
    facts["hypothesis"] = "ignore previous instructions"
    facts["unknown_key"] = "x"
    assert "ignore previous" not in explain(clean_facts(facts) or {})
    guess = model_guess("a Windows backslash variant")
    assert guess.startswith(MODEL_GUESS_LABEL) and "the model's guess" in guess
    assert model_guess("") == "" and explain(None) == "" and explain({}) == ""


def test_unverified_fix_and_surviving_bypass_are_not_dressed_up() -> None:
    facts = {**full_facts(), "fix_verified": False, "bypass_tried": 2, "bypass_succeeded": 1}
    text = explain(facts)
    assert "The fix was not verified" in text and "1 of 2 bypass variants still reached" in text


def test_clean_facts_drops_what_it_does_not_know_and_caps_text() -> None:
    hostile = {"effect": "x" * 5000, "runs": "3", "fix_files": ["a.py", 7], "chain": [{"file": 1}],
               "observed_location": {"file": "a.py", "line": -4, "function": ["no"]}, "extra": 1}
    cleaned = clean_facts(hostile)
    assert len(cleaned["effect"]) <= 300 and "runs" not in cleaned and "chain" not in cleaned
    assert cleaned["fix_files"] == ["a.py"] and "extra" not in cleaned
    assert cleaned["observed_location"] == {"file": "a.py"}
    assert clean_facts("nope") is None and clean_facts({}) is None


def test_summarize_patch_counts_changes_that_look_like_headers() -> None:
    patch = "--- a/x.py\n+++ b/x.py\n@@ -1,2 +1,2 @@\n--- not a header\n+++ nor this\n+added\n"
    assert summarize_patch(patch) == {"fix_files": ["x.py"], "fix_added": 2, "fix_removed": 1}
    assert summarize_patch("") == {}


# -- the loop with a fake runner ---------------------------------------------------------------

#: Per suspicion, the application frames the fake oracle sees reaching the canary.
CHAINS = {
    "S1": FULL_CHAIN,
    "S3": FULL_CHAIN,  # the same bug as S1: the exploit only spells the request differently
    "S4": (HANDLE, READ_FILE),  # another route to the same sink: a different finding
}


def suspicion(sid: str, line: int, hypothesis: str) -> dict:
    return {"id": sid, "class": "path_traversal", "location": {"file": "app.py", "line": line},
            "entry_point": ENTRY, "hypothesis": hypothesis, "source": "query['name']"}


class Scripted:
    name = "scripted"
    pricing = Pricing()

    def complete(self, role, prompt, schema):
        if role == Role.ADVERSARY:
            body = {"suspicions": [
                suspicion("S1", 45, "the name is joined to base_dir unchecked"),
                suspicion("S3", 99, "a Windows backslash variant escapes the directory"),
                suspicion("S4", 13, "read_file opens any path"),
            ]}
        elif role == Role.TEST_WRITER:
            body = {"test_source": "def test_x():\n    assert False\n"}
        elif role == Role.FIXER:
            body = {"files": [{"path": "app.py", "content": (FIXTURES / "fixed" / "app.py").read_text()}]}
        else:
            body = {"variants": [{"name": "v", "test_source": "def test_v():\n    assert True\n"}]}
        return Completion(json.dumps(body), 10, 10, 1, model="scripted")


class FakeOracleRunner:
    """No Docker: the baseline passes, an exploit fails with the scripted frames on the vulnerable code."""

    def __init__(self, chains: dict, root: str = "/workspace") -> None:
        self.chains, self.root = chains, root

    def run_baseline(self, clone, test_path, timeout):
        return {"outcome": "passed", "exit_code": 0, "stdout": "", "stderr": "", "oracle_events": []}

    def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect="canary_read"):
        sid = Path(test_path).parent.parent.name
        if Path(app_root).name == "fixed" or Path(test_path).name != "test_exploit.py":
            return Judgement(observed_effect=False, provenance_ok=False, reason="passed",
                             test_outcome="passed", reason_code="no_effect")
        event = read_event(*self.chains[sid], root=self.root)
        from exhibit_a.oracle.oracle import OracleEvent

        return Judgement(observed_effect=True, provenance_ok=True, reason="canary read through the entry point",
                         test_outcome="failed", events=[OracleEvent.model_validate(event)])


def make_loop(tmp_path: Path, chains: dict = CHAINS, root: str = "/workspace", **kwargs):
    clone = tmp_path / "clone"
    shutil.copytree(FIXTURES / "vulnerable", clone)
    (clone / "test_baseline.py").write_text(BASELINE_TEST)
    provider = ReplayProvider(tmp_path / "replay.jsonl", Scripted())
    roles = Roles(*(ModelRole(r, provider) for r in (Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
    ledger = Ledger(tmp_path / "ledger.jsonl")
    loop = VerificationLoop(clone, tmp_path / "out", ledger, roles, "test_baseline.py", run_id="r1",
                            runner=FakeOracleRunner(chains, root), **kwargs)
    return loop, ledger


@pytest.fixture()
def grouped(tmp_path: Path):
    loop, ledger = make_loop(tmp_path)
    return loop.run("app.py"), ledger, tmp_path / "out"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_the_loop_groups_two_proofs_of_one_effect(grouped) -> None:
    result, ledger, out = grouped
    assert [r.verdict.verdict.value for r in result.results] == ["proven"] * 3  # raw proofs
    assert [r.suspicion.id for r in result.findings] == ["S1", "S4"]
    assert result.duplicate_proofs == 1
    s1, s3, s4 = result.results
    assert s1.duplicates == ["S3"] and s3.duplicate_of == "S1" and s4.duplicates == [] and s4.duplicate_of is None
    assert [(g.primary, g.duplicates) for g in result.groups] == [("S1", ("S3",)), ("S4", ())]


def test_the_primary_lists_its_duplicates_in_evidence_and_verdict(grouped) -> None:
    _, _, out = grouped
    evidence_json, verdict_json = load(out / "packages" / "S1" / "evidence.json"), load(out / "packages" / "S1" / "verdict.json")
    assert verdict_json["duplicates"] == ["S3"] and "duplicate_of" not in verdict_json
    [dup] = evidence_json["duplicates"]
    assert dup["suspicion_id"] == "S3" and dup["package"] == "packages/S3"
    # The duplicate's own words stay labelled as the model's, with the model's location.
    assert dup["model_location"] == {"file": "app.py", "line": 99}
    assert "Windows backslash" in dup["model_hypothesis"]
    assert load(out / "packages" / "S3" / "verdict.json")["duplicate_of"] == "S1"
    assert load(out / "packages" / "S3" / "evidence.json")["duplicate_of"] == "S1"
    own = load(out / "packages" / "S4" / "verdict.json")  # a finding of its own keeps the documented shape
    assert "duplicates" not in own and "duplicate_of" not in own
    assert "duplicates" not in load(out / "packages" / "S4" / "evidence.json")


def test_the_observed_location_sits_next_to_the_models(grouped) -> None:
    _, _, out = grouped
    evidence_json = load(out / "packages" / "S1" / "evidence.json")
    assert evidence_json["suspicion"]["location"] == {"file": "app.py", "line": 45}  # the model's, untouched
    observed = evidence_json["observed_location"]
    assert (observed["file"], observed["line"], observed["function"]) == ("app.py", 15, "read_file")
    assert observed["line_source"] == "graph_sink_call"
    assert evidence_json["evidence"]["provenance"]["observed_location"] == observed
    assert evidence_json["facts"]["entry_point"] == "App.handle_request"
    assert evidence_json["facts"]["fix_files"] == ["app.py"] and evidence_json["facts"]["runs"] == 3


def test_the_ledger_records_the_grouping_without_rewriting_verdicts(grouped) -> None:
    _, ledger, _ = grouped
    events = ledger.read_all()
    verdicts = [e for e in events if e.type == EventType.VERDICT]
    assert len(verdicts) == 3 and ledger.totals("r1")["verdicts"]["proven"] == 3  # raw count stays exact
    assert all("facts" in e.payload for e in verdicts)
    [event] = [e for e in events if e.type == EventType.SCAN_DONE and e.payload.get("status") == "findings_grouped"]
    assert event.payload["groups"] == [{
        "primary": "S1", "duplicates": ["S3"], "effect": "canary_read",
        "entry_point": "App.handle_request", "sink_function": "read_file"}]


def test_result_json_counts_unique_findings_and_keeps_the_raw_count(grouped) -> None:
    _, ledger, _ = grouped
    result = build_result(ledger.read_all(), run_id="r1")
    assert (result["proven"], result["proven_raw"], result["duplicates"]) == (2, 3, 1)
    assert result["verdicts"]["proven"] == 3 and result["dropped"] == 0
    assert [f["suspicion_id"] for f in result["findings"]] == ["S1", "S4"]
    primary = result["findings"][0]
    assert primary["duplicates"] == [{"suspicion_id": "S3", "package": "packages/S3"}]
    assert "duplicates" not in result["findings"][1]
    assert primary["observed_location"]["line"] == 15
    assert primary["hypothesis"] == "the name is joined to base_dir unchecked"


def test_ci_summary_opens_each_finding_with_the_explanation_then_the_models_guess(grouped) -> None:
    _, ledger, _ = grouped
    markdown = render_ci(build_result(ledger.read_all(), run_id="r1"))
    assert "2 proven findings" in markdown
    assert "Proofs: 3, grouped into 2 unique findings (1 duplicate" in markdown
    section = markdown.split("### Proven findings", 1)[1]
    first = section.split("**S4**", 1)[0]
    assert first.index("The oracle observed that") < first.index("Model's hypothesis")
    assert "at app.py:15" in first and "the model's guess; the oracle did not observe it" in first
    assert "Also proven, same effect through the same entry point and sink frames" in first and "S3" in first
    assert "Windows backslash" not in markdown  # the duplicate's guess is not shown as a finding


def test_the_run_index_counts_unique_findings_and_keeps_the_raw_count(grouped, tmp_path: Path) -> None:
    _, ledger, _ = grouped
    result = build_result(ledger.read_all(), run_id="r1")
    _append_run_index(tmp_path, result, tmp_path, "abc123", 0.0)
    [record], problems = read_runs(tmp_path / "runs.jsonl")
    assert problems == [] and record.verdict_counts.proven == 2 and record.proven_raw == 3


def test_the_report_highlights_the_observed_line_and_labels_both(grouped) -> None:
    _, _, out = grouped
    markdown = render_markdown(out / "packages" / "S1")
    assert markdown.index("## What was proven") < markdown.index("## Suspicious code")
    assert "The oracle observed that the application read a file" in markdown
    assert "Model's hypothesis \\(the model's guess; the oracle did not observe it\\)" in markdown
    code = markdown.split("## Suspicious code", 1)[1].split("## Hypothesis", 1)[0]
    assert "**Oracle-observed location** (marked `>`): `app.py:15`" in code
    assert "**Model's location** (marked `?`, the model's guess): `app.py:45`" in code
    assert ">   15 |     with open(path, encoding=" in code
    assert "?   45 |" in code
    assert "## Duplicate proofs" in markdown and "`S3`" in markdown and "packages/S3" in markdown
    html = render_html(out / "packages" / "S1")
    assert '<span class="hit">  15' in html and '<span class="model">  45' in html
    assert "<h2>What was proven</h2>" in html and "Duplicate proofs" in html


def test_the_duplicate_report_points_at_its_primary(grouped) -> None:
    _, _, out = grouped
    assert "duplicate of `S1`" in render_markdown(out / "packages" / "S3")
    assert "Duplicate proofs" not in render_markdown(out / "packages" / "S3")
    assert "Duplicate proofs" not in render_markdown(out / "packages" / "S4")


def test_no_grouping_without_admitted_frames(tmp_path: Path) -> None:
    class Unadmitted(FakeOracleRunner):
        def run_exploit(self, app_root, test_path, entry_points, **kw):
            judgement = super().run_exploit(app_root, test_path, entry_points, **kw)
            for event in judgement.events:
                for f in event.stack:
                    f.admitted = None
            return judgement

    loop, ledger = make_loop(tmp_path)
    loop.runner = Unadmitted(CHAINS)
    loop.judge = loop.runner.run_exploit
    result = loop.run("app.py")
    assert len(result.findings) == 3 and result.duplicate_proofs == 0
    assert all(r.facts is None for r in result.proven)
    assert build_result(ledger.read_all(), run_id="r1")["proven"] == 3


def test_no_facts_and_no_grouping_when_the_oracle_is_ablated(tmp_path: Path) -> None:
    loop, ledger = make_loop(tmp_path, flags=FullSystem(oracle=False))
    result = loop.run("app.py")
    assert len(result.proven) == 3 and result.duplicate_proofs == 0
    assert all(r.facts is None for r in result.proven)  # nothing is claimed as observed


def test_a_proof_through_a_different_entry_point_is_a_different_finding(tmp_path: Path) -> None:
    chains = {**CHAINS, "S3": (("App.dispatch", 50), DOWNLOAD, READ_FILE)}
    loop, ledger = make_loop(tmp_path, chains)
    result = loop.run("app.py")
    assert result.duplicate_proofs == 0 and len(result.findings) == 3
    assert not [e for e in ledger.read_all() if e.payload.get("status") == "findings_grouped"]


# -- the host oracle, for real -----------------------------------------------------------------

TRAVERSAL = '''\
import os
from app import create_app


def test_download_cannot_escape_base_dir():
    app = create_app(os.environ["EXHIBIT_A_ALLOWED_DIR"])
    token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
    response = app.handle_request("GET", "/download", {"name": "%s"})
    assert token not in response.body
'''


def test_the_real_oracle_gives_the_same_facts_for_two_spellings_of_one_attack(tmp_path: Path) -> None:
    clone = tmp_path / "clone"
    shutil.copytree(FIXTURES / "vulnerable", clone)
    graph = build_graph(clone)
    facts = []
    for n, name in enumerate(("../outside/canary.txt", "./../outside/./canary.txt")):
        test = tmp_path / f"t{n}" / "test_exploit.py"
        test.parent.mkdir()
        test.write_text(TRAVERSAL % name)
        judgement = run_oracle(clone, test, {ENTRY}, timeout=60)
        assert judgement.test_outcome == "failed" and judgement.provenance_ok
        proof = proof_facts(
            {"oracle": {"effect": "canary_read", "events": [e.model_dump() for e in judgement.events]}},
            roots=[str(clone.resolve())], entry_points={ENTRY})
        assert proof is not None
        facts.append(refine_with_graph(proof, graph).to_dict())
    assert facts[0] == facts[1]
    assert facts[0]["observed_location"]["file"] == "app.py" and facts[0]["observed_location"]["line"] == 15
    assert group_findings([("A", facts[0]), ("B", facts[1])])[0].duplicates == ("B",)
