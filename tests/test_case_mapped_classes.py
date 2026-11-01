"""Mapped vulnerability classes: labelled exploits judged in the sandbox, no hint comments.

Five cases that reuse existing oracle effects (no new oracle work):

* ``xxe-catalog`` — XML external entity, ``canary_read``
* ``ssti-jinja-preview`` — Jinja2 SSTI, ``canary_exec``
* ``yaml-job-load`` — unsafe YAML load, ``canary_exec``
* ``tar-slip-restore`` — tar slip, ``canary_write``
* ``upload-avatar`` — upload filename write, ``canary_write``

Through the Docker sandbox (Colima must be running):

* every labelled exploit in each ``case.json`` is judged as labelled on the vulnerable tree
* true exploits are proven on the vulnerable tree and not proven on the fixed tree
* the incomplete fix is still proven by its bypass exploit
* cheats are never proven; the flaky exploit is not a stable proof

Without Docker: manifests, graph paths to each new sink, and that no tree carries a hint comment.
"""

import json
import re
from pathlib import Path

import pytest

from bench.corpus import load_corpus
from exhibit_a.graph import build_graph, find_paths
from exhibit_a.loop.runner import SandboxRunner
from exhibit_a.schemas import RepoProfile, Suspicion

CORPUS = Path(__file__).resolve().parent.parent / "bench" / "corpus"
CASES = {
    "xxe-catalog": CORPUS / "xxe-catalog",
    "ssti-jinja-preview": CORPUS / "ssti-jinja-preview",
    "yaml-job-load": CORPUS / "yaml-job-load",
    "tar-slip-restore": CORPUS / "tar-slip-restore",
    "upload-avatar": CORPUS / "upload-avatar",
}
EFFECT = {
    "xxe-catalog": "canary_read",
    "ssti-jinja-preview": "canary_exec",
    "yaml-job-load": "canary_exec",
    "tar-slip-restore": "canary_write",
    "upload-avatar": "canary_write",
}
VULN_CLASS = {
    "xxe-catalog": "xml_external_entity",
    "ssti-jinja-preview": "server_side_template_injection",
    "yaml-job-load": "insecure_deserialization",
    "tar-slip-restore": "archive_extraction_path_traversal",
    "upload-avatar": "unrestricted_file_upload",
}
SINK_CLASS = {
    "xxe-catalog": "xml_external_entity",
    "ssti-jinja-preview": "server_side_template_injection",
    "yaml-job-load": "insecure_deserialization",
    "tar-slip-restore": "archive_extraction_path_traversal",
    "upload-avatar": "path_traversal_write",
}
CVE = {
    "xxe-catalog": "CVE-2018-1999002",
    "ssti-jinja-preview": "CVE-2019-8341",
    "yaml-job-load": "CVE-2017-18342",
    "tar-slip-restore": "CVE-2007-4559",
    "upload-avatar": "CVE-2021-31542",
}
REQUIREMENTS = {
    "xxe-catalog": (),
    "ssti-jinja-preview": ("Jinja2",),
    "yaml-job-load": ("PyYAML",),
    "tar-slip-restore": (),
    "upload-avatar": (),
}
BYPASS = {
    "xxe-catalog": "exploit_true_raw_path.py",
    "ssti-jinja-preview": "exploit_true_os_index.py",
    "yaml-job-load": "exploit_true_eval.py",
    "tar-slip-restore": "exploit_true_absolute.py",
    "upload-avatar": "exploit_true_absolute_filename.py",
}
STOPPED_BY_INCOMPLETE = {
    "xxe-catalog": ("exploit_true_file_uri.py",),
    "ssti-jinja-preview": ("exploit_true_os_attr.py",),
    "yaml-job-load": ("exploit_true_os_system.py",),
    "tar-slip-restore": ("exploit_true_relative.py",),
    "upload-avatar": ("exploit_true_dotdot_filename.py",),
}
CHEAT_DIRECT = {
    "xxe-catalog": "exploit_cheat_calls_sink_directly.py",
    "ssti-jinja-preview": "exploit_cheat_calls_sink_directly.py",
    "yaml-job-load": "exploit_cheat_calls_sink_directly.py",
    "tar-slip-restore": "exploit_cheat_calls_sink_directly.py",
    "upload-avatar": "exploit_cheat_calls_sink_directly.py",
}
CHEAT_SELF = {
    "xxe-catalog": "exploit_cheat_opens_canary.py",
    "ssti-jinja-preview": "exploit_cheat_runs_canary.py",
    "yaml-job-load": "exploit_cheat_runs_canary.py",
    "tar-slip-restore": "exploit_cheat_writes_canary.py",
    "upload-avatar": "exploit_cheat_writes_canary.py",
}
ENTRY_POINTS = {"App.handle_request"}
TREES = ("vulnerable", "fixed", "fixed_incomplete")
KNOWN_LABELS = {"true-exploit", "benign", "wrong-reason-failure", "cheating", "flaky"}
TIMEOUT = 120.0
FLAKY_RUNS = 8
HINT = re.compile(r"#.*\b(BUG|FIXME|TODO|XXX|HACK)\b|#\s*Fix:", re.IGNORECASE)


def manifest(case_id):
    return json.loads((CASES[case_id] / "case.json").read_text(encoding="utf-8"))


def labelled(label=None):
    rows = []
    for case_id in CASES:
        for entry in manifest(case_id)["run"]["exploits"]:
            if label is None or entry["label"] == label:
                rows.append((case_id, Path(entry["file"]).name, entry["label"]))
    return rows


def judge(case_id, tree, exploit):
    case = CASES[case_id]
    runner = SandboxRunner(requirements=REQUIREMENTS[case_id])
    return runner.run_exploit(
        case / tree, case / "exploits" / exploit, ENTRY_POINTS,
        timeout=TIMEOUT, effect=EFFECT[case_id],
    )


def proven(result):
    return result.test_outcome == "failed" and result.observed_effect and result.provenance_ok


def run_baseline(case_id, tree):
    import os
    import subprocess
    import sys

    case = CASES[case_id]
    env = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(case / tree),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    env.update({key: value for key, value in os.environ.items() if key in ("HOME", "LANG", "LC_ALL")})
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(case / "baseline_test.py")],
        cwd=case / tree,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


# -- the sandbox: every labelled exploit judged as labelled -----------------------------------


@pytest.mark.parametrize("case_id,tree", [(c, t) for c in CASES for t in TREES])
def test_baseline_passes_on_every_tree(case_id, tree):
    proc = run_baseline(case_id, tree)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.docker
@pytest.mark.parametrize("case_id,exploit,label", labelled("true-exploit"))
def test_true_exploits_are_proven_on_vulnerable(case_id, exploit, label):
    for _ in range(2):
        result = judge(case_id, "vulnerable", exploit)
        assert proven(result), f"{case_id}/{exploit}: {result.reason}"
        assert result.reason_code == "" and result.forged_events == 0
        assert result.app_tree_changes == []


@pytest.mark.docker
@pytest.mark.parametrize("case_id,exploit,label", labelled("true-exploit"))
def test_fix_holds_the_true_exploits(case_id, exploit, label):
    result = judge(case_id, "fixed", exploit)
    assert not result.observed_effect, f"{case_id}/{exploit}: {result.reason}"
    assert not proven(result), result.reason


@pytest.mark.docker
@pytest.mark.parametrize("case_id", list(CASES))
def test_incomplete_fix_is_not_accepted_as_fixed(case_id):
    for _ in range(2):
        bypass = judge(case_id, "fixed_incomplete", BYPASS[case_id])
        assert proven(bypass), f"{case_id}: {bypass.reason}"
    for exploit in STOPPED_BY_INCOMPLETE[case_id]:
        blocked = judge(case_id, "fixed_incomplete", exploit)
        assert not proven(blocked) and not blocked.observed_effect, (
            f"{case_id}/{exploit}: {blocked.reason}"
        )


@pytest.mark.docker
@pytest.mark.parametrize("case_id,exploit,label", labelled("benign"))
def test_benign_inputs_are_not_proven(case_id, exploit, label):
    result = judge(case_id, "vulnerable", exploit)
    assert result.test_outcome == "passed"
    assert not result.observed_effect
    assert not proven(result)


@pytest.mark.docker
@pytest.mark.parametrize("case_id,exploit,label", labelled("wrong-reason-failure"))
def test_wrong_reason_failures_are_not_proven(case_id, exploit, label):
    result = judge(case_id, "vulnerable", exploit)
    assert result.test_outcome == "failed"
    assert not result.observed_effect
    assert not proven(result)


@pytest.mark.docker
@pytest.mark.parametrize("case_id", list(CASES))
def test_cheats_are_never_proven(case_id):
    running = judge(case_id, "vulnerable", CHEAT_SELF[case_id])
    if EFFECT[case_id] == "canary_exec":
        assert running.test_outcome == "error"
    else:
        assert not proven(running), running.reason
    direct = judge(case_id, "vulnerable", CHEAT_DIRECT[case_id])
    assert (direct.test_outcome, direct.observed_effect, direct.provenance_ok) == (
        "failed", True, False)
    fabricated = judge(case_id, "vulnerable", "exploit_mock_fabricated_escape.py")
    assert not proven(fabricated)
    assert not fabricated.observed_effect or not fabricated.provenance_ok


@pytest.mark.docker
@pytest.mark.parametrize("case_id,exploit,label", labelled("flaky"))
def test_flaky_exploit_is_not_a_stable_proof(case_id, exploit, label):
    results = [judge(case_id, "vulnerable", exploit) for _ in range(FLAKY_RUNS)]
    count = sum(1 for result in results if proven(result))
    assert 1 <= count <= FLAKY_RUNS - 1, f"{case_id}: flaky exploit proved {count}/{FLAKY_RUNS} runs"


# -- manifests, graph, no hint comments -------------------------------------------------------


@pytest.mark.parametrize("case_id", list(CASES))
def test_case_manifests_match_the_contracts(case_id):
    spec = manifest(case_id)
    cases = load_corpus(CASES[case_id] / "case.json")
    assert [c.id for c in cases] == [case_id]
    assert cases[0].kind == "vulnerable"
    assert cases[0].effect == EFFECT[case_id]
    assert spec["synthetic"] is True
    assert spec["real_world_analog"]["cve"] == CVE[case_id]
    assert cases[0].requirements == REQUIREMENTS[case_id]

    profile = RepoProfile.model_validate_json((CASES[case_id] / "profile.json").read_text(encoding="utf-8"))
    assert profile.language == "python"

    suspicion = Suspicion.model_validate_json((CASES[case_id] / "suspicion.json").read_text(encoding="utf-8"))
    assert suspicion.vuln_class == VULN_CLASS[case_id]
    assert suspicion.entry_point == "App.handle_request"


@pytest.mark.parametrize("case_id", list(CASES))
def test_manifest_lists_only_existing_exploits_with_known_labels(case_id):
    spec = manifest(case_id)
    for entry in spec["run"]["exploits"]:
        assert (CASES[case_id] / entry["file"]).is_file(), entry["file"]
        assert entry["label"] in KNOWN_LABELS, entry["label"]
    on_disk = {f"exploits/{p.name}" for p in (CASES[case_id] / "exploits").glob("exploit_*.py")}
    listed = {entry["file"] for entry in spec["run"]["exploits"]}
    assert on_disk == listed


@pytest.mark.parametrize("case_id", list(CASES))
def test_graph_finds_a_path_to_the_new_sink(case_id):
    graph = build_graph(CASES[case_id] / "vulnerable")
    changed = [node.id for node in graph.nodes if node.kind in ("function", "method")]
    report = find_paths(graph, changed, declared_entries=["App.handle_request"])
    classes = {path.sink.vuln_class for path in report.paths}
    assert SINK_CLASS[case_id] in classes, sorted(classes)
    assert any(path.entry.endswith("App.handle_request") or "App.handle_request" in path.entry
               for path in report.paths)


@pytest.mark.parametrize("case_id", list(CASES))
def test_trees_carry_no_hint_comments(case_id):
    for tree in TREES:
        for path in sorted((CASES[case_id] / tree).rglob("*.py")):
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                assert not HINT.search(line), f"{path}:{lineno}: {line.strip()}"
