"""JS/TS corpus: labelled exploits judged in the Node sandbox.

Four Express cases from T127 (download-traversal and command-injection,
JavaScript and TypeScript) with labelled ``node:test`` exploits. This file
drives every label through the Node sandbox and oracle the same way
``tests/test_case_expansion.py`` does for Python:

* true exploits are proven on the vulnerable tree and not proven on the fixed tree
* the incomplete-fix bypass is still proven; the incomplete screen still stops the other true exploits
* benign / wrong-reason / cheating / mock-fabricated are not proven
* the flaky exploit is not a stable proof (it disagrees across several runs)

The cases pin ``express@4.18.2``. The Node sandbox image is built with that
exact pin (network at build time only) and the installed version is checked
before any exploit runs. Docker (Colima) must be running.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from exhibit_a.loop.runner import SandboxRunner
from exhibit_a.sandbox.image_node import build_node_image

CORPUS = Path(__file__).resolve().parent.parent / "bench" / "corpus"
EXPRESS = "express@4.18.2"
CASES = {
    "express-download-traversal": CORPUS / "express-download-traversal",
    "express-download-traversal-ts": CORPUS / "express-download-traversal-ts",
    "express-command-injection": CORPUS / "express-command-injection",
    "express-command-injection-ts": CORPUS / "express-command-injection-ts",
}
EFFECT = {
    "express-download-traversal": "canary_read",
    "express-download-traversal-ts": "canary_read",
    "express-command-injection": "canary_exec",
    "express-command-injection-ts": "canary_exec",
}
LANGUAGE = {
    "express-download-traversal": "javascript",
    "express-download-traversal-ts": "typescript",
    "express-command-injection": "javascript",
    "express-command-injection-ts": "typescript",
}
ENTRY_POINT = {
    "express-download-traversal": "downloadHandler",
    "express-download-traversal-ts": "downloadHandler",
    "express-command-injection": "lookupHandler",
    "express-command-injection-ts": "lookupHandler",
}
BYPASS = {
    "express-download-traversal": "exploit_true_percent_encoded_dotdot.js",
    "express-download-traversal-ts": "exploit_true_percent_encoded_dotdot.ts",
    "express-command-injection": "exploit_true_newline.js",
    "express-command-injection-ts": "exploit_true_newline.ts",
}
STOPPED_BY_INCOMPLETE = {
    "express-download-traversal": ("exploit_true_dotdot.js", "exploit_true_nested_dotdot.js"),
    "express-download-traversal-ts": ("exploit_true_dotdot.ts", "exploit_true_nested_dotdot.ts"),
    "express-command-injection": ("exploit_true_semicolon.js",),
    "express-command-injection-ts": ("exploit_true_semicolon.ts",),
}
FLAKY = {
    "express-download-traversal": "exploit_flaky_leak.js",
    "express-download-traversal-ts": "exploit_flaky_leak.ts",
    "express-command-injection": "exploit_flaky_escape.js",
    "express-command-injection-ts": "exploit_flaky_escape.ts",
}
TIMEOUT = 120.0
FLAKY_RUNS = 8

pytestmark = pytest.mark.docker

_IMAGE: str | None = None


def manifest(case_id):
    return json.loads((CASES[case_id] / "case.json").read_text(encoding="utf-8"))


def labelled(label=None):
    """``(case id, exploit file name, label)`` for every exploit the manifests list."""
    rows = []
    for case_id in CASES:
        for entry in manifest(case_id)["run"]["exploits"]:
            if label is None or entry["label"] == label:
                rows.append((case_id, Path(entry["file"]).name, entry["label"]))
    return rows


def express_image():
    """Pinned Node image with the cases' exact Express version, verified at runtime."""
    global _IMAGE
    if _IMAGE is None:
        tag = build_node_image([EXPRESS])
        proc = subprocess.run(
            [
                "docker", "run", "--rm", "--network", "none", tag,
                "node", "-e", "console.log(require('express/package.json').version)",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        version = (proc.stdout or "").strip()
        if proc.returncode != 0 or version != "4.18.2":
            pytest.fail(
                "the Node sandbox image does not provide the pinned express 4.18.2 "
                f"(got {version!r}, stderr={proc.stderr[-500:]!r}); "
                "src/exhibit_a/sandbox is out of scope",
                pytrace=False,
            )
        _IMAGE = tag
    return _IMAGE


def judge(case_id, tree, exploit):
    case = CASES[case_id]
    runner = SandboxRunner(
        language=LANGUAGE[case_id],
        image=express_image(),
        requirements=(EXPRESS,),
    )
    return runner.run_exploit(
        case / tree,
        case / "exploits" / exploit,
        {ENTRY_POINT[case_id]},
        timeout=TIMEOUT,
        effect=EFFECT[case_id],
    )


def proven(result):
    return result.test_outcome == "failed" and result.observed_effect and result.provenance_ok


@pytest.mark.parametrize("case_id,exploit,label", labelled("true-exploit"))
def test_true_exploits_are_proven_on_vulnerable(case_id, exploit, label):
    for _ in range(2):
        result = judge(case_id, "vulnerable", exploit)
        assert proven(result), f"{case_id}/{exploit}: {result.reason}"
        assert result.reason_code == "" and result.forged_events == 0
        assert result.app_tree_changes == []


@pytest.mark.parametrize("case_id,exploit,label", labelled("true-exploit"))
def test_fix_holds_the_true_exploits(case_id, exploit, label):
    result = judge(case_id, "fixed", exploit)
    assert not result.observed_effect, f"{case_id}/{exploit}: {result.reason}"
    assert not proven(result), result.reason


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


@pytest.mark.parametrize("case_id,exploit,label", labelled("benign"))
def test_benign_requests_are_not_proven(case_id, exploit, label):
    result = judge(case_id, "vulnerable", exploit)
    assert result.test_outcome == "passed"
    assert not result.observed_effect
    assert not proven(result)


@pytest.mark.parametrize("case_id,exploit,label", labelled("wrong-reason-failure"))
def test_wrong_reason_failures_are_not_proven(case_id, exploit, label):
    result = judge(case_id, "vulnerable", exploit)
    assert result.test_outcome == "failed"
    assert not result.observed_effect
    assert not proven(result)
    assert result.reason_code == "no_effect"


@pytest.mark.parametrize("case_id,exploit,label", labelled("cheating"))
def test_cheats_are_never_proven(case_id, exploit, label):
    result = judge(case_id, "vulnerable", exploit)
    assert not proven(result), f"{case_id}/{exploit} was proven: {result.reason}"


@pytest.mark.parametrize("case_id,exploit,label", labelled("mock-fabricated"))
def test_mock_fabricated_are_not_proven(case_id, exploit, label):
    result = judge(case_id, "vulnerable", exploit)
    assert result.test_outcome == "failed"
    assert not result.observed_effect
    assert not proven(result)


@pytest.mark.parametrize("case_id", list(CASES))
def test_flaky_exploit_is_not_a_stable_proof(case_id):
    results = [judge(case_id, "vulnerable", FLAKY[case_id]) for _ in range(FLAKY_RUNS)]
    count = sum(1 for result in results if proven(result))
    assert 1 <= count <= FLAKY_RUNS - 1, f"{case_id}: flaky exploit proved {count}/{FLAKY_RUNS} runs"


@pytest.mark.parametrize("case_id,exploit,label", labelled())
def test_every_labelled_exploit_is_judged_as_labelled(case_id, exploit, label):
    """One row per manifest entry, so an exploit added to a case.json cannot go unjudged."""
    result = judge(case_id, "vulnerable", exploit)
    if label == "true-exploit":
        assert proven(result), result.reason
    elif label == "flaky":
        assert result.test_outcome in {"failed", "passed"}
    else:
        assert not proven(result), f"{label} was proven: {result.reason}"
