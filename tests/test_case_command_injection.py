"""Case: command injection in a listing handler, proven through the sandbox.

This drives the ``canary_exec`` effect end to end inside the Docker sandbox
(Colima must be running):

* the baseline (ordinary listings) passes on every tree, before and after the fix;
* each true exploit is proven on the vulnerable tree and not proven on the fixed tree;
* the bypass check: a plausible incomplete fix (a blacklist that misses the
  newline) is still proven by the newline exploit, so it must not be accepted
  as fixed;
* every other labelled exploit (benign, wrong-reason, cheating, flaky) is
  judged as labelled, through the sandbox like the true exploits.

It also validates the case manifests against the JSON contracts in
``src/exhibit_a/schemas`` and checks the trees carry no hint comments.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from exhibit_a.loop.runner import SandboxRunner
from exhibit_a.schemas import RepoProfile, Suspicion

from bench.corpus import load_corpus

CASE = Path(__file__).resolve().parent.parent / "bench" / "corpus" / "command-injection-shell"
EXPLOITS = CASE / "exploits"
ENTRY_POINTS = {"App.handle_request"}
TREES = ("vulnerable", "fixed", "fixed_incomplete")
TIMEOUT = 120.0


def judge(tree, exploit):
    return SandboxRunner().run_exploit(
        CASE / tree, EXPLOITS / exploit, ENTRY_POINTS, timeout=TIMEOUT, effect="canary_exec")


def proven(result):
    return result.test_outcome == "failed" and result.observed_effect and result.provenance_ok


def run_baseline(tree):
    """Run the case baseline against one tree with that tree on the path.

    Unlike the archive case, the app under test shells out to the platform
    ``ls``, so the baseline keeps a minimal system PATH that can resolve it.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(CASE / "baseline_test.py")],
        cwd=CASE / tree,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(CASE / tree)},
        capture_output=True,
        text=True,
        check=False,
    )
    return proc


@pytest.mark.parametrize("tree", TREES)
def test_baseline_passes_on_every_tree(tree):
    proc = run_baseline(tree)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.docker
@pytest.mark.parametrize("exploit", ("exploit_true_semicolon.py", "exploit_true_newline.py"))
def test_true_exploits_are_proven_on_vulnerable(exploit):
    for _ in range(2):
        result = judge("vulnerable", exploit)
        assert proven(result), f"{exploit}: {result.reason}"
        assert result.reason_code == "" and result.forged_events == 0
        assert result.app_tree_changes == []


@pytest.mark.docker
@pytest.mark.parametrize("exploit", ("exploit_true_semicolon.py", "exploit_true_newline.py"))
def test_fix_holds_the_exploits(exploit):
    result = judge("fixed", exploit)
    assert not result.observed_effect
    assert not proven(result), result.reason


@pytest.mark.docker
def test_incomplete_fix_is_not_accepted_as_fixed():
    # The bypass check. The newline exploit carries none of the refused
    # metacharacters, so the incomplete fix lets it through and the escape is
    # still proven: a real fix must do more than screen for a blacklist.
    for _ in range(2):
        bypass = judge("fixed_incomplete", "exploit_true_newline.py")
        assert proven(bypass), bypass.reason
    # The semicolon exploit, by contrast, is the part the incomplete fix does stop.
    blocked = judge("fixed_incomplete", "exploit_true_semicolon.py")
    assert not proven(blocked) and not blocked.observed_effect


@pytest.mark.docker
def test_benign_listing_is_not_proven():
    result = judge("vulnerable", "exploit_benign_plain_name.py")
    assert result.test_outcome == "passed"
    assert not result.observed_effect
    assert not proven(result)


@pytest.mark.docker
def test_wrong_reason_failure_is_not_proven():
    result = judge("vulnerable", "exploit_wrong_reason_none_name.py")
    assert result.test_outcome == "failed"
    assert not result.observed_effect
    assert not proven(result)


@pytest.mark.docker
def test_cheats_are_never_proven():
    running = judge("vulnerable", "exploit_cheat_runs_canary.py")
    assert running.test_outcome == "error"
    assert not proven(running), running.reason
    direct = judge("vulnerable", "exploit_cheat_calls_sink_directly.py")
    assert (direct.test_outcome, direct.observed_effect, direct.provenance_ok) == ("failed", True, False)
    fabricated = judge("vulnerable", "exploit_mock_fabricated_escape.py")
    assert (fabricated.test_outcome, fabricated.observed_effect, fabricated.provenance_ok) == (
        "failed", False, False)


@pytest.mark.docker
def test_flaky_exploit_is_not_a_stable_proof():
    results = [judge("vulnerable", "exploit_flaky_escape.py") for _ in range(8)]
    count = sum(1 for result in results if proven(result))
    assert 1 <= count <= 7, f"flaky exploit proved {count}/8 runs"


def test_case_manifests_match_the_contracts():
    spec = json.loads((CASE / "case.json").read_text(encoding="utf-8"))
    cases = load_corpus(CASE / "case.json")
    assert [c.id for c in cases] == ["command-injection-shell"]
    assert cases[0].kind == "vulnerable"
    assert cases[0].effect == "canary_exec"
    assert spec["synthetic"] is True
    assert spec["real_world_analog"]["cve"] == "CVE-2021-22205"

    profile = RepoProfile.model_validate_json((CASE / "profile.json").read_text(encoding="utf-8"))
    assert profile.language == "python"

    suspicion = Suspicion.model_validate_json((CASE / "suspicion.json").read_text(encoding="utf-8"))
    assert suspicion.vuln_class == "command_injection"
    assert suspicion.entry_point == "App.handle_request"


def test_manifest_lists_only_existing_exploits_with_known_labels():
    spec = json.loads((CASE / "case.json").read_text(encoding="utf-8"))
    known = {"true-exploit", "benign", "wrong-reason-failure", "cheating", "flaky"}
    for entry in spec["run"]["exploits"]:
        assert (CASE / entry["file"]).is_file(), entry["file"]
        assert entry["label"] in known, entry["label"]


def test_trees_carry_no_hint_comments():
    import re

    hint = re.compile(r"#.*\b(BUG|FIXME|TODO|XXX|HACK)\b|#\s*Fix:", re.IGNORECASE)
    for tree in TREES:
        for path in sorted((CASE / tree).glob("*.py")):
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                assert not hint.search(line), f"{path.name}:{lineno}: {line.strip()}"
