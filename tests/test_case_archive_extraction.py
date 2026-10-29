"""Case: archive-extraction path traversal (zip-slip), proven through a write effect.

This drives the second vulnerability class end to end at the oracle layer (no Docker needed):

* the baseline (ordinary in-bounds extraction) passes on every tree, before and after the fix;
* the true exploit is proven on the vulnerable tree and not proven on the fixed tree;
* the bypass check: a plausible incomplete fix (screens for ".." only) is still proven by the
  absolute-path exploit, so it must not be accepted as fixed.

It also validates the case manifests against the JSON contracts in ``src/exhibit_a/schemas``.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from exhibit_a.oracle import run_oracle
from exhibit_a.schemas import RepoProfile, Suspicion

from bench.corpus import load_corpus

CASE = Path(__file__).resolve().parent.parent / "bench" / "corpus" / "archive-extraction-pathtraversal"
EXPLOITS = CASE / "exploits"
ENTRY_POINTS = {"App.handle_request"}
TREES = ("vulnerable", "fixed", "fixed_incomplete")


def judge(tree, exploit):
    return run_oracle(CASE / tree, EXPLOITS / exploit, ENTRY_POINTS, effect="canary_write")


def proven(result):
    return result.test_outcome == "failed" and result.observed_effect and result.provenance_ok


def run_baseline(tree):
    """Run the case baseline against one tree with that tree on the path."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(CASE / "baseline_test.py")],
        cwd=CASE / tree,
        env={"PATH": "", "PYTHONPATH": str(CASE / tree)},
        capture_output=True,
        text=True,
        check=False,
    )
    return proc


@pytest.mark.parametrize("tree", TREES)
def test_baseline_passes_on_every_tree(tree):
    proc = run_baseline(tree)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_true_exploits_are_proven_on_vulnerable():
    for exploit in ("exploit_true_relative.py", "exploit_true_absolute.py"):
        result = judge("vulnerable", exploit)
        assert proven(result), f"{exploit}: {result.reason}"
        assert [event.via_symlink for event in result.events] == [False], result.reason


def test_fix_holds_the_exploits():
    for exploit in ("exploit_true_relative.py", "exploit_true_absolute.py"):
        result = judge("fixed", exploit)
        assert result.test_outcome == "passed"
        assert not result.observed_effect
        assert not proven(result)


def test_incomplete_fix_is_not_accepted_as_fixed():
    # The bypass check. The absolute-path member carries no "..", so the incomplete fix lets it
    # through and the escape is still proven: a real fix must do more than screen for "..".
    bypass = judge("fixed_incomplete", "exploit_true_absolute.py")
    assert proven(bypass), bypass.reason
    # The relative "../" exploit, by contrast, is the part the incomplete fix does stop.
    blocked = judge("fixed_incomplete", "exploit_true_relative.py")
    assert not proven(blocked)


def test_case_manifests_match_the_contracts():
    spec = json.loads((CASE / "case.json").read_text(encoding="utf-8"))
    cases = load_corpus(CASE / "case.json")
    assert [c.id for c in cases] == ["archive-extraction-pathtraversal"]
    assert cases[0].kind == "vulnerable"
    assert spec["synthetic"] is True
    assert spec["real_world_analog"]["cve"] == "CVE-2007-4559"

    profile = RepoProfile.model_validate_json((CASE / "profile.json").read_text(encoding="utf-8"))
    assert profile.language == "python"

    suspicion = Suspicion.model_validate_json((CASE / "suspicion.json").read_text(encoding="utf-8"))
    assert suspicion.vuln_class == "archive_extraction_path_traversal"
    assert suspicion.entry_point == "App.handle_request"


def test_manifest_lists_only_existing_exploits_with_known_labels():
    spec = json.loads((CASE / "case.json").read_text(encoding="utf-8"))
    known = {"true-exploit", "benign", "wrong-reason-failure", "cheating", "flaky"}
    for entry in spec["run"]["exploits"]:
        assert (CASE / entry["file"]).is_file(), entry["file"]
        assert entry["label"] in known, entry["label"]
