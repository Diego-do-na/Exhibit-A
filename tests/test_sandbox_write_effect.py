"""The canary_write effect proven inside the Docker sandbox, with the real archive-extraction exploits.

Every case runs ``SandboxRunner.run_exploit(..., effect="canary_write")`` on a tree of
``bench/corpus/archive-extraction-pathtraversal``: no canary file is mounted, the app creates it
in the writable ``outside/`` tmpfs, and the judge confirms the write from the post-run dump.
Mount layout: docs/reference/sandbox-write-effect.md. Argument plumbing without Docker is covered in
tests/test_sandbox_fake_docker.py.
"""

from pathlib import Path

import pytest

from exhibit_a.loop.runner import SandboxRunner

CASE = Path(__file__).resolve().parent.parent / "bench" / "corpus" / "archive-extraction-pathtraversal"
EXPLOITS = CASE / "exploits"
ENTRY_POINTS = {"App.handle_request"}

pytestmark = pytest.mark.docker


def judge(tree, exploit):
    return SandboxRunner().run_exploit(
        CASE / tree, EXPLOITS / exploit, ENTRY_POINTS, timeout=120.0, effect="canary_write")


def shape(j):
    return j.test_outcome, j.observed_effect, j.provenance_ok


PROVEN = ("failed", True, True)


@pytest.mark.parametrize("exploit", ["exploit_true_relative.py", "exploit_true_absolute.py"])
def test_vulnerable_tree_is_proven_through_a_canary_write(exploit):
    j = judge("vulnerable", exploit)
    assert shape(j) == PROVEN, j.reason
    assert "written" in j.reason and j.reason_code == "" and j.forged_events == 0
    assert j.app_tree_changes == []  # the escape went to outside/, not into the app tree
    assert j.events and all(e.access in ("write", "read_write") for e in j.events)
    assert all(not e.via_symlink for e in j.events)


@pytest.mark.parametrize("exploit", ["exploit_true_relative.py", "exploit_true_absolute.py"])
def test_fixed_tree_is_not_proven(exploit):
    j = judge("fixed", exploit)
    assert shape(j) == ("passed", False, False), j.reason


def test_fixed_incomplete_is_still_proven_by_the_absolute_path_exploit():
    j = judge("fixed_incomplete", "exploit_true_absolute.py")
    assert shape(j) == PROVEN, j.reason


def test_fixed_incomplete_stops_the_relative_exploit():
    j = judge("fixed_incomplete", "exploit_true_relative.py")
    assert shape(j) != PROVEN, j.reason


@pytest.mark.parametrize("exploit, expected", [
    ("exploit_benign_safe_archive.py", ("passed", False, False)),
    ("exploit_wrong_reason_crash.py", ("failed", False, False)),
    ("exploit_cheat_writes_canary.py", ("failed", False, False)),
    ("exploit_cheat_calls_sink_directly.py", ("failed", True, False)),
    ("exploit_mock_fabricated_escape.py", ("failed", False, False)),
])
def test_benign_and_adversarial_variants_are_not_proven(exploit, expected):
    j = judge("vulnerable", exploit)
    assert shape(j) == expected, j.reason
    assert shape(j) != PROVEN


def test_a_read_effect_run_does_not_count_a_write():
    # The same vulnerable app and exploit, judged for the other effect: a write is never a read.
    j = SandboxRunner().run_exploit(
        CASE / "vulnerable", EXPLOITS / "exploit_true_relative.py", ENTRY_POINTS, timeout=120.0)
    assert shape(j) != PROVEN, j.reason


def test_cli_closes_the_archive_case_red_to_green_in_the_sandbox(tmp_path, capsys):
    import json
    import sys

    sys.path.insert(0, str(CASE.parents[2]))  # `bench` lives at the repo root
    from exhibit_a.cli import main as cli_main

    out = tmp_path / "out"
    assert cli_main(["run", "--case", str(CASE), "--replay", "--out", str(out)]) == 0
    printed = capsys.readouterr().out
    assert '"proven": 1' in printed and "fix_verified=True" in printed
    events = [json.loads(line) for line in (out / "ledger.jsonl").read_text().splitlines()]
    verdicts = [e for e in events if e["type"] == "verdict"]
    assert [(v["payload"]["verdict"], v["payload"]["effect"]) for v in verdicts] == [("proven", "canary_write")]
    assert verdicts[0]["payload"]["fix_verified"] is True
