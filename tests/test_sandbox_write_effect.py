import json
import subprocess
import sys
from pathlib import Path

import pytest

from exhibit_a.loop.runner import SandboxRunner

CASE = Path(__file__).resolve().parent.parent / "bench" / "corpus" / "archive-extraction-pathtraversal"
EXPLOITS = CASE / "exploits"
ENTRY_POINTS = {"App.handle_request"}


@pytest.mark.docker
def test_archive_exploits_in_sandbox_prove_write_effect():
    runner = SandboxRunner()
    # vulnerable tree: true exploits must be proven (canary_write)
    for exploit in ("exploit_true_relative.py", "exploit_true_absolute.py"):
        res = runner.run_exploit(CASE / "vulnerable", EXPLOITS / exploit, ENTRY_POINTS, timeout=120.0, effect="canary_write")
        assert res.test_outcome == "failed"
        assert res.observed_effect and res.provenance_ok, f"{exploit}: {res.reason}"

    # fixed tree: same exploits are not proven
    for exploit in ("exploit_true_relative.py", "exploit_true_absolute.py"):
        res = runner.run_exploit(CASE / "fixed", EXPLOITS / exploit, ENTRY_POINTS, timeout=120.0, effect="canary_write")
        assert res.test_outcome == "passed"
        assert not res.observed_effect

    # fixed_incomplete: absolute-path exploit still proves the write effect
    res = runner.run_exploit(CASE / "fixed_incomplete", EXPLOITS / "exploit_true_absolute.py", ENTRY_POINTS, timeout=120.0, effect="canary_write")
    assert res.test_outcome == "failed" and res.observed_effect and res.provenance_ok

    # benign and cheating variants do not prove
    for exploit in ("exploit_benign_safe_archive.py", "exploit_wrong_reason_crash.py", "exploit_cheat_writes_canary.py", "exploit_cheat_calls_sink_directly.py", "exploit_mock_fabricated_escape.py", "exploit_flaky_escape.py"):
        res = runner.run_exploit(CASE / "vulnerable", EXPLOITS / exploit, ENTRY_POINTS, timeout=120.0, effect="canary_write")
        # benign or wrong-reason should not be proven (may pass or fail without effect/provenance)
        assert not (res.observed_effect and res.provenance_ok)

