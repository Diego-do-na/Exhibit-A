"""First real CVE end to end: Starlette CVE-2023-29159, from recorded model answers.

The CLI runs the whole loop on the corpus case. The package it writes must hold an exploit
test that fails on the vulnerable code and passes once the patch is applied.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from exhibit_a.cli import main
from exhibit_a.ledger import Ledger
from exhibit_a.oracle import run_oracle
from exhibit_a.schemas import EventType

try:
    import anyio  # noqa: F401  (the vendored Starlette needs it; declared in the dev extra of pyproject.toml)
except ImportError:  # pragma: no cover
    pytest.fail("anyio is required by the Starlette case: pip install 'anyio>=3.4,<5'", pytrace=False)

CASE = Path(__file__).resolve().parent.parent / "bench" / "corpus" / "starlette-cve-2023-29159"
ENTRY_POINTS = {"StaticFiles.__call__"}
SUSPICION = "starlette-staticfiles-prefix"


@pytest.fixture(scope="module")
def cycle(tmp_path_factory):
    out = tmp_path_factory.mktemp("first-cve")
    code = main(["run", "--case", str(CASE), "--replay", "--out", str(out)])
    return code, out


def test_cli_closes_the_cycle(cycle, capsys):
    code, out = cycle
    assert code == 0
    assert (out / "packages" / SUSPICION).is_dir()


def test_package_contents_and_verdict(cycle):
    _, out = cycle
    pkg = out / "packages" / SUSPICION
    assert {p.name for p in pkg.iterdir()} == {"test_exploit.py", "fix.patch", "verdict.json", "evidence.json"}
    verdict = json.loads((pkg / "verdict.json").read_text())
    assert verdict["verdict"] == "proven"
    assert verdict["evidence"]["fails_on"] == "vulnerable"
    assert verdict["evidence"]["passes_on"] == "fixed"
    assert verdict["evidence"]["runs"] == 3
    assert verdict["bypass_attempts"] == {"tried": 2, "succeeded": 0}
    patch = (pkg / "fix.patch").read_text()
    assert "-            if os.path.commonprefix([full_path, directory]) != directory:" in patch
    assert "+            if os.path.commonpath([full_path, directory]) != directory:" in patch


def test_exploit_is_red_on_vulnerable_and_green_on_fixed(cycle, tmp_path):
    _, out = cycle
    pkg = out / "packages" / SUSPICION
    exploit = pkg / "test_exploit.py"

    red = run_oracle(CASE / "vulnerable", exploit, ENTRY_POINTS)
    assert red.test_outcome == "failed"
    assert red.observed_effect and red.provenance_ok

    fixed = tmp_path / "fixed"
    shutil.copytree(CASE / "vulnerable", fixed)
    applied = subprocess.run(
        ["patch", "-p1", "-i", str(pkg / "fix.patch")], cwd=fixed, capture_output=True, text=True
    )
    assert applied.returncode == 0, applied.stdout + applied.stderr
    green = run_oracle(fixed, exploit, ENTRY_POINTS)
    assert green.test_outcome == "passed"
    assert not green.observed_effect


def test_ledger_records_the_cycle(cycle):
    _, out = cycle
    ledger = Ledger(out / "ledger.jsonl")
    types = {e.type for e in ledger.replay("starlette-cve-2023-29159")}
    assert types >= {
        EventType.BASELINE_DONE, EventType.SUSPICION_RAISED, EventType.EXPLOIT_WRITTEN,
        EventType.ORACLE_EVENT, EventType.VERDICT, EventType.FIX_PROPOSED,
        EventType.BYPASS_RESULT, EventType.PACKAGED,
    }


def test_cli_needs_replay_for_a_case(capsys):
    assert main(["run", "--case", str(CASE)]) == 2
    assert "--replay" in capsys.readouterr().err
