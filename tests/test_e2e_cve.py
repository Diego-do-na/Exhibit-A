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

CASE = Path(__file__).resolve().parent.parent / "bench" / "corpus" / "starlette-cve-2023-29159"
ENTRY_POINTS = {"StaticFiles.__call__"}
SUSPICION = "starlette-staticfiles-prefix"


def install_starlette(target: Path, version: str = "0.26.1") -> None:
    """Install the pinned Starlette version under a temporary app root for direct oracle runs."""
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [
            "python",
            "-m",
            "pip",
            "install",
            "--target",
            str(target),
            f"starlette=={version}",
            "anyio>=3.4,<5",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.fixture(scope="module")
def cycle(tmp_path_factory):
    out = tmp_path_factory.mktemp("first-cve")
    code = main(["run", "--case", str(CASE), "--replay", "--out", str(out)])
    return code, out


def test_case_uses_pinned_pypi_installation():
    spec = json.loads((CASE / "case.json").read_text(encoding="utf-8"))
    assert spec["run"]["requirements"] == ["starlette==0.26.1", "anyio>=3.4,<5"]
    assert not (CASE / "vulnerable").exists()


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

    vulnerable = tmp_path / "vulnerable"
    install_starlette(vulnerable, version="0.26.1")
    oracle_dir = vulnerable / "_exhibit_a_oracle"
    oracle_dir.mkdir()
    exploit_path = oracle_dir / "test_exploit.py"
    shutil.copyfile(exploit, exploit_path)
    red = run_oracle(vulnerable, exploit_path, ENTRY_POINTS)
    assert red.test_outcome == "failed"
    assert red.observed_effect and red.provenance_ok
    # Assert the oracle observed the application entry point reached from the test
    assert any(
        any(f.qualname == "StaticFiles.__call__" for f in e.stack) and any(
            i < next(j for j, f in enumerate(e.stack) if f.qualname == "StaticFiles.__call__")
            for i, f in enumerate(e.stack) if (f.file.startswith(str(oracle_dir)) or f.file.startswith(str(vulnerable)))
        )
        for e in red.events
    )

    fixed = tmp_path / "fixed"
    shutil.copytree(vulnerable, fixed)
    applied = subprocess.run(
        ["patch", "-p1", "-i", str(pkg / "fix.patch")], cwd=fixed, capture_output=True, text=True
    )
    assert applied.returncode == 0, applied.stdout + applied.stderr
    green = run_oracle(fixed, fixed / "_exhibit_a_oracle" / "test_exploit.py", ENTRY_POINTS)
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


def test_cli_without_replay_builds_live_roles(capsys, monkeypatch):
    # T037: without --replay the CLI no longer exits 2, it builds real provider roles.
    # Stub the role builder so the test never reaches a real provider.
    def refuse(args, meter):
        raise ValueError("stubbed: no live provider in tests")

    monkeypatch.setattr("exhibit_a.cli.run._live_roles", refuse)
    assert main(["run", "--case", str(CASE)]) == 1
    assert "cannot build live roles" in capsys.readouterr().err
