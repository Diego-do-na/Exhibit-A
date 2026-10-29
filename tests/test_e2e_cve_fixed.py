"""Fixed-code guard: the Starlette patch must yield no proven finding.

The CLI runs the whole loop on the fixed corpus case (Starlette 0.27.0 via the
same pinned-PyPI-install mechanism as the vulnerable case). The recorded exploit
passes on the patched code, so the loop must report no proven finding and write
no package: a green result means "nothing could be proven", never "safe".
"""

import json
from pathlib import Path

import pytest

from exhibit_a.cli import main
from exhibit_a.ledger import Ledger
from exhibit_a.schemas import EventType, VerdictValue

CASE = Path(__file__).resolve().parent.parent / "bench" / "corpus" / "starlette-cve-2023-29159-fixed"
CASE_ID = "starlette-cve-2023-29159-fixed"
FIXED_COMMIT = "1797de464124b090f10cf570441e8292936d63e3"


def test_case_is_fixed_and_pinned():
    spec = json.loads((CASE / "case.json").read_text(encoding="utf-8"))
    assert spec["cases"][0]["kind"] == "fixed"
    assert spec["cases"][0]["commit"] == FIXED_COMMIT
    assert "ground_truth" not in spec["cases"][0]
    assert spec["run"]["requirements"] == ["starlette==0.27.0", "anyio>=3.4,<5"]
    assert not (CASE / spec["run"]["tree"]).exists()


pytestmark = pytest.mark.docker


@pytest.fixture(scope="module")
def cycle(tmp_path_factory):
    out = tmp_path_factory.mktemp("starlette-fixed")
    code = main(["run", "--case", str(CASE), "--replay", "--out", str(out)])
    return code, out


def test_cli_exits_nonzero_with_no_package(cycle):
    code, out = cycle
    assert code == 1  # nothing proven, fixed and packaged
    assert not (out / "packages").exists()


def test_ledger_records_no_proven_verdict(cycle):
    _, out = cycle
    ledger = Ledger(out / "ledger.jsonl")
    totals = ledger.totals(CASE_ID)
    assert totals["verdicts"][VerdictValue.PROVEN.value] == 0
    verdicts = [e for e in ledger.replay(CASE_ID) if e.type == EventType.VERDICT]
    assert verdicts, "expected the raised suspicion to reach a verdict"
    # Exactly discarded_unproven: env_failure here would mean a broken sandbox, not a fixed app.
    found = [v.payload.get("verdict") for v in verdicts]
    assert found == [VerdictValue.DISCARDED_UNPROVEN.value] * len(verdicts), (
        f"expected every verdict to be discarded_unproven for the fixed case, got {found}; "
        "env_failure points at a broken sandbox rather than a clean fixed run"
    )
