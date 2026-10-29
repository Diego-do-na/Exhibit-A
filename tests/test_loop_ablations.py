"""The real loop honours the ablation flags of bench/flags.py (SPEC section 11).

Model answers come from a scripted provider and execution from a fake ``TestRunner`` that
returns scripted oracle judgements, so these tests need no Docker. Three suspicions cover the
cases the flags tell apart:

* S-REAL: the exploit fails with the intended effect through the entry point, the fix stops it;
* S-WRONG: the exploit fails, but for the wrong reason (no oracle effect);
* S-PASS: the exploit passes, so the suspicion did not materialise.

The defender proposes one variant that still gets through the fix.
"""

import json
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench.flags import ABLATIONS, Flags  # noqa: E402
from exhibit_a.ledger import Ledger  # noqa: E402
from exhibit_a.loop import Roles, VerificationLoop  # noqa: E402
from exhibit_a.loop.pipeline import FullSystem  # noqa: E402
from exhibit_a.models import Completion, ModelRole, Role  # noqa: E402
from exhibit_a.models.cost import Pricing  # noqa: E402
from exhibit_a.oracle import Judgement  # noqa: E402
from exhibit_a.schemas import EventType  # noqa: E402

ENTRY = "App.handle_request"
IDS = ("S-REAL", "S-WRONG", "S-PASS")


def suspicion(sid):
    return {
        "id": sid,
        "class": "path_traversal",
        "location": {"file": "app.py", "line": 1},
        "entry_point": ENTRY,
        "hypothesis": "name is joined to base_dir unchecked",
        "source": "query['name']",
    }


class Scripted:
    """A model provider with fixed answers that counts the calls per role."""

    name = "scripted"
    pricing = Pricing()

    def __init__(self):
        self.calls = {role: 0 for role in Role}

    def complete(self, role, prompt, schema):
        self.calls[role] += 1
        if role == Role.ADVERSARY:
            body = {"suspicions": [suspicion(sid) for sid in IDS]}
        elif role == Role.TEST_WRITER:
            sid = next(s for s in IDS if f"SUSPICION {s}" in prompt)
            body = {"test_source": f"# {sid}\ndef test_x():\n    pass\n"}
        elif role == Role.FIXER:
            body = {"files": [{"path": "app.py", "content": "FIXED = True\n"}]}
        else:
            body = {"variants": [{"name": "dot-segment", "test_source": "# BYPASS\ndef test_x():\n    pass\n"}]}
        return Completion(json.dumps(body), 10, 10, 1, model="scripted")


def judgement(outcome, effect=False, provenance=False):
    return Judgement(observed_effect=effect, provenance_ok=provenance, reason=f"scripted {outcome}",
                     test_outcome=outcome)


class FakeRunner:
    """Baselines always pass; exploits are judged by the marker on their first line."""

    def __init__(self):
        self.exploits = []  # (marker, ran on the fixed code)

    def run_baseline(self, clone, test_path, timeout):
        return {"outcome": "passed", "exit_code": 0, "stdout": "", "stderr": "", "oracle_events": []}

    def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect: str = "canary_read"):
        marker = Path(test_path).read_text().splitlines()[0].removeprefix("# ")
        on_fixed = Path(app_root).name == "fixed"
        self.exploits.append((marker, on_fixed))
        if marker == "S-REAL":
            return judgement("passed") if on_fixed else judgement("failed", True, True)
        if marker == "S-WRONG":
            return judgement("failed")
        if marker == "BYPASS":
            return judgement("failed", True, True)
        return judgement("passed")


def run_loop(tmp_path, flags=None):
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "app.py").write_text("FIXED = False\n")
    provider = Scripted()
    roles = Roles(*(ModelRole(r, provider) for r in (Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
    ledger = Ledger(tmp_path / "ledger.jsonl")
    runner = FakeRunner()
    loop = VerificationLoop(clone, tmp_path / "out", ledger, roles, "test_baseline.py",
                            run_id="r1", runner=runner, flags=flags)
    return loop.run("app.py"), ledger, runner, provider


def verdicts(result):
    return {r.suspicion.id: r.verdict.verdict.value for r in result.results}


def by_id(result, sid):
    return next(r for r in result.results if r.suspicion.id == sid)


def types(ledger):
    return [e.type for e in ledger.replay("r1")]


def test_default_flags_are_the_full_system_of_the_benchmark():
    assert asdict(FullSystem()) == asdict(Flags()) == asdict(ABLATIONS["full"])


def test_full_system_proves_only_the_real_exploit_and_counts_the_bypass(tmp_path):
    result, ledger, runner, _ = run_loop(tmp_path)
    assert verdicts(result) == {"S-REAL": "proven", "S-WRONG": "invalid_test", "S-PASS": "discarded_unproven"}
    real = by_id(result, "S-REAL")
    assert real.fix_verified
    assert real.verdict.bypass_attempts.tried == 1 and real.verdict.bypass_attempts.succeeded == 1
    assert real.verdict.evidence.provenance["checked"] is True
    assert [s.id for s in result.reported] == ["S-REAL"]
    assert ("S-REAL", True) in runner.exploits
    baseline = next(e for e in ledger.replay("r1") if e.type == EventType.BASELINE_DONE)
    assert baseline.payload["flags"] == asdict(Flags())


def test_naive_reports_every_suspicion_without_exploits_or_verdicts(tmp_path):
    result, ledger, runner, provider = run_loop(tmp_path, ABLATIONS["baseline"])
    assert result.naive and result.results == []
    assert [s.id for s in result.reported] == list(IDS)
    assert runner.exploits == []
    assert provider.calls[Role.TEST_WRITER] == provider.calls[Role.FIXER] == provider.calls[Role.DEFENDER] == 0
    assert set(types(ledger)) == {EventType.BASELINE_DONE, EventType.SUSPICION_RAISED}
    assert not (tmp_path / "out" / "packages").exists()


def test_oracle_off_accepts_a_plain_failing_test(tmp_path):
    result, _, _, _ = run_loop(tmp_path, Flags(oracle=False))
    assert verdicts(result) == {"S-REAL": "proven", "S-WRONG": "proven", "S-PASS": "discarded_unproven"}
    wrong = by_id(result, "S-WRONG")
    assert wrong.verdict.evidence.provenance == {"ok": False, "checked": False, "entry_point": ENTRY}
    assert wrong.verdict.evidence.oracle["checked"] is False
    evidence = json.loads((wrong.package_dir / "evidence.json").read_text())
    assert evidence["flags"]["oracle"] is False
    # Still the full VERIFY otherwise: the wrong-reason failure keeps failing on the fixed code.
    assert not wrong.fix_verified
    assert by_id(result, "S-REAL").fix_verified


def test_differential_off_skips_the_exploit_rerun_on_the_fixed_code(tmp_path):
    result, ledger, runner, _ = run_loop(tmp_path, ABLATIONS["no_differential"])
    assert verdicts(result)["S-REAL"] == "proven"
    real = by_id(result, "S-REAL")
    assert not real.fix_verified  # nothing showed the fix stops the exploit
    assert not (real.package_dir / "fix.patch").exists()
    assert ("S-REAL", True) not in runner.exploits
    assert not [e for e in ledger.replay("r1") if e.type == EventType.RUN_STARTED and e.payload.get("on") == "fixed"]
    assert real.verdict.bypass_attempts.tried == 1  # the defender still runs


def test_defender_off_skips_the_bypass_variants(tmp_path):
    result, ledger, runner, provider = run_loop(tmp_path, ABLATIONS["no_defender"])
    real = by_id(result, "S-REAL")
    assert real.verdict.verdict == "proven" and real.fix_verified
    assert real.verdict.bypass_attempts.tried == 0 and real.verdict.bypass_attempts.succeeded == 0
    assert provider.calls[Role.DEFENDER] == 0
    assert all(marker != "BYPASS" for marker, _ in runner.exploits)
    assert EventType.BYPASS_ATTEMPT not in types(ledger) and EventType.BYPASS_RESULT not in types(ledger)


def test_failing_test_only_proves_any_failure_and_verifies_nothing_after_the_fix(tmp_path):
    result, ledger, runner, provider = run_loop(tmp_path, ABLATIONS["failing_test_only"])
    assert verdicts(result) == {"S-REAL": "proven", "S-WRONG": "proven", "S-PASS": "discarded_unproven"}
    assert not any(r.fix_verified for r in result.results)
    assert not any(on_fixed for _, on_fixed in runner.exploits)
    assert provider.calls[Role.DEFENDER] == 0
    assert EventType.BYPASS_ATTEMPT not in types(ledger)


@pytest.mark.parametrize("name", sorted(ABLATIONS))
def test_every_benchmark_ablation_runs_and_is_recorded(tmp_path, name):
    flags = ABLATIONS[name]
    result, ledger, _, _ = run_loop(tmp_path, flags)
    baseline = next(e for e in ledger.replay("r1") if e.type == EventType.BASELINE_DONE)
    assert baseline.payload["flags"] == asdict(flags)
    verdict_events = [e for e in ledger.replay("r1") if e.type == EventType.VERDICT]
    assert len(verdict_events) == (0 if flags.naive else len(IDS))
    assert {s.id for s in result.reported} >= {"S-REAL"}
