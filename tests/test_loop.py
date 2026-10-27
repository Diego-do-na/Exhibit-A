"""Verification loop tests: one proven case, one discarded, one flaky.

Model answers come from the replay provider. A scripted provider records them into a JSONL
file once; the loop is then also run from the recording alone, without any recorder.

Execution goes through a fake ``TestRunner`` so these tests need no Docker; the tests marked
``docker`` check that the default ``SandboxRunner`` really runs the baseline in the sandbox.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from exhibit_a.ledger import Ledger
from exhibit_a.loop import Roles, SandboxRunner, VerificationLoop
from exhibit_a.loop import runner as loop_runner  # TestRunner by module, so pytest never collects it
from exhibit_a.models import Completion, ModelRole, ReplayProvider, Role
from exhibit_a.models.cost import Pricing
from exhibit_a.oracle import run_oracle
from exhibit_a.schemas import EventType

FIXTURES = Path(__file__).parent / "fixtures" / "oracle"
ENTRY = "App.handle_request"

BASELINE_TEST = '''\
from app import create_app


def test_known_file_is_served(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    app = create_app(str(tmp_path))
    assert app.handle_request("GET", "/download", {"name": "a.txt"}).body == "hello"
'''

TRAVERSAL = '''\
import os
from app import create_app


def test_download_cannot_escape_base_dir():
    app = create_app(os.environ["EXHIBIT_A_ALLOWED_DIR"])
    token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
    response = app.handle_request("GET", "/download", {"name": "%s"})
    assert token not in response.body
'''

# Attacks on the first run only, so the exploit is unstable across repeated runs.
FLAKY = '''\
import os
from pathlib import Path
from app import create_app

COUNTER = Path(%r)


def test_download_cannot_escape_base_dir():
    runs = int(COUNTER.read_text()) if COUNTER.exists() else 0
    COUNTER.write_text(str(runs + 1))
    app = create_app(os.environ["EXHIBIT_A_ALLOWED_DIR"])
    token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
    name = "../outside/canary.txt" if runs == 0 else "public.txt"
    assert token not in app.handle_request("GET", "/download", {"name": name}).body
'''


def suspicion(sid):
    return {
        "id": sid,
        "class": "path_traversal",
        "location": {"file": "app.py", "line": 45},
        "entry_point": ENTRY,
        "hypothesis": "name is joined to base_dir unchecked",
        "source": "query['name']",
    }


class Scripted:
    """Stands in for a real model while recording replay files."""

    name = "scripted"
    pricing = Pricing()

    def __init__(self, counter):
        self.counter = counter

    def complete(self, role, prompt, schema):
        if role == Role.ADVERSARY:
            body = {"suspicions": [suspicion(s) for s in ("S-PROVEN", "S-DROP", "S-FLAKY")]}
        elif role == Role.TEST_WRITER:
            if "SUSPICION S-PROVEN" in prompt:
                src = TRAVERSAL % "../outside/canary.txt"
            elif "SUSPICION S-DROP" in prompt:
                src = TRAVERSAL % "public.txt"  # benign request: the test passes
            else:
                src = FLAKY % str(self.counter)
            body = {"test_source": src}
        elif role == Role.FIXER:
            fixed = (FIXTURES / "fixed" / "app.py").read_text()
            body = {"files": [{"path": "app.py", "content": fixed}]}
        else:
            body = {"variants": [{"name": "dot-segment", "test_source": TRAVERSAL % "./../outside/./canary.txt"}]}
        return Completion(json.dumps(body), 10, 10, 1, model="scripted")


class FakeRunner:
    """Runs without Docker: the baseline by plain pytest on the host, exploits by the oracle."""

    def __init__(self, baseline_outcome=None):
        self.baseline_outcome = baseline_outcome  # forced outcome, or None to really run
        self.baselines = []

    def run_baseline(self, clone, test_path, timeout):
        self.baselines.append((clone, test_path))
        if self.baseline_outcome is not None:
            return {"outcome": self.baseline_outcome, "exit_code": 1, "stdout": "", "stderr": "",
                    "oracle_events": []}
        env = {"PATH": os.environ["PATH"], "PYTHONPATH": clone, "PYTHONDONTWRITEBYTECODE": "1"}
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", test_path],
            cwd=clone, env=env, capture_output=True, timeout=timeout,
        )
        return {"outcome": "passed" if proc.returncode == 0 else "failed", "exit_code": proc.returncode,
                "stdout": proc.stdout.decode(), "stderr": proc.stderr.decode(), "oracle_events": []}

    def run_exploit(self, app_root, test_path, entry_points, *, timeout):
        return run_oracle(app_root, test_path, entry_points, timeout=timeout)


def make_clone(root):
    clone = root / "clone"
    if not clone.exists():
        shutil.copytree(FIXTURES / "vulnerable", clone)
        (clone / "test_baseline.py").write_text(BASELINE_TEST)
    return clone


def make_loop(root, replay_path, recorder=None, *, runner=None):
    clone = make_clone(root)
    provider = ReplayProvider(replay_path, recorder)
    roles = Roles(*(ModelRole(r, provider) for r in (Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
    ledger = Ledger(root / "ledger.jsonl")
    return VerificationLoop(clone, root / "out", ledger, roles, "test_baseline.py",
                            run_id="r1", runner=runner or FakeRunner()), ledger


@pytest.fixture(scope="module")
def recorded(tmp_path_factory):
    root = tmp_path_factory.mktemp("loop")
    counter = root / "flaky.count"
    loop, ledger = make_loop(root, root / "replay.jsonl", Scripted(counter))
    return root, counter, loop.run("app.py"), ledger, loop.runner


def by_id(result, sid):
    return next(r for r in result.results if r.suspicion.id == sid)


def test_proven_case_is_fixed_verified_and_packaged(recorded):
    _, _, result, _, _ = recorded
    proven = by_id(result, "S-PROVEN")
    assert proven.verdict.verdict == "proven"
    assert proven.verdict.evidence.runs == 3
    assert proven.fix_verified
    assert proven.verdict.bypass_attempts.tried == 1
    assert proven.verdict.bypass_attempts.succeeded == 0
    pkg = proven.package_dir
    assert {p.name for p in pkg.iterdir()} == {"test_exploit.py", "fix.patch", "verdict.json", "evidence.json"}
    assert "+        base = os.path.realpath" in (pkg / "fix.patch").read_text()
    assert json.loads((pkg / "verdict.json").read_text())["verdict"] == "proven"


def test_discarded_case_is_dropped_and_counted(recorded):
    _, _, result, _, _ = recorded
    dropped = by_id(result, "S-DROP")
    assert dropped.verdict.verdict == "discarded_unproven"
    assert dropped.package_dir is None
    assert result.dropped == 2
    assert result.counts()["discarded_unproven"] == 1


def test_flaky_case_is_not_proven(recorded):
    _, _, result, _, _ = recorded
    flaky = by_id(result, "S-FLAKY")
    assert flaky.verdict.verdict == "flaky"
    assert flaky.package_dir is None


def test_every_step_is_in_the_ledger(recorded):
    _, _, _, ledger, _ = recorded
    types = {e.type for e in ledger.replay("r1")}
    assert types >= {
        EventType.BASELINE_DONE, EventType.SUSPICION_RAISED, EventType.EXPLOIT_WRITTEN,
        EventType.RUN_STARTED, EventType.ORACLE_EVENT, EventType.VERDICT, EventType.FIX_PROPOSED,
        EventType.BYPASS_ATTEMPT, EventType.BYPASS_RESULT, EventType.PACKAGED,
    }
    assert ledger.totals("r1")["verdicts"] == {
        "proven": 1, "discarded_unproven": 1, "invalid_test": 0, "flaky": 1, "env_failure": 0}
    assert ledger.totals("r1")["tokens_in"] > 0


def test_loop_runs_from_the_recording_alone(recorded, tmp_path):
    root, counter, first, _, _ = recorded
    counter.unlink(missing_ok=True)
    loop, _ = make_loop(tmp_path, root / "replay.jsonl")  # no recorder: a miss would raise
    again = loop.run("app.py")
    assert {r.suspicion.id: r.verdict.verdict for r in again.results} == {
        r.suspicion.id: r.verdict.verdict for r in first.results}


def test_failing_baseline_aborts_before_any_suspicion(tmp_path):
    loop, ledger = make_loop(tmp_path, tmp_path / "replay.jsonl", runner=FakeRunner("failed"))
    result = loop.run("app.py")
    assert not result.baseline_ok and result.results == []
    assert [e.type for e in ledger.read_all()] == [EventType.BASELINE_DONE]


def test_baseline_runs_through_the_injected_runner(recorded):
    root, _, _, _, runner = recorded
    assert isinstance(runner, loop_runner.TestRunner)
    clones = [Path(clone) for clone, _ in runner.baselines]
    assert clones[0] == (root / "clone").resolve()  # the clean clone, before anything else
    assert (root / "out" / "work" / "S-PROVEN" / "fixed").resolve() in clones  # VERIFY re-runs it
    assert {test for _, test in runner.baselines} == {"test_baseline.py"}


def test_default_runner_is_the_sandbox_with_the_case_requirements(tmp_path):
    clone = make_clone(tmp_path)
    loop = VerificationLoop(clone, tmp_path / "out", Ledger(tmp_path / "ledger.jsonl"), None,
                            "test_baseline.py", requirements=["anyio>=3.4,<5"])
    assert loop.runner == SandboxRunner(requirements=("anyio>=3.4,<5",))
    assert isinstance(loop.runner, loop_runner.TestRunner)


def test_sandbox_runner_hands_the_baseline_and_requirements_to_the_sandbox(monkeypatch):
    calls = []

    def fake_run(clone_path, test_path, timeout, requirements=None, image=None):
        calls.append((clone_path, test_path, timeout, requirements, image))
        return {"outcome": "passed", "exit_code": 0, "stdout": "", "stderr": "", "oracle_events": []}

    monkeypatch.setattr("exhibit_a.sandbox.run", fake_run)
    result = SandboxRunner(requirements=["anyio>=3.4,<5"]).run_baseline("/clone", "test_baseline.py", 30.0)
    assert result["outcome"] == "passed"
    assert calls == [("/clone", "test_baseline.py", 30.0, ["anyio>=3.4,<5"], None)]


@pytest.mark.docker
def test_sandbox_runner_runs_the_baseline_in_docker(tmp_path):
    clone = make_clone(tmp_path)
    result = SandboxRunner().run_baseline(str(clone), "test_baseline.py", 120.0)
    assert result["outcome"] == "passed", result["stdout"] + result["stderr"]
    assert "1 passed" in result["stdout"]


@pytest.mark.docker
def test_sandbox_runner_reports_a_failing_baseline_from_docker(tmp_path):
    clone = make_clone(tmp_path)
    (clone / "test_baseline.py").write_text("def test_broken():\n    assert False\n")
    result = SandboxRunner().run_baseline(str(clone), "test_baseline.py", 120.0)
    assert result["outcome"] == "failed"
    assert "1 failed" in result["stdout"]
