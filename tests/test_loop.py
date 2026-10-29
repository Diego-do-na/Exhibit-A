"""Verification loop tests: one proven case, one discarded, one flaky.

Model answers come from the replay provider. A scripted provider records them into a JSONL
file once; the loop is then also run from the recording alone, without any recorder.

Execution goes through a fake ``TestRunner`` so these tests need no Docker; the tests marked
``docker`` check that the default ``SandboxRunner`` really runs the baseline, the exploits and
the defender's variants in the sandbox, judged from the oracle events of the container.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest

from exhibit_a.ci.summary import build_result
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


class _IneffectiveFixScripted:
    """The fixer returns the vulnerable file plus a comment: the fix changes nothing.

    The defender's variant is the exploit itself, so it still proves the flaw
    against the "fixed" code.
    """

    name = "scripted"
    pricing = Pricing()

    def __init__(self, sid):
        self.sid = sid

    def complete(self, role, prompt, schema):
        if role == Role.ADVERSARY:
            body = {"suspicions": [suspicion(self.sid)]}
        elif role == Role.TEST_WRITER:
            body = {"test_source": TRAVERSAL % "../outside/canary.txt"}
        elif role == Role.FIXER:
            original = (FIXTURES / "vulnerable" / "app.py").read_text()
            body = {"files": [{"path": "app.py", "content": original + "\n# ineffective fix: comment only\n"}]}
        else:
            body = {"variants": [{"name": "same-as-exploit", "test_source": TRAVERSAL % "../outside/canary.txt"}]}
        return Completion(json.dumps(body), 10, 10, 1, model="scripted")


def _run_ineffective_fix(tmp_path, sid):
    loop, ledger = make_loop(tmp_path, tmp_path / "replay.jsonl", _IneffectiveFixScripted(sid))
    loop.run_id = "r-noop"
    return loop.run("app.py"), ledger


def test_ineffective_fix_is_discarded_unproven_and_red_never_follows(tmp_path):
    result, ledger = _run_ineffective_fix(tmp_path, "S-NOOP-FIX")
    assert len(result.results) == 1
    outcome = result.results[0]
    assert outcome.verdict.verdict == "discarded_unproven"
    assert outcome.reason == "exploit proven but no verified fix"
    assert not outcome.fix_verified
    assert outcome.package_dir is None
    verdict_events = [
        e for e in ledger.replay("r-noop")
        if e.type == EventType.VERDICT and e.payload.get("suspicion_id") == "S-NOOP-FIX"
    ]
    assert len(verdict_events) == 1  # FIX/VERIFY ran before the single verdict
    assert verdict_events[0].payload.get("effect") == "canary_read"
    assert "reason_code" in verdict_events[0].payload
    assert build_result(ledger.read_all())["proven"] == 0


def test_defender_sees_a_bypass_through_the_fixed_code_on_the_host_path(tmp_path):
    result, _ = _run_ineffective_fix(tmp_path, "S-NOOP-BYPASS")
    outcome = result.results[0]
    assert outcome.verdict.bypass_attempts.tried == 1
    assert outcome.verdict.bypass_attempts.succeeded == 1


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


def _admitted(stack):
    """Frames as the v2 oracle plugin writes them: app frames carry their first line and admission."""
    from exhibit_a.oracle.plugin import code_keys

    lines = dict(code_keys((FIXTURES / "vulnerable" / "app.py").read_bytes()))
    for frame in stack:
        if frame["file"] == "/workspace/app.py":
            frame.update(line=lines[frame["qualname"]], admitted=True)
    return stack


def test_sandbox_runner_stages_the_exploit_with_a_canary_and_judges_container_events(monkeypatch, tmp_path):
    calls = []

    def fake_run(clone_path, test_path, timeout, requirements=None, image=None,
                 canary_path=None, events_path=None, env=None, canary_mount=None, manifest=None):
        stage = Path(clone_path)
        calls.append({
            "files": {p.relative_to(stage).as_posix() for p in stage.rglob("*") if p.is_file()},
            "test_path": test_path, "requirements": requirements, "canary_mount": canary_mount,
            "canary": Path(canary_path).read_text().strip(), "env": dict(env),
        })
        oracle_dir = test_path.split("/")[0]
        stack = _admitted([
            {"file": f"/workspace/{oracle_dir}/test_exploit.py", "function": "test_x", "qualname": "test_x"},
            {"file": "/workspace/app.py", "function": "handle_request", "qualname": "App.handle_request"},
            {"file": "/workspace/app.py", "function": "read_file", "qualname": "read_file"},
        ])
        # The fields the plugin records since A-11 F2/F4 (flags, access, requested path).
        event = {"path": "/tmp/exhibit_a_oracle/outside/canary.txt", "mode": "r", "flags": 0, "access": "read",
                 "requested": "/tmp/exhibit_a_oracle/allowed/../outside/canary.txt", "stack": stack}
        events = [event, {"garbage": True}]
        return {"outcome": "failed", "exit_code": 1, "stdout": "", "stderr": "", "oracle_events": events}

    monkeypatch.setattr("exhibit_a.sandbox.run", fake_run)
    clone = make_clone(tmp_path)
    exploit = tmp_path / "test_exploit.py"
    exploit.write_text(TRAVERSAL % "../outside/canary.txt")
    judgement = SandboxRunner(requirements=["anyio>=3.4,<5"]).run_exploit(clone, exploit, {ENTRY}, timeout=30.0)

    assert judgement.test_outcome == "failed" and judgement.observed_effect and judgement.provenance_ok
    assert len(judgement.events) == 1  # the malformed container event is dropped
    (call,) = calls
    oracle_dir = call["test_path"].split("/")[0]
    assert call["test_path"] == f"{oracle_dir}/test_exploit.py"
    assert {"app.py", "test_baseline.py", f"{oracle_dir}/test_exploit.py", f"{oracle_dir}/conftest.py"} <= call["files"]
    assert call["requirements"] == ["anyio>=3.4,<5"]
    assert call["env"]["EXHIBIT_A_CANARY_TOKEN"] == call["canary"]
    # The canary sits beside the allowed directory, as with the host oracle.
    allowed = PurePosixPath(call["env"]["EXHIBIT_A_ALLOWED_DIR"])
    assert PurePosixPath(call["canary_mount"]) == allowed.parent / "outside" / "canary.txt"
    assert not (clone / oracle_dir).exists()  # the clone itself is never written to


def test_sandbox_runner_judges_provenance_by_container_paths(monkeypatch, tmp_path):
    def fake_run(clone_path, test_path, timeout, **kwargs):
        oracle_dir = test_path.split("/")[0]
        stack = _admitted([  # the test called the sink directly: no entry point on the stack
            {"file": f"/workspace/{oracle_dir}/test_exploit.py", "function": "test_x", "qualname": "test_x"},
            {"file": "/workspace/app.py", "function": "read_file", "qualname": "read_file"},
        ])
        events = [{"path": "/tmp/exhibit_a_oracle/outside/canary.txt", "mode": "r", "flags": 0, "access": "read",
                   "requested": "/tmp/exhibit_a_oracle/outside/canary.txt", "stack": stack}]
        return {"outcome": "failed", "exit_code": 1, "stdout": "", "stderr": "", "oracle_events": events}

    monkeypatch.setattr("exhibit_a.sandbox.run", fake_run)
    exploit = tmp_path / "test_exploit.py"
    exploit.write_text("def test_x():\n    pass\n")
    judgement = SandboxRunner().run_exploit(make_clone(tmp_path), exploit, {ENTRY}, timeout=30.0)
    assert judgement.observed_effect and not judgement.provenance_ok
    assert "entry point" in judgement.reason


@pytest.mark.parametrize("result, outcome", [
    ({"outcome": "passed", "exit_code": 0}, "passed"),
    ({"outcome": "failed", "exit_code": 1}, "failed"),
    ({"outcome": "failed", "exit_code": 2}, "error"),  # collection or usage error, not a failure
    ({"outcome": "timeout", "exit_code": None}, "timeout"),
])
def test_sandbox_runner_reads_pytest_exit_codes_like_the_host_oracle(monkeypatch, tmp_path, result, outcome):
    monkeypatch.setattr("exhibit_a.sandbox.run", lambda *a, **k: {
        **result, "stdout": "", "stderr": "", "oracle_events": []})
    exploit = tmp_path / "test_exploit.py"
    exploit.write_text("def test_x():\n    pass\n")
    judgement = SandboxRunner().run_exploit(make_clone(tmp_path), exploit, {ENTRY}, timeout=30.0)
    assert judgement.test_outcome == outcome and not judgement.observed_effect


def test_sandbox_that_cannot_run_the_exploit_is_an_env_failure(monkeypatch, tmp_path):
    monkeypatch.setattr("exhibit_a.sandbox.run", lambda *a, **k: {
        "outcome": "env_failure", "exit_code": None, "stdout": "", "stderr": "docker not available",
        "oracle_events": []})
    exploit = tmp_path / "test_exploit.py"
    exploit.write_text("def test_x():\n    pass\n")
    with pytest.raises(OSError, match="docker not available"):
        SandboxRunner().run_exploit(make_clone(tmp_path), exploit, {ENTRY}, timeout=30.0)


class _BaselineOnlyOnHost(FakeRunner):
    """Host baseline, sandboxed exploits: isolates the exploit path for the loop test below."""

    def run_exploit(self, app_root, test_path, entry_points, *, timeout):
        return SandboxRunner().run_exploit(app_root, test_path, entry_points, timeout=timeout)


def test_loop_turns_a_sandbox_env_failure_into_an_env_failure_verdict(recorded, tmp_path, monkeypatch):
    root = recorded[0]
    monkeypatch.setattr("exhibit_a.sandbox.run", lambda *a, **k: {
        "outcome": "env_failure", "exit_code": None, "stdout": "", "stderr": "docker not available",
        "oracle_events": []})
    loop, _ = make_loop(tmp_path, root / "replay.jsonl", runner=_BaselineOnlyOnHost())
    result = loop.run("app.py")
    assert {r.verdict.verdict for r in result.results} == {"env_failure"}


@pytest.mark.docker
@pytest.mark.parametrize("app, exploit, outcome, effect, provenance", [
    ("vulnerable", "exploit_traversal.py", "failed", True, True),
    ("fixed", "exploit_traversal.py", "passed", False, False),
    ("vulnerable", "exploit_crashes_early.py", "failed", False, False),
    ("vulnerable", "exploit_cheating.py", "failed", True, False),
    ("vulnerable", "exploit_reads_itself.py", "failed", True, False),
])
def test_sandbox_runner_judges_exploits_run_in_docker(app, exploit, outcome, effect, provenance):
    judgement = SandboxRunner().run_exploit(
        FIXTURES / app, FIXTURES / "exploits" / exploit, {ENTRY}, timeout=120.0)
    assert (judgement.test_outcome, judgement.observed_effect, judgement.provenance_ok) == (
        outcome, effect, provenance), judgement.reason
    for event in judgement.events:
        app_frames = [f.file for f in event.stack if f.file.endswith("/app.py")]
        assert set(app_frames) <= {"/workspace/app.py"}  # judged by container paths


@pytest.mark.docker
def test_loop_proves_fixes_and_defends_in_docker(recorded, tmp_path):
    root = recorded[0]
    loop, ledger = make_loop(tmp_path, root / "replay.jsonl", runner=SandboxRunner())
    result = loop.run("app.py")
    assert result.baseline_ok
    proven = by_id(result, "S-PROVEN")
    assert proven.verdict.verdict == "proven", proven.reason
    assert proven.fix_verified
    assert proven.verdict.bypass_attempts.tried == 1
    assert proven.verdict.bypass_attempts.succeeded == 0
    assert by_id(result, "S-DROP").verdict.verdict == "discarded_unproven"
    oracle = [e for e in ledger.replay("r1") if e.type == EventType.ORACLE_EVENT]
    assert oracle and all(e.payload["event"]["path"] == "/tmp/exhibit_a_oracle/outside/canary.txt" for e in oracle)


PREFIX_APP = '''\
import os


def read_file(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class App:
    def __init__(self, base_dir):
        self.base_dir = base_dir

    def handle_request(self, name):
        full = os.path.realpath(os.path.join(self.base_dir, name))
        base = os.path.realpath(self.base_dir)
        # BUG: a string prefix check, so a sibling such as "<base>side" passes.
        if os.path.commonprefix([full, base]) != base:
            return ""
        return read_file(full)
'''

PREFIX_EXPLOIT = '''\
import os
from pathlib import Path

from app import App


def test_sibling_directory_is_not_served():
    work = Path(os.environ["EXHIBIT_A_ALLOWED_DIR"]).parent
    served = work / "out"  # a string prefix of the canary's directory "outside"
    served.mkdir()
    assert os.environ["EXHIBIT_A_CANARY_TOKEN"] not in App(str(served)).handle_request("../outside/canary.txt")
'''


@pytest.mark.docker
def test_sandbox_canary_is_a_real_file_for_apps_that_canonicalise_paths(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "app.py").write_text(PREFIX_APP)
    exploit = tmp_path / "test_exploit.py"
    exploit.write_text(PREFIX_EXPLOIT)
    judgement = SandboxRunner().run_exploit(app, exploit, {ENTRY}, timeout=120.0)
    assert (judgement.test_outcome, judgement.observed_effect, judgement.provenance_ok) == (
        "failed", True, True), judgement.reason
