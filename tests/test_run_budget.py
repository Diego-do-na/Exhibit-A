"""Budget abort path for the live ``run`` command.

When the shared CostMeter hits its limit mid-run, the command must exit
non-zero with a clear message while leaving the ledger flushed on disk.
These tests use a fake provider and a host runner so they need no Docker
and no network.
"""

import argparse
import json
import shutil
import subprocess
import os
import sys
from pathlib import Path

from exhibit_a.cli import run as run_mod
from exhibit_a.models import Completion, Role
from exhibit_a.models.config import PROVIDER_REGISTRY
from exhibit_a.models.cost import Pricing
from exhibit_a.oracle import run_oracle

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


def suspicion():
    return {
        "id": "S-BUDGET",
        "class": "path_traversal",
        "location": {"file": "app.py", "line": 1},
        "entry_point": ENTRY,
        "hypothesis": "name is joined to base_dir unchecked",
        "source": "query['name']",
    }


class PricedFakeLive:
    """Fake backend with per-role costs to trip the meter mid-run."""

    name = "fake-live-budget"
    pricing = Pricing()

    costs = {
        Role.ADVERSARY: 0.2,
        Role.TEST_WRITER: 5.0,
        Role.FIXER: 0.2,
        Role.DEFENDER: 0.2,
    }

    def __init__(self, spec=None) -> None:
        self.spec = spec

    def complete(self, role, prompt, schema):
        if role == Role.ADVERSARY:
            body = {"suspicions": [suspicion()]}
        elif role == Role.TEST_WRITER:
            body = {"test_source": TRAVERSAL % "../outside/canary.txt"}
        elif role == Role.FIXER:
            fixed = (FIXTURES / "fixed" / "app.py").read_text()
            body = {"files": [{"path": "app.py", "content": fixed}]}
        else:
            body = {"variants": [{"name": "dot", "test_source": TRAVERSAL % "./../outside/canary.txt"}]}
        cost = self.costs[role]
        return Completion(json.dumps(body), 10, 10, 1, model="fake-model", cost_usd=cost)


class FakeRunner:
    """Host runner: baseline by host pytest, exploits by the oracle."""

    def __init__(self, *args, **kwargs) -> None:
        self.requirements = kwargs.get("requirements", args[0] if args else ())

    def run_baseline(self, clone, test_path, timeout):
        env = {"PATH": os.environ["PATH"], "PYTHONPATH": clone, "PYTHONDONTWRITEBYTECODE": "1"}
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", test_path],
            cwd=clone, env=env, capture_output=True, timeout=timeout,
        )
        return {"outcome": "passed" if proc.returncode == 0 else "failed",
                "exit_code": proc.returncode,
                "stdout": proc.stdout.decode(), "stderr": proc.stderr.decode(),
                "oracle_events": []}

    def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect: str = "canary_read"):
        return run_oracle(app_root, test_path, entry_points, timeout=timeout, effect=effect)


def stage_case(root):
    case_dir = root / "case"
    shutil.copytree(FIXTURES / "vulnerable", case_dir / "tree")
    (case_dir / "baseline_test.py").write_text(BASELINE_TEST)
    spec = {
        "cases": [{"id": "budget-case"}],
        "run": {
            "tree": "tree",
            "source_file": "app.py",
            "baseline_test": "baseline_test.py",
            "recording": "replay.jsonl",
        },
    }
    case_file = case_dir / "case.json"
    case_file.write_text(json.dumps(spec))
    return case_file


def run_args(case_file, out, **overrides):
    args = argparse.Namespace(
        case=str(case_file), out=str(out), replay=False,
        provider="fake-live-budget", model="fake-model", budget_usd=1.0,
        repo=".", diff=None,
    )
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def register_fake(monkeypatch):
    def factory(spec):
        return PricedFakeLive(spec)

    monkeypatch.setitem(PROVIDER_REGISTRY, "fake-live-budget", factory)


def read_events(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def test_budget_exceeded_mid_run_aborts_cleanly(tmp_path, monkeypatch, capsys) -> None:
    """The meter trips on the test-writer call: non-zero exit, clear message."""
    monkeypatch.setattr(run_mod, "SandboxRunner", FakeRunner)
    register_fake(monkeypatch)
    case_file = stage_case(tmp_path)
    out = tmp_path / "out"

    code = run_mod.cmd_run(run_args(case_file, out, budget_usd=1.0))

    assert code != 0
    err = capsys.readouterr().err.lower()
    assert "budget exceeded" in err


def test_budget_exceeded_still_flushes_ledger(tmp_path, monkeypatch, capsys) -> None:
    """Events emitted before the abort (baseline, suspicion) reach the ledger."""
    monkeypatch.setattr(run_mod, "SandboxRunner", FakeRunner)
    register_fake(monkeypatch)
    case_file = stage_case(tmp_path)
    out = tmp_path / "out"

    run_mod.cmd_run(run_args(case_file, out, budget_usd=1.0))
    capsys.readouterr()

    ledger_path = out / "ledger.jsonl"
    assert ledger_path.exists()
    events = read_events(ledger_path)
    assert events, "expected events flushed before the budget abort"
    types = {event["type"] for event in events}
    assert "baseline_done" in types
    assert "suspicion_raised" in types
