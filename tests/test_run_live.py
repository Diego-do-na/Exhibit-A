"""Tests for the live ``run`` path (real providers through the registry).

The loop runs with a fake provider (registered under ``fake-live``) and a fake
runner (host baseline, host oracle), so these tests need no Docker and no
network. They prove that ``run`` without ``--replay`` builds its roles via
``models.config`` from the provider/model pair, shares one ``CostMeter`` from
``--budget-usd`` across roles, executes through the sandbox-backed runner
seam, and still supports ``--replay`` for recorded cases.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from exhibit_a.cli import run as run_mod
from exhibit_a.cli import main as cli_main
from exhibit_a.ledger import Ledger
from exhibit_a.loop import Roles, VerificationLoop
from exhibit_a.loop import pipeline as loop_pipeline
from exhibit_a.models import Completion, ModelRole, ReplayProvider, Role
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
        "id": "S-LIVE",
        "class": "path_traversal",
        "location": {"file": "app.py", "line": 1},
        "entry_point": ENTRY,
        "hypothesis": "name is joined to base_dir unchecked",
        "source": "query['name']",
    }


class FakeLive:
    """Stands in for a real model backend; answers one proven suspicion."""

    name = "fake-live"
    pricing = Pricing()
    cost_usd = 0.5

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
        return Completion(json.dumps(body), 10, 10, 1, model="fake-model", cost_usd=self.cost_usd)


class FakeRunner:
    """Runs without Docker: the baseline by host pytest, exploits by the oracle."""

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


@pytest.fixture
def fake_provider():
    """Register the fake backend and hand back the specs each factory call saw."""
    seen = []

    def factory(spec):
        seen.append(spec)
        return FakeLive(spec)
    saved = dict(PROVIDER_REGISTRY)
    PROVIDER_REGISTRY["fake-live"] = factory
    try:
        yield seen
    finally:
        PROVIDER_REGISTRY.clear()
        PROVIDER_REGISTRY.update(saved)


def stage_case(root):
    """Stage a minimal benchmark case directory; return its case.json path."""
    case_dir = root / "case"
    shutil.copytree(FIXTURES / "vulnerable", case_dir / "tree")
    (case_dir / "baseline_test.py").write_text(BASELINE_TEST)
    spec = {
        "cases": [{"id": "live-case"}],
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
        provider="fake-live", model="fake-model", budget_usd=10.0,
        repo=".", diff=None,
    )
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def test_cli_flags_and_env_precedence(tmp_path, monkeypatch, fake_provider, capsys):
    """Verify CLI flags override env vars and env vars are used when flags are absent."""
    monkeypatch.setattr(run_mod, "SandboxRunner", FakeRunner)
    case_file = stage_case(tmp_path)
    out = tmp_path / "out"

    # Set env vars and ensure they are used when flags absent.
    monkeypatch.setenv("EXHIBIT_A_PROVIDER", "fake-live")
    monkeypatch.setenv("EXHIBIT_A_MODEL", "fake-model")
    # Call via CLI main (parses and dispatches to cmd_run)
    rc = cli_main(["run", "--case", str(case_file), "--out", str(out), "--budget-usd", "10.0"])
    assert rc == 0
    captured = fake_provider
    assert captured
    assert all(spec.provider == "fake-live" for spec in captured)
    assert all(spec.model == "fake-model" for spec in captured)

    # Flags override env vars.
    out2 = tmp_path / "out2"
    rc2 = cli_main(["run", "--case", str(case_file), "--out", str(out2), "--provider", "fake-live", "--model", "override-model", "--budget-usd", "10.0"])
    assert rc2 == 0
    # The last factory calls should have seen the override model.
    assert any(spec.model == "override-model" for spec in fake_provider)


def test_model_without_provider_uses_default_provider(tmp_path, monkeypatch, capsys, fake_provider):
    """--model without --provider uses the default provider name (ollama) — we override ollama in the registry."""
    monkeypatch.setattr(run_mod, "SandboxRunner", FakeRunner)
    case_file = stage_case(tmp_path)
    out = tmp_path / "out3"

    # Temporarily register a fake 'ollama' provider to observe the spec.
    from exhibit_a.models.config import PROVIDER_REGISTRY

    seen = []

    def ollama_factory(spec):
        seen.append(spec)
        return FakeLive(spec)

    monkeypatch.setitem(PROVIDER_REGISTRY, "ollama", ollama_factory)
    rc = cli_main(["run", "--case", str(case_file), "--out", str(out), "--model", "some-model", "--budget-usd", "10.0"])
    assert rc == 0
    assert seen
    assert all(spec.provider == "ollama" for spec in seen)
    assert all(spec.model == "some-model" for spec in seen)


def test_live_run_proves_and_packages(tmp_path, monkeypatch, fake_provider, capsys) -> None:
    monkeypatch.setattr(run_mod, "SandboxRunner", FakeRunner)
    case_file = stage_case(tmp_path)
    out = tmp_path / "out"

    code = run_mod.cmd_run(run_args(case_file, out))

    assert code == 0
    printed = capsys.readouterr().out
    assert "PACKAGE" in printed
    assert (out / "ledger.jsonl").exists()
    # The provider/model pair reached the registry factory.
    assert fake_provider
    assert all(spec.provider == "fake-live" for spec in fake_provider)
    assert all(spec.model == "fake-model" for spec in fake_provider)


def test_live_run_shares_one_cost_meter(tmp_path, monkeypatch, fake_provider, capsys) -> None:
    monkeypatch.setattr(run_mod, "SandboxRunner", FakeRunner)
    meters = []
    real_meter = run_mod.CostMeter

    class SpyMeter(real_meter):
        def __init__(self, limit_usd):
            super().__init__(limit_usd)
            meters.append(self)

    monkeypatch.setattr(run_mod, "CostMeter", SpyMeter)
    case_file = stage_case(tmp_path)

    assert run_mod.cmd_run(run_args(case_file, tmp_path / "out")) == 0

    assert len(meters) == 1
    assert meters[0].limit_usd == 10.0
    assert meters[0].total_usd > 0.0
    capsys.readouterr()


def test_live_run_defaults_to_ollama_dev_model(tmp_path, monkeypatch, fake_provider, capsys) -> None:
    monkeypatch.setattr(run_mod, "SandboxRunner", FakeRunner)
    captured = {}
    real_build_roles = run_mod.build_roles

    def spy(config, meter=None):
        captured.update(config)
        stand_in = {role: {"provider": "fake-live", "model": "fake-model"} for role in config}
        return real_build_roles(stand_in, meter)

    monkeypatch.setattr(run_mod, "build_roles", spy)
    case_file = stage_case(tmp_path)
    args = run_args(case_file, tmp_path / "out")
    del args.provider
    del args.model

    assert run_mod.cmd_run(args) == 0

    assert set(captured) == set(Role)
    assert all(spec.provider == "ollama" for spec in captured.values())
    assert all(spec.model == "llama3.1:8b" for spec in captured.values())
    capsys.readouterr()


def test_live_run_budget_abort_returns_nonzero(tmp_path, monkeypatch, fake_provider, capsys) -> None:
    monkeypatch.setattr(run_mod, "SandboxRunner", FakeRunner)
    monkeypatch.setattr(FakeLive, "cost_usd", 5.0)
    case_file = stage_case(tmp_path)

    code = run_mod.cmd_run(run_args(case_file, tmp_path / "out", budget_usd=1.0))

    assert code == 1
    assert "budget" in capsys.readouterr().err


def test_live_run_rejects_non_positive_budget(tmp_path, monkeypatch, fake_provider, capsys) -> None:
    monkeypatch.setattr(run_mod, "SandboxRunner", FakeRunner)
    case_file = stage_case(tmp_path)

    code = run_mod.cmd_run(run_args(case_file, tmp_path / "out", budget_usd=0.0))

    assert code == 1
    assert "budget" in capsys.readouterr().err


def test_replay_path_still_supported(tmp_path, monkeypatch, capsys) -> None:
    """Record with the fake backend, then replay the case through ``--replay``."""
    monkeypatch.setattr(loop_pipeline, "SandboxRunner", FakeRunner)
    case_file = stage_case(tmp_path)

    scratch = tmp_path / "scratch"
    clone = scratch / "clone"
    shutil.copytree(FIXTURES / "vulnerable", clone)
    (clone / "test_baseline.py").write_text(BASELINE_TEST)
    recording = case_file.parent / "replay.jsonl"
    provider = ReplayProvider(recording, recorder=FakeLive())
    roles = Roles(*(ModelRole(r, provider) for r in (
        Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
    loop = VerificationLoop(
        clone, scratch / "out", Ledger(scratch / "ledger.jsonl"),
        roles, "test_baseline.py", run_id="record", runner=FakeRunner(),
    )
    assert any(r.fix_verified for r in loop.run("app.py").proven)

    out = tmp_path / "out"
    args = run_args(case_file, out, replay=True)
    assert run_mod.cmd_run(args) == 0
    assert "PACKAGE" in capsys.readouterr().out
