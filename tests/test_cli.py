"""Tests for the skeleton CLI (src/exhibit_a/cli.py)."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
import shutil

import pytest

from exhibit_a.cli import main
from exhibit_a.cli import dashboard as dashboard_cli
from exhibit_a.cli.banner import TAGLINE, load_logo, print_banner
from exhibit_a.cli.ext.init import (
    CHECKOUT_ACTION,
    CHECKOUT_SHA,
    EXHIBIT_A_ACTION,
    EXHIBIT_A_ACTION_SHA,
    workflow_text,
)
from exhibit_a.ledger import Ledger
from exhibit_a.schemas import Event, EventType, RepoProfile
from exhibit_a.models import Completion, Role
from exhibit_a.models.cost import Pricing
from tests.test_run_live import FakeLive, FIXTURES, TRAVERSAL, suspicion, BASELINE_TEST, FakeRunner
from exhibit_a.cli import run as run_mod

ROOT = Path(__file__).resolve().parent.parent


def test_scan_without_repository_scans_the_current_directory(capsys) -> None:
    assert main(["scan"]) == 0
    raw = capsys.readouterr().out
    profile = RepoProfile.model_validate(json.loads(raw))
    assert profile.language == "python"
    assert profile.dependencies == []
    assert profile.test_cmd == "pytest"


def test_run_without_case_or_pr_diff_is_a_usage_error(capsys) -> None:
    assert main(["run"]) == 2
    assert "one of --case or --pr-diff is required" in capsys.readouterr().err


def test_run_with_repo_and_diff_but_no_case_or_pr_diff_is_a_usage_error(capsys) -> None:
    code = main(
        [
            "run",
            "--repo",
            "/tmp/repo",
            "--diff",
            "change.diff",
            "--replay",
            "--budget-usd",
            "2.5",
        ]
    )
    assert code == 2
    err = capsys.readouterr().err
    assert "one of --case or --pr-diff is required" in err
    assert "core loop is not wired yet" not in err


def test_run_rejects_non_numeric_budget() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["run", "--budget-usd", "much-money"])
    assert exc.value.code == 2


def _event(run_id: str, kind: EventType, **fields) -> Event:
    base = {"ts": "2026-10-27T00:00:00Z", "run_id": run_id, "type": kind}
    base.update(fields)
    return Event.model_validate(base)


def test_ledger_prints_totals_for_one_run(tmp_path, capsys) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    ledger = Ledger(ledger_path)
    ledger.append(_event("r1", EventType.SCAN_DONE, tokens_in=10, tokens_out=4, cost_usd=0.5))
    ledger.append(
        _event(
            "r1",
            EventType.VERDICT,
            tokens_in=1,
            tokens_out=2,
            cost_usd=0.25,
            payload={"verdict": "proven"},
        )
    )
    ledger.append(_event("r1", EventType.VERDICT, payload={"verdict": "flaky"}))
    # Another run's events must not leak into r1's totals.
    ledger.append(_event("r2", EventType.SCAN_DONE, tokens_in=100, cost_usd=9.0))

    assert main(["ledger", "r1", "--ledger", str(ledger_path)]) == 0
    totals = json.loads(capsys.readouterr().out)
    assert totals["tokens_in"] == 11
    assert totals["tokens_out"] == 6
    assert totals["cost_usd"] == pytest.approx(0.75)
    assert totals["verdicts"]["proven"] == 1
    assert totals["verdicts"]["flaky"] == 1
    assert totals["verdicts"]["discarded_unproven"] == 0


def test_ledger_missing_file_prints_zero_totals(tmp_path, capsys) -> None:
    missing = tmp_path / "no-such-ledger.jsonl"
    assert main(["ledger", "r1", "--ledger", str(missing)]) == 0
    totals = json.loads(capsys.readouterr().out)
    assert totals["tokens_in"] == 0
    assert totals["tokens_out"] == 0
    assert totals["cost_usd"] == 0.0
    assert all(count == 0 for count in totals["verdicts"].values())


def test_ledger_corrupt_file_returns_error(tmp_path, capsys) -> None:
    bad = tmp_path / "ledger.jsonl"
    bad.write_text("this is not json\n", encoding="utf-8")
    assert main(["ledger", "r1", "--ledger", str(bad)]) == 1
    assert "cannot read" in capsys.readouterr().err


def test_no_subcommand_exits_with_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_unknown_subcommand_exits_with_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["bespoke"])
    assert exc.value.code == 2


def test_python_m_entry_point_scans_the_current_directory() -> None:
    """The documented ``python -m exhibit_a.cli`` invocation must work."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    done = subprocess.run(
        [sys.executable, "-m", "exhibit_a.cli", "scan"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode == 0, done.stderr
    profile = RepoProfile.model_validate(json.loads(done.stdout))
    assert profile.language == "python"


def _stage_case(root):
    case_dir = root / "case"
    shutil.copytree(Path(__file__).parent / "fixtures" / "oracle" / "vulnerable", case_dir / "tree")
    (case_dir / "baseline_test.py").write_text(BASELINE_TEST)
    spec = {
        "cases": [{"id": "cli-case"}],
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


def test_run_cli_honours_provider_and_model_and_does_not_leak_key(tmp_path, monkeypatch, capsys):
    """CLI main([...]) honours --provider/--model for every role and never prints the API key."""
    from exhibit_a.models.config import PROVIDER_REGISTRY

    # Fake provider that records specs and returns canned completions similar to FakeLive.
    seen = []

    def factory(spec):
        seen.append(spec)
        return FakeLive(spec)

    monkeypatch.setitem(PROVIDER_REGISTRY, "fake-cli", factory)
    monkeypatch.setattr(run_mod, "SandboxRunner", FakeRunner)

    case_file = _stage_case(tmp_path)
    out = tmp_path / "out"
    monkeypatch.setenv("EXHIBIT_A_API_KEY", "SECRET_KEY")
    # run via CLI main
    rc = main(["run", "--case", str(case_file), "--out", str(out), "--provider", "fake-cli", "--model", "fake-model", "--budget-usd", "10.0"])
    assert rc == 0
    printed = capsys.readouterr().out
    assert "PACKAGE" in printed
    ledger_text = (out / "ledger.jsonl").read_text()
    assert "SECRET_KEY" not in printed
    assert "SECRET_KEY" not in ledger_text
    assert seen
    assert all(spec.provider == "fake-cli" for spec in seen)
    assert all(spec.model == "fake-model" for spec in seen)


def test_run_cli_invalid_provider_exits_usage_error():
    """An unknown --provider should exit with code 2 (argparse usage error)."""
    with pytest.raises(SystemExit) as exc:
        main(["run", "--provider", "no-such", "--model", "m"])
    assert exc.value.code == 2


SHA40 = re.compile(r"^[0-9a-f]{40}$")


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def _fake_dashboard_server(monkeypatch, calls: list) -> None:
    real_import_module = dashboard_cli.importlib.import_module

    def fake_import(name, *args, **kwargs):
        if name == "exhibit_a.dashboard":
            return object()
        if name == "exhibit_a.dashboard.server":
            return type("Server", (), {"main": lambda argv: calls.append(argv) or 0})
        return real_import_module(name, *args, **kwargs)

    monkeypatch.setattr(dashboard_cli.importlib, "import_module", fake_import)


def _tty(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)


def test_init_writes_sha_pinned_workflow_and_prints_manual_steps(tmp_path, capsys):
    target = tmp_path / ".github" / "workflows" / "exhibit-a.yml"
    assert main(["init", "--path", str(target)]) == 0
    text = target.read_text(encoding="utf-8")
    assert SHA40.fullmatch(CHECKOUT_SHA)
    assert SHA40.fullmatch(EXHIBIT_A_ACTION_SHA)
    assert f"{CHECKOUT_ACTION}@{CHECKOUT_SHA}" in text
    assert f"{EXHIBIT_A_ACTION}@{EXHIBIT_A_ACTION_SHA}" in text
    assert "profile: compact" in text
    assert "--slice" in text
    assert "suggest-fixes:" in text and "true" in text
    assert "comment:" in text and "true" in text
    assert "environment: exhibit-a" in text
    assert "vars.EXHIBIT_A_ENABLED" in text
    assert "name: exhibit-a / verify" in text
    assert "name: exhibit-a / fork-guard" in text
    assert "on:" in text and "pull_request:" in text
    assert re.search(r"^\s+pull_request_target\s*:", text, re.M) is None
    assert f"{EXHIBIT_A_ACTION}@main" not in text
    assert f"{CHECKOUT_ACTION}@v" not in text
    assert "secrets.EXHIBIT_A_API_KEY" in text
    assert "sk-" not in text
    out = capsys.readouterr().out
    assert "gh secret set EXHIBIT_A_API_KEY --env exhibit-a" in out
    assert "EXHIBIT_A_ENABLED=true" in out
    assert "exhibit-a / verify" in out
    assert "fork-guard" in out
    assert "branch protection" in out
    assert "admin" in out and "bypass" in out


def test_init_default_path_and_refuses_overwrite_without_force(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    target = tmp_path / ".github" / "workflows" / "exhibit-a.yml"
    assert target.is_file()
    assert target.read_text(encoding="utf-8") == workflow_text()
    capsys.readouterr()
    assert main(["init"]) == 2
    err = capsys.readouterr().err
    assert "already exists" in err
    assert "--force" in err
    original = target.read_text(encoding="utf-8")
    target.write_text("stale\n", encoding="utf-8")
    assert main(["init", "--force"]) == 0
    assert target.read_text(encoding="utf-8") == original


def test_logo_slot_stays_ascii_within_eight_lines_and_sixty_columns():
    raw = load_logo()
    assert TAGLINE in raw
    lines = raw.splitlines()
    assert 1 <= len(lines) <= 8
    for line in lines:
        assert len(line) <= 60
        assert all(ord(ch) < 128 for ch in line)
    assert all(ord(ch) < 128 for ch in raw)


def test_banner_prints_on_init_and_dashboard_start_only_when_interactive(
    tmp_path, monkeypatch, capsys
):
    _tty(monkeypatch)
    target = tmp_path / "wf.yml"
    assert main(["init", "--path", str(target)]) == 0
    captured = capsys.readouterr()
    assert TAGLINE in captured.err
    assert TAGLINE not in captured.out

    calls: list = []
    _fake_dashboard_server(monkeypatch, calls)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs" / "run-1").mkdir(parents=True)
    assert main(["dashboard", "--no-open"]) == 0
    captured = capsys.readouterr()
    assert TAGLINE in captured.err
    assert "127.0.0.1" in captured.out
    assert "never hosted" in captured.out


def test_banner_disabled_by_no_banner_no_color_and_non_tty(tmp_path, monkeypatch, capsys):
    target = tmp_path / "wf.yml"
    assert main(["init", "--path", str(target)]) == 0
    assert TAGLINE not in capsys.readouterr().err

    _tty(monkeypatch)
    target.write_text("stale\n", encoding="utf-8")
    assert main(["init", "--path", str(target), "--force", "--no-banner"]) == 0
    assert TAGLINE not in capsys.readouterr().err

    monkeypatch.setenv("NO_COLOR", "1")
    assert main(["init", "--path", str(target), "--force"]) == 0
    assert TAGLINE not in capsys.readouterr().err


def test_banner_never_on_json_or_machine_output(tmp_path, monkeypatch, capsys):
    _tty(monkeypatch)
    assert main(["scan"]) == 0
    raw = capsys.readouterr().out
    json.loads(raw)
    assert TAGLINE not in raw

    index = tmp_path / "runs.jsonl"
    index.write_text("{}\n", encoding="utf-8")
    code = main(["runs", "--index", str(index), "--json"])
    assert code in (0, 1)
    payload = capsys.readouterr().out
    json.loads(payload)
    assert TAGLINE not in payload


def test_dashboard_autodetects_github_remote_without_local_runs(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "remote", "add", "origin", "https://github.com/acme/app.git")
    assert dashboard_cli.resolve_source(None, cwd=tmp_path) == "github:acme/app"
    calls: list = []
    _fake_dashboard_server(monkeypatch, calls)
    assert main(["dashboard", "--no-open"]) == 0
    assert calls[0][:2] == ["--source", "github:acme/app"]
    assert "--host" not in calls[0]
    assert "0.0.0.0" not in calls[0]
    out = capsys.readouterr().out
    assert "127.0.0.1" in out
    assert "never hosted" in out


def test_dashboard_prefers_local_runs_over_github_remote(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "remote", "add", "origin", "git@github.com:acme/app.git")
    (tmp_path / "runs" / "run-1").mkdir(parents=True)
    assert dashboard_cli.resolve_source(None, cwd=tmp_path) == "local:runs"
    calls: list = []
    _fake_dashboard_server(monkeypatch, calls)
    assert main(["dashboard", "--no-open", "--port", "9000"]) == 0
    assert calls == [["--source", "local:runs", "--port", "9000"]]


def test_dashboard_prints_exact_source_commands_without_runs_or_github(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.chdir(tmp_path)
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "remote", "add", "origin", "https://gitlab.com/acme/app.git")
    assert dashboard_cli.resolve_source(None, cwd=tmp_path) is None
    assert main(["dashboard", "--no-open"]) == 2
    err = capsys.readouterr().err
    assert "no runs found" in err
    assert "exhibit-a dashboard --source local:<dir>" in err
    assert "exhibit-a dashboard --source github:<owner/repo>" in err
    assert "127.0.0.1" in err
    assert "never hosted" in err


def test_parse_github_nwo_accepts_common_remote_shapes():
    parse = dashboard_cli.parse_github_nwo
    assert parse("https://github.com/acme/app.git") == "acme/app"
    assert parse("git@github.com:Acme/App.git") == "Acme/App"
    assert parse("ssh://git@github.com/acme/app.git") == "acme/app"
    assert parse("https://gitlab.com/acme/app.git") is None
    assert parse("https://notgithub.com/acme/app") is None


def test_print_banner_writes_the_logo_when_enabled(monkeypatch, capsys):
    _tty(monkeypatch)
    print_banner()
    captured = capsys.readouterr()
    assert TAGLINE in captured.err
    assert captured.out == ""

