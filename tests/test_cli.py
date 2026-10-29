"""Tests for the skeleton CLI (src/exhibit_a/cli.py)."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from exhibit_a.cli import NOT_WIRED_YET, main
from exhibit_a.ledger import Ledger
from exhibit_a.schemas import Event, EventType, RepoProfile
from exhibit_a.models import Completion, Role
from exhibit_a.models.cost import Pricing
from tests.test_run_live import FakeLive, FIXTURES, TRAVERSAL, suspicion

ROOT = Path(__file__).resolve().parent.parent


def test_scan_prints_valid_repo_profile_placeholder(capsys) -> None:
    assert main(["scan"]) == 0
    raw = capsys.readouterr().out
    profile = RepoProfile.model_validate(json.loads(raw))
    assert profile.language == "unknown"
    assert profile.dependencies == []
    assert profile.baseline.passed == 0


def test_run_accepts_all_flags(capsys) -> None:
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
    assert code == 0
    out = capsys.readouterr().out
    assert NOT_WIRED_YET in out
    assert "/tmp/repo" in out
    assert "change.diff" in out


def test_run_defaults(capsys) -> None:
    assert main(["run"]) == 0
    assert NOT_WIRED_YET in capsys.readouterr().out


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


def test_python_m_entry_point_reports_scan_placeholder() -> None:
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
    assert profile.language == "unknown"


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

    PROVIDER_REGISTRY["fake-cli"] = factory
    try:
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
    finally:
        del PROVIDER_REGISTRY["fake-cli"]


def test_run_cli_invalid_provider_exits_usage_error():
    """An unknown --provider should exit with code 2 (argparse usage error)."""
    with pytest.raises(SystemExit) as exc:
        main(["run", "--provider", "no-such", "--model", "m"])
    assert exc.value.code == 2
