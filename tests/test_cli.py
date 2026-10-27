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
