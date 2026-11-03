"""Tests for the simplified CLI: defaults, global flags, init, version, doctor --env."""

from __future__ import annotations

import json
from pathlib import Path

from exhibit_a.cli import build_parser, main
from exhibit_a.cli.dashboard import resolve_source
from exhibit_a.ledger.index import append_run

RECORD = {
    "schema_version": "1", "run_id": "run-1", "repo": "example/app", "commit": "abc123",
    "ts": "2026-10-29T00:00:00+00:00", "status": "completed",
    "verdict_counts": {"proven": 1, "discarded_unproven": 0, "invalid_test": 0, "flaky": 0, "env_failure": 0},
    "severity": "high", "discarded_suspicions": 0, "tokens_in": 1, "tokens_out": 2,
    "cost_usd": 0.1, "duration_s": 1.5, "ledger_path": "ledger.jsonl",
}


def test_version(tmp_path, capsys):
    assert main(["version"]) == 0
    assert capsys.readouterr().out.startswith("exhibit-a ")


def test_help_is_grouped_and_mentions_every_group(capsys):
    import pytest

    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    for group in ("core:", "inspection:", "utilities:"):
        assert group in out
    for name in ("init", "version", "dashboard", "doctor"):
        assert name in out


def test_init_writes_workflow_without_secrets_and_refuses_overwrite(tmp_path, capsys):
    from exhibit_a.cli.ext.init import (
        CHECKOUT_ACTION,
        CHECKOUT_SHA,
        EXHIBIT_A_ACTION,
        EXHIBIT_A_ACTION_SHA,
    )

    target = tmp_path / ".github" / "workflows" / "exhibit-a.yml"
    assert main(["init", "--path", str(target)]) == 0
    text = target.read_text(encoding="utf-8")
    assert f"{EXHIBIT_A_ACTION}@{EXHIBIT_A_ACTION_SHA}" in text
    assert f"{CHECKOUT_ACTION}@{CHECKOUT_SHA}" in text
    assert "pull_request" in text
    assert "secrets.EXHIBIT_A_API_KEY" in text  # name only, no value
    out = capsys.readouterr().out
    assert "gh secret set EXHIBIT_A_API_KEY --env exhibit-a" in out
    assert main(["init", "--path", str(target)]) == 2
    assert main(["init", "--path", str(target), "--force"]) == 0


def test_doctor_env_reports_host_checks(capsys):
    code = main(["doctor", "--env"])
    out = capsys.readouterr().out
    assert "PASS python:" in out
    assert "exhibit-a:" in out
    assert "docker CLI:" in out
    assert code in (0, 1)  # 0 when a docker CLI is installed, 1 otherwise


def test_dashboard_without_runs_is_a_clear_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["dashboard", "--no-open"]) == 2
    err = capsys.readouterr().err
    assert "no runs found" in err
    assert "exhibit-a dashboard --source local:<dir>" in err
    assert "exhibit-a dashboard --source github:<owner/repo>" in err
    assert "127.0.0.1" in err
    assert "Traceback" not in err


def test_dashboard_resolves_local_runs_by_default(tmp_path):
    assert resolve_source(None, cwd=tmp_path) is None
    (tmp_path / "runs" / "run-1").mkdir(parents=True)
    assert resolve_source(None, cwd=tmp_path) == "local:runs"
    assert resolve_source("local:elsewhere", cwd=tmp_path) == "local:elsewhere"


def test_quiet_and_verbose_flags_work_on_inspection_commands(tmp_path, capsys):
    index = tmp_path / "runs.jsonl"
    append_run(index, dict(RECORD))
    assert main(["runs", "--index", str(index), "-q"]) == 0
    assert capsys.readouterr().out == ""
    assert main(["-q", "runs", "--index", str(index)]) == 0
    assert main(["runs", "--index", str(index), "--verbose"]) == 0
    assert "run-1" in capsys.readouterr().out


def test_every_subcommand_accepts_verbose_and_quiet():
    parser = build_parser()
    sub = next(a for a in parser._actions if a.dest == "command")
    for name, sub_parser in sub.choices.items():
        opts = {o for a in sub_parser._actions for o in a.option_strings}
        assert {"-v", "--verbose", "-q", "--quiet", "--no-banner"} <= opts, name
