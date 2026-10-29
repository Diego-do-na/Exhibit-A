"""Tests for the report, runs, advisories and dashboard CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

from exhibit_a.cli import main
from exhibit_a.cli import dashboard as dashboard_cli
from exhibit_a.ledger.index import append_run


FIXTURES = Path(__file__).parent / "fixtures"


def _package(tmp_path: Path) -> Path:
    package = tmp_path / "package"
    package.mkdir()
    (package / "verdict.json").write_text(
        json.dumps({"suspicion_id": "S-1", "verdict": "proven", "evidence": {}}),
        encoding="utf-8",
    )
    (package / "evidence.json").write_text(
        json.dumps({
            "suspicion": {"class": "path_traversal", "location": {"file": "app.py", "line": 1}},
            "suspicious_code": {"content": "return user_path\n"},
            "evidence": {"oracle": {"effect": "canary_read"}, "provenance": {"ok": True}},
        }),
        encoding="utf-8",
    )
    return package


def _run_record(run_id: str) -> dict:
    return {
        "schema_version": "1",
        "run_id": run_id,
        "repo": "example/app",
        "commit": "abc123",
        "ts": "2026-10-29T00:00:00+00:00",
        "status": "completed",
        "verdict_counts": {
            "proven": 1, "discarded_unproven": 0, "invalid_test": 0,
            "flaky": 0, "env_failure": 0,
        },
        "severity": "high",
        "discarded_suspicions": 0,
        "tokens_in": 1,
        "tokens_out": 2,
        "cost_usd": 0.1,
        "duration_s": 1.5,
        "ledger_path": "ledger.jsonl",
    }


def test_report_writes_markdown_and_rejects_missing_package(tmp_path, capsys):
    out = tmp_path / "finding.md"
    assert main(["report", str(_package(tmp_path)), "--out", str(out)]) == 0
    assert "Exhibit A finding" in out.read_text(encoding="utf-8")
    assert main(["report", str(tmp_path / "missing")]) == 1
    assert "cannot render" in capsys.readouterr().err


def test_runs_prints_json_and_never_hides_corrupt_lines(tmp_path, capsys):
    index = tmp_path / "runs.jsonl"
    append_run(index, _run_record("run-1"))
    index.write_text(index.read_text() + "{bad json\n", encoding="utf-8")
    assert main(["runs", "--index", str(index), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["runs"][0]["run_id"] == "run-1"
    assert payload["problems"]


def test_advisories_offline_json_and_bad_input(tmp_path, capsys):
    requirements = FIXTURES / "advisory" / "project" / "requirements.txt"
    fixture = FIXTURES / "advisory" / "osv_synthetic.json"
    assert main([
        "advisories", "--requirements", str(requirements),
        "--offline", str(fixture), "--json",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["matches"]
    assert "advisory_hint" in json.dumps(payload)
    assert main(["advisories"]) == 2
    assert "provide --requirements" in capsys.readouterr().err


def test_dashboard_delegates_and_reports_missing_build(monkeypatch, capsys):
    calls = []

    def fake_import(name):
        if name == "exhibit_a.dashboard":
            return object()
        if name == "exhibit_a.dashboard.server":
            return type("Server", (), {"main": lambda argv: calls.append(argv) or 0})
        raise AssertionError(name)

    monkeypatch.setattr(dashboard_cli.importlib, "import_module", fake_import)
    assert main(["dashboard", "--source", "local:runs", "--port", "9000"]) == 0
    assert calls == [["--source", "local:runs", "--port", "9000"]]

    def missing(_name):
        raise ImportError("not packaged")

    monkeypatch.setattr(dashboard_cli.importlib, "import_module", missing)
    assert main(["dashboard", "--source", "local:runs"]) == 2
    assert "dashboard not installed in this build" in capsys.readouterr().err
