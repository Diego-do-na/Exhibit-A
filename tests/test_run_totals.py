import json

from exhibit_a.cli import run as run_mod
from exhibit_a.ledger import Ledger
from exhibit_a.models.config import PROVIDER_REGISTRY

from tests.test_run_live import FakeLive, FakeRunner, stage_case


def test_run_prints_ledger_totals_for_run_id(tmp_path, monkeypatch, capsys):
    PROVIDER_REGISTRY["fake-live"] = lambda spec: FakeLive(spec)
    monkeypatch.setattr(run_mod, "SandboxRunner", FakeRunner)
    case_file = stage_case(tmp_path)
    out = tmp_path / "out"

    assert run_mod.cmd_run(_run_args(case_file, out)) == 0

    text = capsys.readouterr().out
    totals_line = next(line for line in text.splitlines() if "totals:" in line)
    totals = json.loads(totals_line.split("totals:", 1)[1].strip())

    assert "tokens_in" in totals
    assert "tokens_out" in totals
    assert "cost_usd" in totals
    assert "verdicts" in totals
    assert totals["tokens_in"] >= 0
    assert totals["tokens_out"] >= 0
    assert totals["cost_usd"] >= 0.0
    assert totals["verdicts"]["proven"] >= 1
    assert Ledger(out / "ledger.jsonl").totals("live-case") == totals


def _run_args(case_file, out, **overrides):
    import argparse

    args = argparse.Namespace(
        case=str(case_file),
        out=str(out),
        replay=False,
        provider="fake-live",
        model="fake-model",
        budget_usd=10.0,
        repo=".",
        diff=None,
    )
    for key, value in overrides.items():
        setattr(args, key, value)
    return args
