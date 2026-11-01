from pathlib import Path

from exhibit_a.models import Completion, Role

from bench.corpus import Case
from bench.scale import (
    aggregate,
    execute,
    recording_provider,
    regenerate_document,
    run_key,
    wilson,
)


def _case(case_id="case", kind="vulnerable"):
    return Case(case_id, kind, "", "", ({"class": "x", "file": "a.py"},) if kind == "vulnerable" else ())


def test_wilson_matches_hand_computed_interval():
    result = wilson(1, 3)
    assert result["rate"] == 1 / 3
    assert round(result["low"], 6) == 0.061492
    assert round(result["high"], 6) == 0.792340


def test_resume_skips_finished_runs(tmp_path: Path):
    calls = []

    def runner(case, system, model, repetition, out, cap):
        calls.append(run_key(case.id, system, model, repetition))
        return {"proven": True, "cost_usd": 0.1, "latency_ms": 2}

    first = execute([_case()], ["loop"], ["fake"], 2, 1, 0.2, tmp_path, runner, doc=tmp_path / "doc")
    second = execute([_case()], ["loop"], ["fake"], 2, 1, 0.2, tmp_path, runner, doc=tmp_path / "doc")
    assert first["completed_runs"] == second["completed_runs"] == 2
    assert len(calls) == 2


def test_budget_stops_before_next_run(tmp_path: Path):
    calls = []

    def runner(*args):
        calls.append(args[3])
        return {"proven": False, "cost_usd": 0.6}

    result = execute([_case()], ["loop"], ["fake"], 3, 1, 0.6, tmp_path, runner, doc=tmp_path / "doc")
    assert len(calls) == 1
    assert result["stopped"] is True
    assert result["spent_usd"] == 0.6


def test_dry_run_estimates_without_calling_runner(tmp_path: Path):
    def forbidden(*args):
        raise AssertionError("runner must not be called")

    result = execute([_case()], ["loop", "naive"], ["muse-wonder-1.0"], 3,
                     100, 10, tmp_path, forbidden, dry_run=True)
    assert result["planned_runs"] == 6
    assert result["worst_case_cost_usd"] > 0
    assert not (tmp_path / "runs.jsonl").exists()


def test_generated_block_is_deterministic(tmp_path: Path):
    records = [{"case": "c", "system": "loop", "model": "fake", "repetition": 1,
                "effect": "canary_read", "proven": True, "true_vulnerability": True,
                "valid_proof": True, "cost_usd": 0.2, "latency_ms": 5}]
    doc = tmp_path / "benchmark.md"
    regenerate_document(doc, records)
    before = doc.read_text()
    regenerate_document(doc, records)
    assert doc.read_text() == before


def test_recorded_fake_replays_identically(tmp_path: Path):
    class Fake:
        name = "fake"
        pricing = type("Pricing", (), {"cost": lambda self, i, o: 0.0})()
        def complete(self, role, prompt, schema):
            return Completion('{"ok": true}', 2, 3, 7, "fake", 0.25)

    provider = recording_provider(tmp_path / "recording.jsonl", Fake())
    schema = {"type": "object", "required": ["ok"], "properties": {"ok": {"type": "boolean"}}}
    first = provider.complete(Role.ADVERSARY, "same", schema)
    second = provider.complete(Role.ADVERSARY, "same", schema)
    assert first == second
    assert len((tmp_path / "recording.jsonl").read_text().splitlines()) == 1


def test_aggregation_keeps_held_out_separate():
    rows = aggregate([
        {"case": "c", "system": "loop", "effect": "canary_read", "held_out": False,
         "proven": True, "true_vulnerability": True, "valid_proof": True, "cost_usd": 1},
        {"case": "h", "system": "loop", "effect": "canary_read", "held_out": True,
         "proven": True, "true_vulnerability": True, "valid_proof": True, "cost_usd": 1},
    ])
    assert "loop:canary_read" in rows["groups"]
    assert "loop:canary_read" in rows["held_out"]
