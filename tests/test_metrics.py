"""Tests for bench.metrics: tokens and cost attribution per proven finding."""

from pathlib import Path

from exhibit_a.ledger import Ledger
from exhibit_a.schemas import Event, EventType

from bench.corpus import Case
from bench.metrics import case_metrics, aggregate, render_table


def make_event(run_id: str, etype: EventType, payload: dict, tokens_in: int = 0, tokens_out: int = 0, cost_usd: float = 0.0) -> dict:
    return Event(
        ts="t",
        run_id=run_id,
        type=etype,
        role="",
        model="m",
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        cost_usd=cost_usd,
        latency_ms=0,
        payload=payload,
    ).model_dump()


def test_tokens_and_cost_attributed_to_proven(tmp_path: Path):
    # Build a ledger with events for two suspicions. Totals should include both.
    run_id = "bench:test:c1"
    ledger = Ledger(tmp_path / "ledger.jsonl")

    case = Case(id="c1", kind="vulnerable", repo="", commit="r", ground_truth=({"class": "path_traversal", "file": "a.py"},))

    ledger.append(make_event(run_id, EventType.SUSPICION_RAISED, {"id": "S-1", "class": "path_traversal", "location": {"file": "a.py"}}))
    ledger.append(make_event(run_id, EventType.SUSPICION_RAISED, {"id": "S-2", "class": "xss", "location": {"file": "b.py"}}))

    # Events with tokens/cost:
    # S-1: tokens_in 10 + tokens_out 2, cost 0.10
    # S-1 run: tokens_in 20 + tokens_out 8, cost 0.20
    # S-2: tokens_in 5 + tokens_out 5, cost 0.05
    ledger.append(make_event(run_id, EventType.EXPLOIT_WRITTEN, {"suspicion_id": "S-1"}, tokens_in=10, tokens_out=2, cost_usd=0.10))
    ledger.append(make_event(run_id, EventType.RUN_STARTED, {"suspicion_id": "S-1"}, tokens_in=20, tokens_out=8, cost_usd=0.20))
    ledger.append(make_event(run_id, EventType.EXPLOIT_WRITTEN, {"suspicion_id": "S-2"}, tokens_in=5, tokens_out=5, cost_usd=0.05))

    # Verdicts: S-1 proven, S-2 discarded
    ledger.append(make_event(run_id, EventType.VERDICT, {"suspicion_id": "S-1", "verdict": "proven"}))
    ledger.append(make_event(run_id, EventType.VERDICT, {"suspicion_id": "S-2", "verdict": "discarded_unproven"}))

    cm = case_metrics(ledger, run_id, case, naive=False)

    # Totals are for the whole run (both S-1 and S-2)
    assert cm.tokens == 50  # 40 for S-1 events + 10 for S-2 events
    assert abs(cm.cost_usd - 0.35) < 1e-9
    assert cm.proven == 1

    # Aggregate row shows totals and per-proven = total / proven
    row = aggregate("test", [cm])
    assert row.tokens == 50
    assert row.proven == 1
    assert row.tokens_per_proven == 50.0
    assert abs(row.cost_per_proven - 0.35) < 1e-9

    table = render_table([row])
    assert "| 50 |" in table
    assert "50" in table


def test_per_proven_zero_shows_na(tmp_path: Path):
    run_id = "bench:test:c2"
    ledger = Ledger(tmp_path / "ledger2.jsonl")
    case = Case(id="c2", kind="clean", repo="", commit="r", ground_truth=())

    # Add some token-using events but no proven verdicts
    ledger.append(make_event(run_id, EventType.SUSPICION_RAISED, {"id": "S-1"}))
    ledger.append(make_event(run_id, EventType.EXPLOIT_WRITTEN, {"suspicion_id": "S-1"}, tokens_in=3, tokens_out=2, cost_usd=0.01))
    ledger.append(make_event(run_id, EventType.VERDICT, {"suspicion_id": "S-1", "verdict": "discarded_unproven"}))

    cm = case_metrics(ledger, run_id, case, naive=False)
    assert cm.proven == 0
    assert cm.tokens == 5

    row = aggregate("none", [cm])
    assert row.tokens_per_proven is None
    table = render_table([row])
    assert "n/a" in table

