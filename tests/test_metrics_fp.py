"""Tests for bench.metrics: false positives and recall against Case.ground_truth."""

from pathlib import Path

from exhibit_a.ledger import Ledger
from exhibit_a.schemas import Event, EventType

from bench.corpus import Case
from bench.metrics import case_metrics, aggregate
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


def test_vulnerable_case_false_positives_and_recall(tmp_path: Path):
    """One ground-truth vuln; two proven findings (one matches, one doesn't)."""
    run_id = "bench:test:fp:vuln"
    ledger = Ledger(tmp_path / "ledger_fp_vuln.jsonl")

    case = Case(
        id="c-vuln",
        kind="vulnerable",
        repo="",
        commit="r",
        ground_truth=({"class": "path_traversal", "file": "a.py"},),
    )

    # Two suspicions raised
    ledger.append(make_event(run_id, EventType.SUSPICION_RAISED, {"id": "S-1", "class": "path_traversal", "location": {"file": "a.py"}}))
    ledger.append(make_event(run_id, EventType.SUSPICION_RAISED, {"id": "S-2", "class": "xss", "location": {"file": "b.py"}}))

    # Both proven (simulating false positive + true positive)
    ledger.append(make_event(run_id, EventType.VERDICT, {"suspicion_id": "S-1", "verdict": "proven"}))
    ledger.append(make_event(run_id, EventType.VERDICT, {"suspicion_id": "S-2", "verdict": "proven"}))

    cm = case_metrics(ledger, run_id, case, naive=False)

    assert cm.proven == 2
    assert cm.true_positives == 1
    assert cm.false_positives == 1
    assert cm.truth_total == 1
    assert cm.truth_found == 1

    row = aggregate("fp-test", [cm])
    assert row.recall == 1.0


def test_clean_case_proven_counts_as_false_positive(tmp_path: Path):
    """A clean case has no ground truth; any proven finding is a false positive."""
    run_id = "bench:test:fp:clean"
    ledger = Ledger(tmp_path / "ledger_fp_clean.jsonl")

    case = Case(id="c-clean", kind="clean", repo="", commit="r", ground_truth=())

    ledger.append(make_event(run_id, EventType.SUSPICION_RAISED, {"id": "S-1", "class": "path_traversal", "location": {"file": "c.py"}}))
    ledger.append(make_event(run_id, EventType.VERDICT, {"suspicion_id": "S-1", "verdict": "proven"}))

    cm = case_metrics(ledger, run_id, case, naive=False)
    assert cm.proven == 1
    assert cm.true_positives == 0
    assert cm.false_positives == 1
    assert cm.truth_total == 0

    row = aggregate("fp-clean", [cm])
    assert row.recall is None


def test_vulnerable_case_partial_recall(tmp_path: Path):
    """Two ground-truth vulns, only one is found by the loop."""
    run_id = "bench:test:fp:partial"
    ledger = Ledger(tmp_path / "ledger_fp_partial.jsonl")

    case = Case(
        id="c-partial",
        kind="vulnerable",
        repo="",
        commit="r",
        ground_truth=(
            {"class": "path_traversal", "file": "a.py"},
            {"class": "xss", "file": "b.py"},
        ),
    )

    # Two suspicions raised, only S-1 is proven
    ledger.append(make_event(run_id, EventType.SUSPICION_RAISED, {"id": "S-1", "class": "path_traversal", "location": {"file": "a.py"}}))
    ledger.append(make_event(run_id, EventType.SUSPICION_RAISED, {"id": "S-2", "class": "xss", "location": {"file": "b.py"}}))
    ledger.append(make_event(run_id, EventType.VERDICT, {"suspicion_id": "S-1", "verdict": "proven"}))
    # S-2 not proven / discarded (no proven verdict)

    cm = case_metrics(ledger, run_id, case, naive=False)
    assert cm.truth_total == 2
    assert cm.truth_found == 1
    assert cm.proven == 1
    assert cm.true_positives == 1
    assert cm.false_positives == 0

    row = aggregate("partial", [cm])
    assert row.recall == 0.5


def test_clean_case_no_proven_is_not_false_positive(tmp_path: Path):
    """Clean case with no proven verdicts should yield zero proven and zero false positives."""
    run_id = "bench:test:fp:clean2"
    ledger = Ledger(tmp_path / "ledger_fp_clean2.jsonl")

    case = Case(id="c-clean2", kind="clean", repo="", commit="r", ground_truth=())

    ledger.append(make_event(run_id, EventType.SUSPICION_RAISED, {"id": "S-1", "class": "path_traversal", "location": {"file": "c.py"}}))
    ledger.append(make_event(run_id, EventType.VERDICT, {"suspicion_id": "S-1", "verdict": "discarded_unproven"}))

    cm = case_metrics(ledger, run_id, case, naive=False)
    assert cm.proven == 0
    assert cm.false_positives == 0

