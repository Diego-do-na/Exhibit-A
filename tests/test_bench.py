"""Tests for the benchmark harness, run on the tiny synthetic corpus with a replay provider."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench.corpus import load_corpus  # noqa: E402
from bench.flags import select  # noqa: E402
from bench.runner import run_benchmark, write_results  # noqa: E402
from bench.synthetic import ScriptedProvider, make_pipeline  # noqa: E402
from exhibit_a.ledger import Ledger  # noqa: E402
from exhibit_a.models import ReplayProvider, ReplayMiss  # noqa: E402

CORPUS = ROOT / "bench" / "corpus" / "synthetic.json"


@pytest.fixture
def corpus():
    return load_corpus(CORPUS)


@pytest.fixture
def recording(tmp_path, corpus):
    """Record scripted answers once, then hand back a replay-only provider."""
    path = tmp_path / "replay.jsonl"
    recording_pipeline = make_pipeline(ReplayProvider(path, ScriptedProvider(corpus)))
    run_benchmark(corpus, recording_pipeline, Ledger(tmp_path / "warmup.jsonl"))
    return path


def rows_by_name(rows):
    return {r.ablation: r for r in rows}


def test_ablation_table_from_replay(tmp_path, corpus, recording):
    ledger = Ledger(tmp_path / "ledger.jsonl")
    pipeline = make_pipeline(ReplayProvider(recording))  # no recorder: pure replay
    rows = rows_by_name(run_benchmark(corpus, pipeline, ledger))

    assert list(rows) == ["baseline", "failing_test_only", "no_differential", "no_defender", "full"]

    baseline = rows["baseline"]
    assert (baseline.reported, baseline.proven, baseline.discarded) == (8, 0, 0)
    assert baseline.false_positives == 6
    assert baseline.recall == 1.0
    assert baseline.cost_per_proven is None

    assert rows["failing_test_only"].reported == 5
    assert rows["failing_test_only"].false_positives == 3
    assert rows["no_differential"].reported == 3
    assert rows["no_differential"].false_positives == 1

    full = rows["full"]
    assert (full.proven, full.false_positives, full.discarded) == (2, 0, 6)
    assert full.recall == 1.0
    assert full.cost_per_proven == pytest.approx(full.cost_usd / 2)
    assert full.tokens_per_proven == full.tokens / 2

    # Dropping the defender saves tokens; dropping nothing costs the most.
    assert rows["no_defender"].tokens < full.tokens
    assert rows["no_defender"].proven == full.proven


def test_costs_come_from_the_ledger(tmp_path, corpus, recording):
    ledger = Ledger(tmp_path / "ledger.jsonl")
    rows = rows_by_name(
        run_benchmark(corpus, make_pipeline(ReplayProvider(recording)), ledger, select(["full"]))
    )
    totals = [ledger.totals(f"bench:full:{c.id}") for c in corpus]
    assert rows["full"].cost_usd == pytest.approx(sum(t["cost_usd"] for t in totals))
    assert rows["full"].tokens == sum(t["tokens_in"] + t["tokens_out"] for t in totals)
    assert rows["full"].cost_usd > 0


def test_replay_without_recording_misses(tmp_path, corpus):
    pipeline = make_pipeline(ReplayProvider(tmp_path / "empty.jsonl"))
    with pytest.raises(ReplayMiss):
        run_benchmark(corpus, pipeline, Ledger(tmp_path / "l.jsonl"), select(["full"]))


def test_write_results(tmp_path, corpus, recording):
    rows = run_benchmark(
        corpus, make_pipeline(ReplayProvider(recording)), Ledger(tmp_path / "l.jsonl")
    )
    write_results(rows, tmp_path / "out")
    table = (tmp_path / "out" / "results.md").read_text()
    assert table.splitlines()[0].startswith("| ablation |")
    assert "| full | 2 | 2 | 0 | 1.00 | 6 |" in table
    assert "n/a" in table  # baseline proves nothing


def test_unknown_ablation_rejected():
    with pytest.raises(ValueError):
        select(["nope"])


def test_corpus_validation(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"cases":[{"id":"x","kind":"clean","ground_truth":[{"class":"a","file":"b"}]}]}')
    with pytest.raises(ValueError):
        load_corpus(bad)
