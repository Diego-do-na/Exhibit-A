"""Offline replay of the real Meta-model recordings (SPEC section 15, docs/meta-run.md).

Each corpus case carries a recording of a live run with a Meta model and the verdicts that
run obtained. Replaying the recording with no network, through the same loop and the same
sandbox runner, must reproduce those verdicts exactly. No test here calls the Meta API.
"""

import json

import pytest

from bench.record_meta import (
    CASES,
    DEFAULT_MODEL,
    SplitMeter,
    comparable,
    recording_paths,
    replay_case,
    scan_files,
    scan_values,
)
from exhibit_a.models import BudgetExceeded, CostMeter


def _metadata(case_id):
    recording, metadata = recording_paths(case_id, DEFAULT_MODEL)
    assert recording.is_file(), f"no Meta recording for {case_id}"
    assert metadata.is_file(), f"no Meta recording metadata for {case_id}"
    return recording, json.loads(metadata.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case_id", CASES)
def test_recording_is_a_real_meta_run_with_metadata(case_id):
    recording, meta = _metadata(case_id)
    assert meta["provider"] == "meta"
    assert meta["model"] == DEFAULT_MODEL
    assert meta["hand_authored"] is False
    assert meta["exhibit_a"]["commit"]
    assert meta["date_utc"].endswith("Z")
    rows = [json.loads(line) for line in recording.read_text(encoding="utf-8").splitlines() if line]
    assert len(rows) == meta["calls"] >= 1
    assert all(row["model"] != "hand-authored" for row in rows)
    assert sum(row["tokens_in"] for row in rows) == meta["tokens_in"]
    assert sum(row["tokens_out"] for row in rows) == meta["tokens_out"]
    assert meta["cost_usd"] == pytest.approx(sum(row["cost_usd"] for row in rows))
    assert meta["cost_usd"] <= meta["budget_usd"]["case"] + 1.0  # one call may overshoot


def test_recorded_spend_stays_within_the_run_cap():
    spent = sum(_metadata(case_id)[1]["cost_usd"] for case_id in CASES)
    assert spent <= 5.0


@pytest.mark.docker
@pytest.mark.parametrize("case_id", CASES)
def test_offline_replay_reproduces_the_recorded_verdicts(case_id, tmp_path, monkeypatch):
    _, meta = _metadata(case_id)
    # Prove the replay is offline: without the key no live call could even be built.
    monkeypatch.delenv("META_API_KEY", raising=False)
    outcome = replay_case(case_id, DEFAULT_MODEL, tmp_path / "replay")
    assert outcome.baseline_ok == meta["baseline_ok"]
    assert outcome.aborted == meta["aborted"]
    assert outcome.suspicions_raised == meta["suspicions_raised"]
    assert comparable(outcome.verdicts) == comparable(meta["verdicts"])
    # The replay charges the recorded costs against the same caps, so a live run stopped by
    # its budget stops at the same call; one stopped by a provider error runs out of answers.
    expected = {"": "", "budget_exceeded": "budget_exceeded"}.get(meta["stopped"], "replay_miss")
    assert outcome.stopped == expected


def test_split_meter_stops_on_either_cap():
    total = CostMeter(5.0)
    meter = SplitMeter(CostMeter(2.0), total)
    meter.charge(1.5)
    with pytest.raises(BudgetExceeded):
        meter.charge(0.6)
    assert total.total_usd == pytest.approx(2.1)  # the run total still saw the spend
    SplitMeter(CostMeter(2.0), total).charge(1.9)
    with pytest.raises(BudgetExceeded):
        SplitMeter(CostMeter(2.0), total).charge(1.2)  # case cap untouched, run cap passed
    with pytest.raises(BudgetExceeded):
        SplitMeter(CostMeter(2.0), total).check()


def test_secret_scan_finds_the_key_and_long_env_values_without_printing_them(tmp_path):
    env = {"META_API_KEY": "short-key", "SOME_PATHISH": "x" * 20, "SHELL": "/bin/zsh"}
    values = scan_values(env)
    assert set(values) == {"META_API_KEY", "SOME_PATHISH"}
    leaked = tmp_path / "leak.jsonl"
    leaked.write_text('{"text": "short-key"}\n', encoding="utf-8")
    clean = tmp_path / "clean.jsonl"
    clean.write_text('{"text": "/bin/zsh"}\n', encoding="utf-8")
    assert scan_files([leaked, clean], values) == [(str(leaked), "META_API_KEY")]


@pytest.mark.parametrize("case_id", CASES)
def test_committed_recordings_hold_no_secret_from_this_environment(case_id):
    recording, _ = recording_paths(case_id, DEFAULT_MODEL)
    files = [recording, recording.with_suffix(".json")]
    assert scan_files(files, scan_values()) == []
