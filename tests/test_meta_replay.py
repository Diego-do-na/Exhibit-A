"""Offline replay of the real Meta-model recordings (SPEC section 15, docs/bench/meta-run.md).

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
    if not recording.is_file() or not metadata.is_file():
        pytest.skip(
            f"no Meta recording for {case_id} yet: record it with "
            f"python -m bench.record_meta --profile compact --case {case_id} "
            "(needs the model key)"
        )
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
    if not all(path.is_file() for path in files):
        pytest.skip(
            f"no Meta recording for {case_id} yet: record it with "
            f"python -m bench.record_meta --profile compact --case {case_id} "
            "(needs the model key)"
        )
    assert scan_files(files, scan_values()) == []


# -- compact-profile recordings (docs/bench/cost-controls.md) ----------------------------------------
#
# Recorded on 2026-10-30 with --profile compact (bounded answers, proof contract, minimal
# reasoning). Unlike the standard run above, both vulnerable cases end proven with a verified
# fix. The replay must reproduce that offline, with no key and no network.

COMPACT_CASES = ("archive-extraction-pathtraversal", "starlette-cve-2023-29159")


def _compact_metadata(case_id):
    recording, metadata = recording_paths(case_id, DEFAULT_MODEL, "compact")
    assert recording.is_file(), f"no compact Meta recording for {case_id}"
    return recording, json.loads(metadata.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case_id", COMPACT_CASES)
def test_compact_recording_is_a_real_meta_run_that_proved_and_fixed(case_id):
    recording, meta = _compact_metadata(case_id)
    assert (meta["provider"], meta["model"], meta["profile"]) == ("meta", DEFAULT_MODEL, "compact")
    assert meta["hand_authored"] is False
    assert meta["reasoning_effort"] == "minimal"
    rows = [json.loads(line) for line in recording.read_text(encoding="utf-8").splitlines() if line]
    assert len(rows) == meta["calls"] >= 1
    assert meta["cost_usd"] == pytest.approx(sum(row["cost_usd"] for row in rows))
    assert meta["cost_usd"] <= meta["budget_usd"]["case"]
    proven = [v for v in meta["verdicts"] if v["verdict"] == "proven"]
    assert proven and all(v["fix_verified"] and not v["fix_incomplete"] for v in proven)


@pytest.mark.docker
@pytest.mark.parametrize("case_id", COMPACT_CASES)
def test_offline_replay_reproduces_the_compact_verdicts(case_id, tmp_path, monkeypatch):
    _, meta = _compact_metadata(case_id)
    monkeypatch.delenv("META_API_KEY", raising=False)
    outcome = replay_case(case_id, DEFAULT_MODEL, tmp_path / "replay", "compact")
    assert outcome.baseline_ok == meta["baseline_ok"]
    assert outcome.aborted == meta["aborted"]
    assert outcome.suspicions_raised == meta["suspicions_raised"]
    assert comparable(outcome.verdicts) == comparable(meta["verdicts"])


@pytest.mark.parametrize("case_id", COMPACT_CASES)
def test_compact_recordings_hold_no_secret_from_this_environment(case_id):
    recording, _ = recording_paths(case_id, DEFAULT_MODEL, "compact")
    assert scan_files([recording, recording.with_suffix(".json")], scan_values()) == []


# -- every other compact recording (2026-11-01) --------------------------------------------------
#
# The batch recorded with --profile compact on 2026-11-01 covers every other Python and JS/TS
# case. Some end proven and some do not (invalid_test or discarded_unproven are honest
# outcomes and are kept as they came). What must hold for all of them: the metadata matches the
# recording, nothing from this environment leaked into either file, and an offline replay
# reproduces the recorded verdicts.

_NEGATIVE_CONTROL_CASE = "starlette-cve-2023-29159-fixed"
BATCH_COMPACT_CASES = tuple(
    case_id for case_id in CASES
    if case_id not in COMPACT_CASES and case_id != _NEGATIVE_CONTROL_CASE
    and recording_paths(case_id, DEFAULT_MODEL, "compact")[0].is_file()
)


@pytest.mark.parametrize("case_id", BATCH_COMPACT_CASES)
def test_batch_compact_recording_matches_its_metadata(case_id):
    recording, meta = _compact_metadata(case_id)
    assert (meta["provider"], meta["model"], meta["profile"]) == ("meta", DEFAULT_MODEL, "compact")
    assert meta["hand_authored"] is False and meta["baseline_ok"] is True
    rows = [json.loads(line) for line in recording.read_text(encoding="utf-8").splitlines() if line]
    assert len(rows) == meta["calls"] >= 1
    assert meta["tokens_in"] == sum(row["tokens_in"] for row in rows)
    assert meta["tokens_out"] == sum(row["tokens_out"] for row in rows)
    assert meta["cost_usd"] == pytest.approx(sum(row["cost_usd"] for row in rows))
    assert meta["cost_usd"] <= meta["budget_usd"]["case"] + 1.0  # one call may overshoot
    assert meta["spent_before_usd"] + meta["cost_usd"] <= meta["budget_usd"]["run_total"] + 1.0


@pytest.mark.parametrize("case_id", BATCH_COMPACT_CASES)
def test_batch_compact_recordings_hold_no_secret_from_this_environment(case_id):
    recording, _ = recording_paths(case_id, DEFAULT_MODEL, "compact")
    assert scan_files([recording, recording.with_suffix(".json")], scan_values()) == []


@pytest.mark.docker
@pytest.mark.parametrize("case_id", BATCH_COMPACT_CASES)
def test_offline_replay_reproduces_the_batch_compact_verdicts(case_id, tmp_path, monkeypatch):
    _, meta = _compact_metadata(case_id)
    monkeypatch.delenv("META_API_KEY", raising=False)
    outcome = replay_case(case_id, DEFAULT_MODEL, tmp_path / "replay", "compact")
    assert outcome.baseline_ok == meta["baseline_ok"]
    assert outcome.aborted == meta["aborted"]
    assert outcome.suspicions_raised == meta["suspicions_raised"]
    assert comparable(_race_normalized(case_id, outcome.verdicts, meta["verdicts"])) == comparable(
        meta["verdicts"]
    )


# Race-dependent reasons (docs/ci/replay-determinism.md). The recorded S3 exploit races a symlink-swap
# thread against 3000 serve() calls. When the swap lands the oracle reports "provenance"; when a
# loaded runner never lands it, the test passes on the vulnerable tree and the judge reports
# "no_effect". Either way the verdict is invalid_test and nothing is proven. Only the reason_code
# of this one suspicion may take either value; the verdict, fix flags and every other row stay exact.
RACE_DEPENDENT_REASONS = {("static-route-traversal", "S3"): frozenset({"provenance", "no_effect"})}


def _race_normalized(case_id, replayed, recorded):
    recorded_by_id = {row["suspicion_id"]: row for row in recorded}
    rows = []
    for row in replayed:
        row = dict(row)
        allowed = RACE_DEPENDENT_REASONS.get((case_id, row["suspicion_id"]))
        want = recorded_by_id.get(row["suspicion_id"], {})
        if (
            allowed
            and row["reason_code"] in allowed
            and want.get("reason_code") in allowed
            and row["verdict"] == want.get("verdict") == "invalid_test"
        ):
            row["reason_code"] = want["reason_code"]
        rows.append(row)
    return rows


def test_race_tolerance_is_limited_to_one_invalid_test_reason():
    assert set(RACE_DEPENDENT_REASONS) == {("static-route-traversal", "S3")}
    recorded = [{"suspicion_id": "S3", "verdict": "invalid_test", "reason_code": "provenance"}]
    flipped = [{"suspicion_id": "S3", "verdict": "invalid_test", "reason_code": "no_effect"}]
    assert _race_normalized("static-route-traversal", flipped, recorded) == recorded
    # a different verdict, a different case or a different suspicion is never forgiven
    proven = [{"suspicion_id": "S3", "verdict": "proven", "reason_code": ""}]
    assert _race_normalized("static-route-traversal", proven, recorded) == proven
    assert _race_normalized("other-case", flipped, recorded) == flipped
    other = [{"suspicion_id": "S1", "verdict": "invalid_test", "reason_code": "no_effect"}]
    assert _race_normalized("static-route-traversal", other, recorded) == other


# -- negative control: the fixed Starlette tree must never end proven ----------------------------
#
# The first compact live run of starlette-cve-2023-29159-fixed (2026-10-30) ended with S3
# "proven": a test thread swapped a served file for a symlink to the canary and back, and the
# oracle's fresh-symlink walk raced it. The recording is kept unedited as evidence; its
# metadata still says what the live run concluded. Replayed against the current oracle, which
# flags any link to the canary created during the run, it must prove nothing.

NEGATIVE_CONTROL = "starlette-cve-2023-29159-fixed"


def test_the_negative_control_recording_documents_the_raced_false_proof():
    _, meta = _compact_metadata(NEGATIVE_CONTROL)
    assert [v["suspicion_id"] for v in meta["verdicts"] if v["verdict"] == "proven"] == ["S3"]


@pytest.mark.docker
def test_replaying_the_negative_control_proves_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("META_API_KEY", raising=False)
    outcome = replay_case(NEGATIVE_CONTROL, DEFAULT_MODEL, tmp_path / "replay", "compact")
    assert outcome.baseline_ok
    assert [v for v in outcome.verdicts if v["verdict"] == "proven"] == []
    s3 = next(v for v in outcome.verdicts if v["suspicion_id"] == "S3")
    # The race may or may not hit the canary on replay; either way it is never a proof.
    assert s3["verdict"] in {"invalid_test", "discarded_unproven"}


def test_the_negative_control_recording_holds_no_secret():
    recording, _ = recording_paths(NEGATIVE_CONTROL, DEFAULT_MODEL, "compact")
    assert scan_files([recording, recording.with_suffix(".json")], scan_values()) == []
