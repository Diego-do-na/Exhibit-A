"""Demo kit: the offline demo replays the compact Meta recordings end to end.

The demo's headline (docs/demo.md) is that the two compact-profile live runs
with Muse Wonder — archive zip-slip (US$0.06) and Starlette CVE-2023-29159
(US$0.11) — each ended with a proven finding and a verified fix. Step 1 of
``scripts/demo.sh --offline`` shows exactly that code (the archive
fixed/vulnerable diff and the Starlette ``commonprefix`` line), and step 2
replays the recordings committed under ``bench/corpus/<case>/recordings/``
(single source of truth) through the real loop and the real sandbox, with no
key and no network to the model. The sandbox still runs every test, so the
replay tests carry the docker marker.
"""

import json
from pathlib import Path

import pytest

from bench.record_meta import comparable, replay_case, scan_files, scan_values

ROOT = Path(__file__).resolve().parent.parent

#: (corpus case, live cost in USD)
COMPACT_CASES = (
    ("archive-extraction-pathtraversal", 0.0597),
    ("starlette-cve-2023-29159", 0.1106),
)


def _compact_paths(case_id):
    base = ROOT / "bench" / "corpus" / case_id / "recordings" / "meta-muse-wonder-1.0-compact"
    return base.parent / (base.name + ".jsonl"), base.parent / (base.name + ".json")


def _compact_meta(case_id):
    return json.loads(_compact_paths(case_id)[1].read_text(encoding="utf-8"))


@pytest.mark.parametrize("case_id,cost", COMPACT_CASES)
def test_compact_metadata_records_a_proven_finding_with_a_verified_fix(case_id, cost):
    meta = _compact_meta(case_id)
    assert (meta["provider"], meta["model"], meta["profile"]) == ("meta", "muse-wonder-1.0", "compact")
    assert meta["hand_authored"] is False
    assert meta["baseline_ok"] and not meta["aborted"] and not meta["stopped"]
    proven = [v for v in meta["verdicts"] if v["verdict"] == "proven"]
    assert proven and all(v["fix_verified"] and not v["fix_incomplete"] for v in proven)
    # The replayed run charges the recorded live cost: US$0.06 / US$0.11.
    assert meta["cost_usd"] == pytest.approx(cost, abs=0.001)


@pytest.mark.parametrize("case_id,cost", COMPACT_CASES)
def test_compact_recordings_hold_no_secret_from_this_environment(case_id, cost):
    recording, metadata = _compact_paths(case_id)
    assert scan_files([recording, metadata], scan_values()) == []


@pytest.mark.docker
@pytest.mark.parametrize("case_id,cost", COMPACT_CASES)
def test_offline_demo_ends_with_a_proven_finding_and_a_verified_fix(
    case_id, cost, tmp_path, monkeypatch
):
    # Prove the replay is offline: without the key no live call could be built.
    monkeypatch.delenv("META_API_KEY", raising=False)
    meta = _compact_meta(case_id)
    outcome = replay_case(case_id, "muse-wonder-1.0", tmp_path / "replay", "compact")
    assert outcome.baseline_ok
    assert outcome.suspicions_raised == meta["suspicions_raised"] == 1
    assert comparable(outcome.verdicts) == comparable(meta["verdicts"])
    verdict = outcome.verdicts[0]
    assert verdict["verdict"] == "proven"
    assert verdict["fix_verified"] and not verdict["fix_incomplete"]
