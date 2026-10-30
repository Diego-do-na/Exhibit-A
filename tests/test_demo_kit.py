"""Demo kit: the offline demo replays the compact Meta recordings end to end.

The demo's headline (docs/demo.md) is that the two compact-profile live runs
with Muse Wonder — archive zip-slip (US$0.06) and Starlette CVE-2023-29159
(US$0.11) — each ended with a proven finding and a verified fix. Replaying the
recordings committed under ``examples/demo-app/recordings/`` through the real
loop and the real sandbox must reproduce exactly that, with no key and no
network to the model. The sandbox still runs every test, so the replay tests
carry the docker marker.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from bench.corpus import load_corpus
from bench.record_meta import SplitMeter, run_case, scan_files, scan_values
from exhibit_a.models import CostMeter, ReplayProvider

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "demo-app"
RECORDINGS = DEMO / "recordings"

#: (corpus case, demo recording stem, live cost in USD)
COMPACT_PAIRS = (
    ("archive-extraction-pathtraversal", "archive", 0.0597),
    ("starlette-cve-2023-29159", "starlette", 0.1106),
)


def _demo_paths(stem):
    return (RECORDINGS / f"{stem}-meta-muse-wonder-1.0-compact.jsonl",
            RECORDINGS / f"{stem}-meta-muse-wonder-1.0-compact.json")


def _demo_meta(stem):
    return json.loads(_demo_paths(stem)[1].read_text(encoding="utf-8"))


def _replay(case_id, stem, out_dir, monkeypatch):
    """Replay one demo recording offline; the sandbox still runs every test."""
    monkeypatch.delenv("META_API_KEY", raising=False)
    recording, _ = _demo_paths(stem)
    meta = _demo_meta(stem)
    total = CostMeter(meta["budget_usd"]["run_total"])
    for earlier, _, _ in COMPACT_PAIRS[:[c for c, _, _ in COMPACT_PAIRS].index(case_id)]:
        total.charge(_demo_meta(earlier)["cost_usd"])
    meter = SplitMeter(CostMeter(meta["budget_usd"]["case"]), total)
    return run_case(load_corpus(ROOT / "bench" / "corpus" / case_id)[0],
                    ReplayProvider(recording), out_dir, meter, "compact"), meta


@pytest.mark.parametrize("case_id,stem,_", COMPACT_PAIRS)
def test_demo_recordings_are_byte_identical_to_the_bench_originals(case_id, stem, _):
    recording, metadata = _demo_paths(stem)
    bench = ROOT / "bench" / "corpus" / case_id / "recordings" / "meta-muse-wonder-1.0-compact"
    assert recording.read_bytes() == (bench.parent / (bench.name + ".jsonl")).read_bytes()
    assert metadata.read_bytes() == (bench.parent / (bench.name + ".json")).read_bytes()


@pytest.mark.parametrize("case_id,stem,_", COMPACT_PAIRS)
def test_demo_recordings_hold_no_secret_from_this_environment(case_id, stem, _):
    recording, metadata = _demo_paths(stem)
    assert scan_files([recording, metadata], scan_values()) == []


@pytest.mark.docker
@pytest.mark.parametrize("case_id,stem,cost", COMPACT_PAIRS)
def test_offline_demo_ends_with_a_proven_finding_and_a_verified_fix(
    case_id, stem, cost, tmp_path, monkeypatch
):
    outcome, meta = _replay(case_id, stem, tmp_path / "replay", monkeypatch)
    assert outcome.baseline_ok
    assert outcome.suspicions_raised == 1
    assert len(outcome.verdicts) == 1
    verdict = outcome.verdicts[0]
    assert verdict["verdict"] == "proven"
    assert verdict["fix_verified"] and not verdict["fix_incomplete"]
    # The replayed run charges the recorded live cost: US$0.06 / US$0.11.
    assert meta["cost_usd"] == pytest.approx(cost, abs=0.001)


def test_demo_pr_patch_turns_base_into_pr(tmp_path):
    target = tmp_path / "importer.py"
    target.write_bytes((DEMO / "base" / "importer.py").read_bytes())
    proc = subprocess.run(
        ["patch", "-s", str(target), "-i", str(DEMO / "pr.patch")],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert target.read_bytes() == (DEMO / "pr" / "importer.py").read_bytes()


@pytest.mark.parametrize("tree", ["base", "pr"])
def test_demo_baseline_passes_on_both_trees(tree, tmp_path):
    env = dict(os.environ, PYTHONPATH=str(DEMO / tree), PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
         str(DEMO / "baseline_test.py")],
        capture_output=True, text=True, cwd=tmp_path, env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
