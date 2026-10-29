import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import __main__ as bench_main  # noqa: E402
from bench.corpus import load_corpus  # noqa: E402
import bench.loop_pipeline as loop_pipeline  # noqa: E402
import bench.synthetic as synthetic  # noqa: E402
from exhibit_a.ledger import Ledger  # noqa: E402
from exhibit_a.oracle import run_oracle  # noqa: E402
from exhibit_a.schemas import EventType  # noqa: E402


def _case_json(tmp_path: Path, *, recording: str = "replay.jsonl") -> Path:
    corpus = tmp_path / "case.json"
    payload = {
        "cases": [
            {
                "id": "demo",
                "kind": "vulnerable",
                "repo": "https://example.invalid/demo",
                "commit": "deadbeef",
                "ground_truth": [{"class": "path_traversal", "file": "app.py"}],
            }
        ],
        "run": {"recording": recording},
    }
    corpus.write_text(json.dumps(payload), encoding="utf-8")
    (tmp_path / recording).write_text("", encoding="utf-8")
    return corpus


def test_main_defaults_to_real_loop(tmp_path, monkeypatch):
    corpus = _case_json(tmp_path)
    seen = {}

    def fake_make_pipeline(providers):
        seen["providers"] = providers
        return "real-pipeline"

    monkeypatch.setattr(loop_pipeline, "make_pipeline", fake_make_pipeline)
    monkeypatch.setattr(bench_main, "run_benchmark", lambda *args, **kwargs: [])
    monkeypatch.setattr(bench_main, "write_results", lambda *args, **kwargs: None)
    monkeypatch.setattr(bench_main, "render_table", lambda rows: "")

    assert bench_main.main(["--corpus", str(corpus), "--out", str(tmp_path / "out")]) == 0
    assert seen["providers"]["demo"].path == tmp_path / "replay.jsonl"


def test_main_accepts_directory_corpus(tmp_path, monkeypatch):
    case_dir = tmp_path / "corpus" / "demo-case"
    case_dir.mkdir(parents=True)
    payload = {
        "cases": [
            {
                "id": "demo-case",
                "kind": "vulnerable",
                "repo": "https://example.invalid/demo",
                "commit": "deadbeef",
            }
        ],
        "run": {"recording": "replay.jsonl"},
    }
    (case_dir / "case.json").write_text(json.dumps(payload), encoding="utf-8")
    (case_dir / "replay.jsonl").write_text("", encoding="utf-8")
    seen = {}

    def fake_make_pipeline(providers):
        seen["providers"] = providers
        return "real-pipeline"

    monkeypatch.setattr(loop_pipeline, "make_pipeline", fake_make_pipeline)
    monkeypatch.setattr(bench_main, "run_benchmark", lambda *args, **kwargs: [])
    monkeypatch.setattr(bench_main, "write_results", lambda *args, **kwargs: None)
    monkeypatch.setattr(bench_main, "render_table", lambda rows: "")

    assert bench_main.main(["--corpus", str(tmp_path / "corpus"), "--out", str(tmp_path / "out")]) == 0
    assert seen["providers"]["demo-case"].path == case_dir / "replay.jsonl"


class _HostRunner:
    """Stand-in for the Docker-backed SandboxRunner used by the real-path test.

    The Docker container is the only substituted part: the baseline still runs
    the case's real test file under pytest and the exploit still goes through
    the real oracle judgement, both on the host. Everything else (corpus
    loading, replay providers, pipeline, loop, ledger) is the production path.
    """

    def __init__(self, *args, **kwargs):
        pass

    def run_baseline(self, clone, test_path, timeout):
        env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(clone),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(test_path)],
            cwd=str(clone),
            env=env,
            capture_output=True,
            timeout=180,
        )
        return {
            "outcome": "passed" if proc.returncode == 0 else "failed",
            "exit_code": proc.returncode,
            "stdout": proc.stdout.decode(),
            "stderr": proc.stderr.decode(),
            "oracle_events": [],
        }

    def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect="canary_read"):
        return run_oracle(app_root, test_path, entry_points, timeout=timeout, effect=effect)


def _assert_ordered_subsequence(kinds: list[str], wanted: list[str]) -> None:
    """Every kind in `wanted` appears in `kinds` in order (other events may sit between)."""
    pos = -1
    for want in wanted:
        assert want in kinds[pos + 1:], f"{want} missing after position {pos} in {kinds}"
        pos = kinds.index(want, pos + 1)


def test_main_runs_real_loop_on_copied_corpus(tmp_path, monkeypatch, capsys):
    """End to end through bench main() with no pipeline mocks.

    Copies the two Starlette cases (vulnerable + fixed, with their existing
    replay recordings) into a temporary corpus directory and runs the real
    ``main``: real corpus loading, real replay providers, the real loop
    pipeline over the real VerificationLoop, and real result/ledger files.
    Only two seams are substituted: the Docker-backed SandboxRunner (a host
    runner above) and the PyPI index (a wheelhouse downloaded once, then a
    hermetic ``PIP_NO_INDEX`` install through the real installer).
    """
    corpus_dir = tmp_path / "corpus"
    for name in ("starlette-cve-2023-29159", "starlette-cve-2023-29159-fixed"):
        shutil.copytree(ROOT / "bench" / "corpus" / name, corpus_dir / name)

    # Hermetic install: fetch the pinned wheels once with the ambient
    # environment (proxy included), then install offline so the replay keys,
    # which hash the staged source, match the shipped recordings byte for byte.
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    for case in load_corpus(corpus_dir):
        if case.requirements:
            proc = subprocess.run(
                [sys.executable, "-m", "pip", "download", "-d", str(wheelhouse),
                 *case.requirements],
                capture_output=True,
                text=True,
                timeout=240,
            )
            assert proc.returncode == 0, proc.stderr[-2000:]
    monkeypatch.setenv("PIP_FIND_LINKS", str(wheelhouse))
    monkeypatch.setenv("PIP_NO_INDEX", "1")

    monkeypatch.setattr(loop_pipeline, "SandboxRunner", _HostRunner)

    out = tmp_path / "out"
    assert bench_main.main(["--corpus", str(corpus_dir), "--out", str(out),
                            "--ablation", "full"]) == 0

    rows = json.loads((out / "results.json").read_text(encoding="utf-8"))
    assert [row["ablation"] for row in rows] == ["full"]
    assert rows[0]["proven"] == 1 and rows[0]["reported"] == 1

    shown = capsys.readouterr().out
    assert "case starlette-cve-2023-29159 (vulnerable) [full]: reported=1 proven=1" in shown
    assert "case starlette-cve-2023-29159-fixed (fixed) [full]: reported=0 proven=0" in shown

    ledger = Ledger(out / "ledger.jsonl")
    vuln_id = "bench:full:starlette-cve-2023-29159"
    fixed_id = "bench:full:starlette-cve-2023-29159-fixed"
    wanted = ["pr_opened", "baseline_done", "suspicion_raised", "exploit_written",
              "run_started", "verdict"]
    vuln_kinds = [event.type.value for event in ledger.replay(vuln_id)]
    fixed_kinds = [event.type.value for event in ledger.replay(fixed_id)]
    _assert_ordered_subsequence(vuln_kinds, wanted)
    _assert_ordered_subsequence(fixed_kinds, wanted)

    vuln_verdicts = [e for e in ledger.replay(vuln_id) if e.type == EventType.VERDICT]
    assert len(vuln_verdicts) == 1
    assert vuln_verdicts[0].payload["suspicion_id"] == "starlette-staticfiles-prefix"
    assert vuln_verdicts[0].payload["verdict"] == "proven"
    assert "fix_proposed" in vuln_kinds and "packaged" in vuln_kinds

    fixed_verdicts = [e for e in ledger.replay(fixed_id) if e.type == EventType.VERDICT]
    assert len(fixed_verdicts) == 1
    assert fixed_verdicts[0].payload["verdict"] == "discarded_unproven"
    assert "packaged" not in fixed_kinds


def test_main_keeps_synthetic_smoke_run(tmp_path, monkeypatch):
    corpus = tmp_path / "corpus.json"
    corpus.write_text("{}", encoding="utf-8")
    seen = {}

    def fake_make_pipeline(provider):
        seen["provider"] = provider
        return "synthetic-pipeline"

    monkeypatch.setattr(bench_main, "load_corpus", lambda _: [])
    monkeypatch.setattr(synthetic, "make_pipeline", fake_make_pipeline)
    monkeypatch.setattr(bench_main, "run_benchmark", lambda *args, **kwargs: [])
    monkeypatch.setattr(bench_main, "write_results", lambda *args, **kwargs: None)
    monkeypatch.setattr(bench_main, "render_table", lambda rows: "")

    assert bench_main.main(["--corpus", str(corpus), "--out", str(tmp_path / "out"), "--synthetic"]) == 0
    assert seen["provider"] is not None
