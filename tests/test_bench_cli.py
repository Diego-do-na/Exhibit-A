import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import __main__ as bench_main  # noqa: E402
import bench.loop_pipeline as loop_pipeline  # noqa: E402
import bench.synthetic as synthetic  # noqa: E402


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
