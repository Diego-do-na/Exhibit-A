"""``python -m bench``: run the benchmark and write the results table.

The default benchmark path uses the real loop adapter in ``bench.loop_pipeline`` and a
replay recording when a corpus defines one. ``--synthetic`` runs the scripted stand-in and is
meant for smoke tests only.
"""

import argparse
import importlib
import json
import sys
from pathlib import Path

from exhibit_a.ledger import Ledger
from exhibit_a.models import ReplayProvider

from .corpus import load_corpus
from .flags import select
from .metrics import render_table
from .runner import run_benchmark, write_results


def _default_replay_path(corpus_path: Path) -> Path:
    """Resolve the replay recording next to the corpus, if defined."""
    path = Path(corpus_path)
    if path.is_dir():
        case_json = path / "case.json"
        if case_json.exists():
            path = case_json
        else:
            replay = path / "replay.jsonl"
            if replay.exists():
                return replay
            raise FileNotFoundError(f"no replay recording found for {path}")

    data = json.loads(path.read_text(encoding="utf-8"))
    recording = data.get("run", {}).get("recording")
    if recording:
        replay = path.parent / recording
        if replay.exists():
            return replay
    replay = path.parent / "replay.jsonl"
    if replay.exists():
        return replay
    raise FileNotFoundError(f"no replay recording found near {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench", description=__doc__)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path, help="output directory")
    parser.add_argument("--pipeline", help="module:function implementing Pipeline")
    parser.add_argument("--synthetic", action="store_true", help="scripted stand-in (tests only)")
    parser.add_argument("--ablation", action="append", help="repeatable; default all")
    args = parser.parse_args(argv)

    corpus = load_corpus(args.corpus)
    if args.synthetic:
        from .synthetic import ScriptedProvider, make_pipeline

        pipeline = make_pipeline(ScriptedProvider(corpus))
    elif args.pipeline:
        module, _, attr = args.pipeline.partition(":")
        pipeline = getattr(importlib.import_module(module), attr)
    else:
        from .loop_pipeline import make_pipeline

        try:
            replay = _default_replay_path(args.corpus)
        except FileNotFoundError as exc:
            parser.error(str(exc))
        pipeline = make_pipeline(ReplayProvider(replay))

    ledger = Ledger(args.out / "ledger.jsonl")
    rows = run_benchmark(corpus, pipeline, ledger, select(args.ablation))
    write_results(rows, args.out)
    sys.stdout.write(render_table(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
