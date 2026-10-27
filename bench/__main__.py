"""``python -m bench``: run the benchmark and write the results table.

The real pipeline is not wired here yet; pass ``--pipeline module:function`` for a callable
matching ``bench.runner.Pipeline``. ``--synthetic`` runs the scripted test stand-in and is
meant for smoke tests only.
"""

import argparse
import importlib
import sys
from pathlib import Path

from exhibit_a.ledger import Ledger

from .corpus import load_corpus
from .flags import select
from .metrics import render_table
from .runner import run_benchmark, write_results


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
        parser.error("give --pipeline module:function (or --synthetic for a smoke run)")

    ledger = Ledger(args.out / "ledger.jsonl")
    rows = run_benchmark(corpus, pipeline, ledger, select(args.ablation))
    write_results(rows, args.out)
    sys.stdout.write(render_table(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
