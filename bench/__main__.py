"""``python -m bench``: run the benchmark and write the results table.

The default benchmark path runs the real loop adapter in ``bench.loop_pipeline``
with one provider per case: the case's replay recording when it declares one,
otherwise a deterministic provider built from the case's own materials
(``suspicion.json``, labelled exploits, fixed tree). ``--synthetic`` runs the
scripted stand-in and is meant for smoke tests only.
"""

import argparse
import importlib
import sys
from pathlib import Path

from exhibit_a.ledger import Ledger
from exhibit_a.models import ModelError, ReplayProvider

from .corpus import Case, load_corpus
from .flags import select
from .metrics import case_metrics, render_table
from .runner import run_benchmark, run_id_for, write_results


def _provider_for_case(case: Case):
    """Resolve the model-answer provider for one case.

    A case that declares ``run.recording`` and ships the file replays it; a
    case that ships its own materials (``suspicion.json``) runs from those.
    Anything else is a corpus bug, reported as a clear ``FileNotFoundError``.
    """
    from .loop_pipeline import CaseMaterialsProvider

    if case.case_dir:
        case_dir = Path(case.case_dir)
        if case.recording and (case_dir / case.recording).is_file():
            return ReplayProvider(case_dir / case.recording)
        if (case_dir / "suspicion.json").is_file():
            return CaseMaterialsProvider(case)
    raise FileNotFoundError(
        f"no replay recording for case {case.id!r}: "
        "declare run.recording in case.json or ship suspicion.json materials"
    )


def _compare(out: Path | None, doc: Path | None) -> int:
    from .baseline import DOC_PATH, RESULTS_DIR, ComparisonError, render_section, run_comparison

    try:
        result, path = run_comparison(out or RESULTS_DIR, doc or DOC_PATH)
    except (ComparisonError, FileNotFoundError, ModelError, RuntimeError) as exc:
        print(f"bench: comparison not written: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(render_section(result))
    sys.stdout.write(f"results: {path}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench", description=__doc__)
    parser.add_argument("--corpus", type=Path,
                        help="corpus file, single case.json, or corpus directory")
    parser.add_argument("--out", type=Path, help="output directory")
    parser.add_argument("--pipeline", help="module:function implementing Pipeline")
    parser.add_argument("--synthetic", action="store_true", help="scripted stand-in (tests only)")
    parser.add_argument("--ablation", action="append", help="repeatable; default all")
    parser.add_argument("--compare", choices=["baseline"],
                        help="replay the naive baseline and Exhibit A offline, write bench/results "
                             "(or --out) and regenerate docs/bench.md (or --doc)")
    parser.add_argument("--doc", type=Path, help="document to regenerate with --compare")
    args = parser.parse_args(argv)

    if args.compare:
        return _compare(args.out, args.doc)
    if args.corpus is None or args.out is None:
        parser.error("the following arguments are required: --corpus, --out")

    try:
        corpus = load_corpus(args.corpus)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    try:
        ablations = select(args.ablation)
    except ValueError as exc:
        parser.error(str(exc))
    if args.synthetic:
        from .synthetic import ScriptedProvider, make_pipeline

        pipeline = make_pipeline(ScriptedProvider(corpus))
    elif args.pipeline:
        module, _, attr = args.pipeline.partition(":")
        pipeline = getattr(importlib.import_module(module), attr)
    else:
        from .loop_pipeline import make_pipeline

        try:
            providers = {case.id: _provider_for_case(case) for case in corpus}
        except (FileNotFoundError, ValueError) as exc:
            parser.error(str(exc))
        pipeline = make_pipeline(providers)

    ledger = Ledger(args.out / "ledger.jsonl")
    rows = run_benchmark(corpus, pipeline, ledger, ablations)
    write_results(rows, args.out)
    sys.stdout.write(render_table(rows))
    # One result row per case under the full ablation (or the first ablation
    # when --ablation excludes it), so a corpus run shows every case's reading.
    ablation = "full" if "full" in ablations else next(iter(ablations))
    flags = ablations[ablation]
    for case in corpus:
        metrics = case_metrics(ledger, run_id_for(ablation, case), case, flags.naive)
        sys.stdout.write(
            f"case {case.id} ({case.kind}) [{ablation}]: "
            f"reported={metrics.reported} proven={metrics.proven} "
            f"false_positives={metrics.false_positives} "
            f"discarded={metrics.discarded} "
            f"truth_found={metrics.truth_found}/{metrics.truth_total}\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
