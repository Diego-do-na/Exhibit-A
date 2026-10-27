"""Runs a pipeline over a corpus once per ablation and builds the results table."""

import json
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path

from exhibit_a.ledger import Ledger

from .corpus import Case
from .flags import ABLATIONS, Flags
from .metrics import CaseMetrics, Row, aggregate, case_metrics, render_table

# A pipeline analyses one case under the given flags and appends its events to the ledger
# under `run_id`. It is a plain callable so the real loop and test stubs are interchangeable.
Pipeline = Callable[[Case, Flags, Ledger, str], None]


def run_id_for(ablation: str, case: Case) -> str:
    return f"bench:{ablation}:{case.id}"


def run_benchmark(
    corpus: list[Case],
    pipeline: Pipeline,
    ledger: Ledger,
    ablations: dict[str, Flags] | None = None,
) -> list[Row]:
    """Run every case under every ablation and return one Row per ablation."""
    ablations = ABLATIONS if ablations is None else ablations
    rows: list[Row] = []
    for name, flags in ablations.items():
        parts: list[CaseMetrics] = []
        for case in corpus:
            run_id = run_id_for(name, case)
            pipeline(case, flags, ledger, run_id)
            parts.append(case_metrics(ledger, run_id, case, flags.naive))
        rows.append(aggregate(name, parts))
    return rows


def write_results(rows: list[Row], out_dir: str | Path) -> None:
    """Write results.md (table) and results.json (rows plus derived ratios)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.md").write_text(render_table(rows), encoding="utf-8")
    payload = [
        {
            **asdict(r),
            "tokens_per_proven": r.tokens_per_proven,
            "cost_per_proven": r.cost_per_proven,
        }
        for r in rows
    ]
    (out / "results.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
