"""Argument parser shared by the Exhibit A CLI entry points."""

from __future__ import annotations

import argparse

from .ledger import cmd_ledger
from .run import cmd_run
from .scan import cmd_scan
from ..models.config import PROVIDER_REGISTRY

NOT_WIRED_YET = "not wired yet"


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the skeleton CLI."""
    parser = argparse.ArgumentParser(
        prog="exhibit_a.cli",
        description="Exhibit A skeleton CLI: proof before accusation.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser(
        "scan", help="Print a RepoProfile placeholder and exit."
    )
    scan.set_defaults(func=cmd_scan)

    run = sub.add_parser(
        "run", help="Run the core loop (wired for benchmark cases via --case)."
    )
    run.add_argument(
        "--case",
        default=None,
        help="Benchmark case.json (or its directory) to run the loop on.",
    )
    run.add_argument(
        "--out",
        default="runs/case",
        help="Output directory for the clone, ledger and packages (default: runs/case).",
    )
    run.add_argument("--repo", default=".", help="Path to the target clone.")
    run.add_argument("--diff", default=None, help="Path to the PR diff file.")
    run.add_argument(
        "--replay",
        action="store_true",
        help="Replay recorded model calls instead of calling a provider.",
    )
    # Provider/model selection for live runs. Choices are driven by the
    # provider registry so new backends appear automatically.
    run.add_argument(
        "--provider",
        choices=sorted(PROVIDER_REGISTRY),
        default=None,
        help="Model provider to use for every role (overrides EXHIBIT_A_PROVIDER).",
    )
    run.add_argument(
        "--model",
        default=None,
        help="Model name to use for every role (overrides EXHIBIT_A_MODEL).",
    )
    run.add_argument(
        "--budget-usd",
        type=float,
        default=None,
        help="Hard cost limit in USD for this run.",
    )
    run.set_defaults(func=cmd_run)

    ledger = sub.add_parser(
        "ledger", help="Print totals for one run id from a ledger file."
    )
    ledger.add_argument("run_id", help="Run id to total up.")
    ledger.add_argument(
        "--ledger",
        default="ledger.jsonl",
        help="Path to the append-only JSONL ledger (default: ledger.jsonl).",
    )
    ledger.set_defaults(func=cmd_ledger)
    return parser
    return parser
