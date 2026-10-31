"""Argument parser shared by the Exhibit A CLI entry points."""

from __future__ import annotations

import argparse
from typing import get_args

from .ledger import cmd_ledger
from .run import cmd_run
from .scan import cmd_scan
from .advisories import cmd_advisories
from .dashboard import cmd_dashboard
from .report import cmd_report
from .runs import cmd_runs
from .trace import cmd_trace
from ..models.config import PROVIDER_REGISTRY
from ..oracle.oracle import Effect
from .ext import register_all as register_extensions

NOT_WIRED_YET = "not wired yet"


def _provider_name(value: str) -> str:
    if value not in PROVIDER_REGISTRY:
        raise argparse.ArgumentTypeError(
            f"unknown provider {value!r}; known providers: {sorted(PROVIDER_REGISTRY)}"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the skeleton CLI."""
    parser = argparse.ArgumentParser(
        prog="exhibit_a.cli",
        description="Exhibit A skeleton CLI: proof before accusation.",
        epilog="Exit codes: 0 success; 1 runtime error; 2 usage or input error.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser(
        "scan",
        help="Print the RepoProfile of a repository (a placeholder without one), "
        "optionally with its call graph and reach paths.",
    )
    scan.add_argument(
        "repo", nargs="?", default=None,
        help="Repository to scan. Without it, a RepoProfile placeholder is printed.",
    )
    scan.add_argument(
        "--graph", action="store_true",
        help="Add a summary of the static call graph (entry points, sinks, sizes).",
    )
    scan.add_argument(
        "--graph-out", default=None, metavar="FILE",
        help="With --graph, also write the whole graph as JSON to FILE.",
    )
    scan.add_argument(
        "--pr-diff", default=None, metavar="BASE..HEAD",
        help="Add the reach paths (entry -> changed function -> sink) of the commits' changes.",
    )
    scan.add_argument(
        "--entry-point", action="append", default=None, metavar="NAME",
        help="Declared entry point (Class.method); repeatable. Declared names replace detection.",
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
        "--pr-diff",
        default=None,
        metavar="BASE..HEAD",
        help="Run the proof loop on Python files changed between two commits.",
    )
    run.add_argument(
        "--out",
        default="runs/case",
        help="Output directory for the clone, ledger and packages (default: runs/case).",
    )
    run.add_argument("--repo", default=".", help="Path to the target clone.")
    run.add_argument("--diff", default=None, help="Path to the PR diff file.")
    run.add_argument(
        "--recording",
        default=None,
        help="Replay recording for a PR-diff run (also read from EXHIBIT_A_REPLAY_RECORDING).",
    )
    run.add_argument(
        "--effect",
        choices=get_args(Effect),
        default="canary_read",
        help="Oracle effect to prove in PR-diff mode (default: canary_read).",
    )
    run.add_argument(
        "--replay",
        action="store_true",
        help="Replay recorded model calls instead of calling a provider.",
    )
    # Provider/model selection for live runs. Choices are driven by the
    # provider registry so new backends appear automatically.
    run.add_argument(
        "--provider",
        type=_provider_name,
        default=None,
        help="Model provider to use for every role (overrides EXHIBIT_A_PROVIDER).",
    )
    run.add_argument(
        "--model",
        default=None,
        help="Model name to use for every role (overrides EXHIBIT_A_MODEL).",
    )
    run.add_argument(
        "--profile",
        choices=("standard", "compact"),
        default="standard",
        help=(
            "Prompt profile. 'compact' bounds every answer, asks the fixer for search/replace "
            "edits, and defaults to --reasoning-effort minimal plus per-role output caps, "
            "to cut cost. 'standard' (default) matches the recorded replays."
        ),
    )
    run.add_argument(
        "--slice",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Build the static call graph first: when no changed function is on a path from an "
            "entry point to a sink, record that and make no model call; otherwise send the "
            "adversary only the functions on those paths and judge with the graph's entry "
            "point, never the model's. On by default with --profile compact, off with the "
            "standard profile; --slice / --no-slice override."
        ),
    )
    run.add_argument(
        "--reasoning-effort",
        choices=("minimal", "low", "medium", "high", "max"),
        default=None,
        help="Reasoning effort sent to chat-completions providers (default: provider default; minimal with --profile compact).",
    )
    run.add_argument(
        "--max-output-tokens",
        type=int,
        default=None,
        metavar="N",
        help="Output-token ceiling per model call (default: none; per-role caps with --profile compact).",
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

    trace = sub.add_parser(
        "trace", help="Print the ordered steps one run took, from its ledger."
    )
    trace.add_argument("run_id", help="Run id whose steps to print.")
    trace.add_argument(
        "--ledger",
        default="ledger.jsonl",
        help="Path to the append-only JSONL ledger (default: ledger.jsonl).",
    )
    trace.add_argument("--json", action="store_true", help="Print JSON instead of text.")
    trace.set_defaults(func=cmd_trace)

    report = sub.add_parser("report", help="Render a finding package as Markdown or HTML.")
    report.add_argument("package_dir")
    report.add_argument("--format", choices=("md", "html"), default="md")
    report.add_argument("--out", default=None, metavar="FILE")
    report.set_defaults(func=cmd_report)

    runs = sub.add_parser("runs", help="Print the table of past runs.")
    runs.add_argument("--index", default="runs.jsonl")
    runs.add_argument("--json", action="store_true")
    runs.set_defaults(func=cmd_runs)

    advisories = sub.add_parser("advisories", help="Look up OSV advisories (hint, not proof).")
    advisories.add_argument("--requirements", default=None, metavar="FILE")
    advisories.add_argument("--pyproject", default=None, metavar="FILE")
    advisories.add_argument("--offline", default=None, metavar="FIXTURE")
    advisories.add_argument("--json", action="store_true")
    advisories.set_defaults(func=cmd_advisories)

    dashboard = sub.add_parser("dashboard", help="Serve the optional local dashboard.")
    dashboard.add_argument("--source", required=True, help="Dashboard source, such as local:RUNS.")
    dashboard.add_argument("--port", type=int, default=8765)
    dashboard.set_defaults(func=cmd_dashboard)

    register_extensions(sub)
    return parser
