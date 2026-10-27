"""Command-line interface for Exhibit A.

Run it with::

    python -m exhibit_a.cli <subcommand> [options]

There is no ``exhibit-a`` console entry point yet: ``pyproject.toml`` declares
no ``[project.scripts]`` table, so this skeleton documents the ``python -m``
invocation instead of adding one.

Skeleton subcommands (SPEC.md sections 3, 6, 9):

- ``scan`` prints a RepoProfile placeholder for the target repository.
- ``run`` accepts the core-loop flags and reports the loop is not wired yet.
- ``ledger`` prints token, cost and verdict totals for one run id, read from a
  ledger file.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .ledger import Ledger
from .schemas import Baseline, RepoProfile

# Message printed by every subcommand that has no engine behind it yet.
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
        "run", help="Run the core loop (not wired yet)."
    )
    run.add_argument("--repo", default=".", help="Path to the target clone.")
    run.add_argument("--diff", default=None, help="Path to the PR diff file.")
    run.add_argument(
        "--replay",
        action="store_true",
        help="Replay recorded model calls instead of calling a provider.",
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


def cmd_scan(args: argparse.Namespace) -> int:
    """Print a RepoProfile placeholder as JSON.

    The placeholder is built through the real RepoProfile schema, so the
    printed document always matches the SPEC.md contract.
    """
    _ = args  # scan takes no options yet; the scanner is a later task.
    profile = RepoProfile(
        commit="unknown",
        language="unknown",
        interpreter="unknown",
        dependency_manager="unknown",
        install_cmd="unknown",
        test_cmd="unknown",
        framework="unknown",
        dependencies=[],
        baseline=Baseline(passed=0, failed=0, seconds=0.0),
    )
    print(profile.model_dump_json(indent=2))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Accept the core-loop flags and report the loop is not wired yet."""
    print(
        f"run: the core loop is {NOT_WIRED_YET} "
        f"(repo={args.repo!r}, diff={args.diff!r}, "
        f"replay={args.replay!r}, budget_usd={args.budget_usd!r})"
    )
    return 0


def cmd_ledger(args: argparse.Namespace) -> int:
    """Print token, cost and verdict totals for one run id as JSON."""
    try:
        totals = Ledger(Path(args.ledger)).totals(args.run_id)
    except (OSError, ValueError) as exc:
        print(f"ledger: cannot read {args.ledger}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(totals, indent=2))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``python -m exhibit_a.cli``. Returns an exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
