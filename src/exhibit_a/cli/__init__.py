"""Command-line interface for Exhibit A."""

from __future__ import annotations

from collections.abc import Sequence

from .ledger import cmd_ledger
from .advisories import cmd_advisories
from .dashboard import cmd_dashboard
from .parser import NOT_WIRED_YET, build_parser
from .report import cmd_report
from .run import cmd_run
from .runs import cmd_runs
from .scan import cmd_scan


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``python -m exhibit_a.cli``. Returns an exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


__all__ = [
    "NOT_WIRED_YET",
    "build_parser",
    "cmd_ledger",
    "cmd_advisories",
    "cmd_dashboard",
    "cmd_report",
    "cmd_run",
    "cmd_runs",
    "cmd_scan",
    "main",
]
