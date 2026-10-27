"""Command-line interface for Exhibit A."""

from __future__ import annotations

from collections.abc import Sequence

from .ledger import cmd_ledger
from .parser import NOT_WIRED_YET, build_parser
from .run import cmd_run
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
    "cmd_run",
    "cmd_scan",
    "main",
]
