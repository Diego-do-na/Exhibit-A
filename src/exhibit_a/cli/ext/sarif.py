"""CLI extension for exporting proven findings to SARIF 2.1.0."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ...report.sarif import generate_sarif


def cmd_sarif(args: argparse.Namespace) -> int:
    """Generate SARIF 2.1.0 for a run directory."""
    out_dir = Path(args.out_dir)
    if not out_dir.exists():
        sys.stderr.write(f"error: run directory does not exist: {args.out_dir}\n")
        return 2

    try:
        sarif_doc = generate_sarif(out_dir)
    except Exception as exc:
        sys.stderr.write(f"error: failed to generate SARIF: {exc}\n")
        return 1

    formatted = json.dumps(sarif_doc, indent=2) + "\n"

    if args.output:
        try:
            out_file = Path(args.output)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(formatted, encoding="utf-8")
        except OSError as exc:
            sys.stderr.write(f"error: could not write {args.output}: {exc}\n")
            return 1
    else:
        sys.stdout.write(formatted)

    return 0


def register(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the 'sarif' subcommand."""
    parser = sub.add_parser(
        "sarif",
        help="Export proven findings from a run directory to SARIF 2.1.0 for code scanning.",
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        metavar="DIR",
        help="Run directory containing packages/ and ledger.jsonl.",
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="File to write SARIF JSON to (default: stdout).",
    )
    parser.set_defaults(func=cmd_sarif)
