"""Implementation of the ``runs`` CLI subcommand."""

from __future__ import annotations

import argparse
import json
import sys

from ..ledger.index import read_runs


def _rows(records) -> list[list[str]]:
    return [
        [
            record.run_id,
            record.status,
            record.repo,
            record.commit,
            str(record.verdict_counts.proven),
            record.severity or "-",
            f"{record.duration_s:.2f}",
        ]
        for record in records
    ]


def _table(records) -> str:
    headers = ["RUN ID", "STATUS", "REPO", "COMMIT", "PROVEN", "SEVERITY", "SECONDS"]
    rows = _rows(records)
    widths = [len(header) for header in headers]
    for row in rows:
        widths = [max(width, len(value)) for width, value in zip(widths, row)]
    lines = ["  ".join(value.ljust(width) for value, width in zip(headers, widths))]
    lines.append("  ".join("-" * width for width in widths))
    lines.extend("  ".join(value.ljust(width) for value, width in zip(row, widths)) for row in rows)
    return "\n".join(lines)


def cmd_runs(args: argparse.Namespace) -> int:
    """Print the run index, preserving diagnostics for corrupt lines."""
    try:
        records, problems = read_runs(args.index)
    except OSError as exc:
        print(f"runs: cannot read {args.index}: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({
            "runs": [record.model_dump(mode="json") for record in records],
            "problems": problems,
        }, indent=2, sort_keys=True))
    else:
        print(_table(records))
        if problems:
            print("\nProblems:", file=sys.stderr)
            for problem in problems:
                print(problem, file=sys.stderr)
    return 0 if not problems else 1
