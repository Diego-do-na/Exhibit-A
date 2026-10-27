"""Implementation of the ``ledger`` CLI subcommand."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..ledger import Ledger


def cmd_ledger(args: argparse.Namespace) -> int:
    """Print token, cost and verdict totals for one run id as JSON."""
    try:
        totals = Ledger(Path(args.ledger)).totals(args.run_id)
    except (OSError, ValueError) as exc:
        print(f"ledger: cannot read {args.ledger}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(totals, indent=2))
    return 0
