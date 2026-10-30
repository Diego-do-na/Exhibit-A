"""Implementation of the ``trace`` CLI subcommand."""

from __future__ import annotations

import argparse
import json
import sys

from ..ledger.trace import build_trace, render_text, trace_to_dict


def cmd_trace(args: argparse.Namespace) -> int:
    """Print the ordered steps of one run, as aligned text or (--json) as JSON."""
    try:
        steps = build_trace(args.ledger, args.run_id)
    except (OSError, ValueError) as exc:
        print(f"trace: cannot read {args.ledger}: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(trace_to_dict(args.run_id, steps), indent=2))
    else:
        print(render_text(args.run_id, steps))
    return 0
