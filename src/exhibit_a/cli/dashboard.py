"""Implementation of the ``dashboard`` CLI subcommand."""

from __future__ import annotations

import argparse
import importlib
import sys


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Delegate to the optional local dashboard package."""
    try:
        importlib.import_module("exhibit_a.dashboard")
        server = importlib.import_module("exhibit_a.dashboard.server")
        dashboard_main = getattr(server, "main")
    except (ImportError, AttributeError):
        print("dashboard: dashboard not installed in this build", file=sys.stderr)
        return 2
    forwarded = ["--source", args.source, "--port", str(args.port)]
    if getattr(args, "export", None):
        forwarded.extend(["--export", args.export])
    if getattr(args, "run", None):
        forwarded.extend(["--run", args.run])
    if getattr(args, "open", False):
        forwarded.append("--open")
    try:
        return int(dashboard_main(forwarded))
    except (OSError, ValueError) as exc:
        print(f"dashboard: {exc}", file=sys.stderr)
        return 1
