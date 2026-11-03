"""Implementation of the ``dashboard`` CLI subcommand."""

from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path


def resolve_source(source: str | None, *, cwd: Path | None = None) -> str | None:
    """Default the dashboard source to ``local:runs`` when that folder exists."""
    if source:
        return source
    root = (cwd or Path.cwd()) / "runs"
    if root.is_dir() and any(child.is_dir() for child in root.iterdir()):
        return "local:runs"
    return None


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Delegate to the optional local dashboard package."""
    try:
        importlib.import_module("exhibit_a.dashboard")
        server = importlib.import_module("exhibit_a.dashboard.server")
        dashboard_main = getattr(server, "main")
    except (ImportError, AttributeError):
        print("dashboard: dashboard not installed in this build", file=sys.stderr)
        return 2
    source = resolve_source(getattr(args, "source", None))
    if source is None:
        print(
            "dashboard: no runs found. Run something first (for example "
            "`exhibit-a run --case <case>`) or pass --source local:RUNS.",
            file=sys.stderr,
        )
        return 2
    forwarded = ["--source", source, "--port", str(getattr(args, "port", 0))]
    if getattr(args, "export", None):
        forwarded.extend(["--export", args.export])
    if getattr(args, "run", None):
        forwarded.extend(["--run", args.run])
    if getattr(args, "open", True):
        forwarded.append("--open")
    try:
        return int(dashboard_main(forwarded))
    except (OSError, ValueError) as exc:
        print(f"dashboard: {exc}", file=sys.stderr)
        return 1
