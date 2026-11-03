"""Implementation of the ``init`` CLI subcommand (extension module).

Writes an example GitHub Actions workflow that runs the Exhibit A Action on
pull requests. No secret values are written: the workflow only references a
repository secret by name, so nothing sensitive lands in the file.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

WORKFLOW = """\
# Exhibit A: prove vulnerabilities in this pull request before reporting them.
# A green run means only that nothing could be proven, never that the change is safe.
name: Exhibit A

on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  exhibit-a:
    runs-on: ubuntu-latest
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Exhibit A on this pull request
        uses: Diego-do-na/Exhibit-A@main
        with:
          pr-diff: "${{ github.event.pull_request.base.sha }}..${{ github.event.pull_request.head.sha }}"
        env:
          # Name only: create this repository secret under Settings > Secrets.
          META_API_KEY: "${{ secrets.META_API_KEY }}"
"""


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(getattr(args, "path", None) or ".github/workflows/exhibit-a.yml")
    if target.exists() and not getattr(args, "force", False):
        print(f"init: {target} already exists (use --force to overwrite)", file=sys.stderr)
        return 2
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(WORKFLOW, encoding="utf-8", newline="\n")
    print(f"init: wrote {target}")
    print("init: create the META_API_KEY repository secret, then open a pull request.")
    return 0


def register(sub: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Add the ``init`` subcommand to the CLI."""
    parser = sub.add_parser(
        "init",
        help="Write an example GitHub Actions workflow that runs Exhibit A on pull requests.",
    )
    parser.add_argument("--path", default=None, metavar="FILE",
                        help="Where to write the workflow (default: .github/workflows/exhibit-a.yml).")
    parser.add_argument("--force", action="store_true", help="Overwrite an existing workflow file.")
    parser.set_defaults(func=cmd_init)
