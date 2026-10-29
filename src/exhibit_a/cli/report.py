"""Implementation of the ``report`` CLI subcommand."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..report import render_html, render_markdown


def cmd_report(args: argparse.Namespace) -> int:
    """Render a finding package to stdout or a file."""
    try:
        rendered = (
            render_html(args.package_dir)
            if args.format == "html"
            else render_markdown(args.package_dir)
        )
        if args.out:
            Path(args.out).write_text(rendered, encoding="utf-8")
        else:
            print(rendered)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"report: cannot render {args.package_dir}: {exc}", file=sys.stderr)
        return 1
    return 0
