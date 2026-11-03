"""ASCII banner slot for interactive CLI commands.

The banner is a plain-text file next to this module so it can be swapped
without touching Python. It is printed only on human-facing commands
(``init`` and when the dashboard starts), never on JSON or other machine
output, and it is disabled by ``--no-banner``, ``NO_COLOR``, or a non-tty.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

LOGO_PATH = Path(__file__).with_name("logo.txt")
TAGLINE = "EXHIBIT A - proof before accusation"


def load_logo(path: Path = LOGO_PATH) -> str:
    """Return the banner file contents (UTF-8). Tests enforce ASCII and size."""
    return path.read_text(encoding="utf-8")


def banner_enabled(args: argparse.Namespace | None = None, *, stream=None) -> bool:
    """Whether the ASCII banner should be printed on this invocation."""
    if args is not None:
        if getattr(args, "no_banner", False):
            return False
        if getattr(args, "json", False):
            return False
    if "NO_COLOR" in os.environ:
        return False
    stream = sys.stdout if stream is None else stream
    isatty = getattr(stream, "isatty", None)
    return bool(callable(isatty) and isatty())


def print_banner(args: argparse.Namespace | None = None) -> None:
    """Print the banner to stderr when this is an interactive human session."""
    if not banner_enabled(args, stream=sys.stdout):
        return
    text = load_logo().rstrip("\n")
    print(text, file=sys.stderr)
