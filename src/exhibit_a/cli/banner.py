"""ASCII banner slot for interactive CLI commands.

The banner is a plain-text file next to this module so it can be swapped
without touching Python. The full logo is printed only on no-args,
``--version``, and ``init``. Other human commands get one line
``exhibit-a <ver>  proof before accusation``. It is never printed on JSON,
pipes, ``NO_COLOR``, ``--no-banner``, ``-q``, or a non-tty.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from exhibit_a import __version__

LOGO_PATH = Path(__file__).with_name("logo.txt")
TAGLINE = "proof before accusation"
FULL_COMMANDS = frozenset({"init", "version"})
MACHINE_COMMANDS = frozenset({"scan", "ledger"})


def load_logo(path: Path = LOGO_PATH) -> str:
    """Return the banner file contents (UTF-8). Tests enforce ASCII and size."""
    return path.read_text(encoding="utf-8")


def identity_line(version: str = __version__) -> str:
    """One-line identity used by every human command that is not logo-full."""
    return f"exhibit-a {version}  {TAGLINE}"


def is_machine_output(args: argparse.Namespace | None) -> bool:
    """True when stdout is JSON or another document the caller will parse."""
    if args is None:
        return False
    if getattr(args, "json", False):
        return True
    command = getattr(args, "command", None)
    if command in MACHINE_COMMANDS:
        return True
    return False


def banner_enabled(args: argparse.Namespace | None = None, *, stream=None) -> bool:
    """Whether any identity line or logo should be printed on this invocation."""
    if args is not None:
        if getattr(args, "no_banner", False):
            return False
        if getattr(args, "quiet", False):
            return False
        if is_machine_output(args):
            return False
    if "NO_COLOR" in os.environ:
        return False
    stream = sys.stdout if stream is None else stream
    isatty = getattr(stream, "isatty", None)
    return bool(callable(isatty) and isatty())


def wants_full_logo(args: argparse.Namespace | None = None) -> bool:
    """True for no-args, ``--version``, and ``init`` (and the ``version`` command)."""
    if args is None:
        return True
    if getattr(args, "version", False) and not getattr(args, "command", None):
        return True
    return getattr(args, "command", None) in FULL_COMMANDS


def print_banner(args: argparse.Namespace | None = None) -> None:
    """Print the full logo to stderr when this is an interactive human session."""
    if not banner_enabled(args, stream=sys.stdout):
        return
    print(load_logo().rstrip("\n"), file=sys.stderr)


def print_intro(args: argparse.Namespace | None = None) -> None:
    """Print either the full logo or the one-line identity, never both."""
    if not banner_enabled(args, stream=sys.stdout):
        return
    if wants_full_logo(args):
        print(load_logo().rstrip("\n"), file=sys.stderr)
        return
    print(identity_line(), file=sys.stderr)
