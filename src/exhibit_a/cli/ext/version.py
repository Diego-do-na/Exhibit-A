"""Implementation of the ``version`` CLI subcommand (extension module)."""

from __future__ import annotations

import argparse

from exhibit_a import __version__


def cmd_version(args: argparse.Namespace) -> int:
    print(f"exhibit-a {__version__}")
    return 0


def register(sub: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Add the ``version`` subcommand to the CLI."""
    parser = sub.add_parser("version", help="Print the Exhibit A version and exit.")
    parser.set_defaults(func=cmd_version)
