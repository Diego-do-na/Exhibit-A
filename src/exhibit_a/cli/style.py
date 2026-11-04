"""TTY-aware CLI layout: tags, aligned keys, Next steps, and progress.

Color and progress apply only on a tty and never when ``NO_COLOR`` is set.
JSON, pipes, and quiet mode stay plain.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence

OK = "[ok]"
WARN = "[warn]"
FAIL = "[fail]"
SKIP = "[skip]"

_KEY_WIDTH = 16
_RESET = "\033[0m"
_COLORS = {
    OK: "\033[32m",
    WARN: "\033[33m",
    FAIL: "\033[31m",
    SKIP: "\033[90m",
}


def color_enabled(*, stream=None) -> bool:
    """True only for an interactive tty that did not set ``NO_COLOR``."""
    if "NO_COLOR" in os.environ:
        return False
    stream = sys.stdout if stream is None else stream
    isatty = getattr(stream, "isatty", None)
    return bool(callable(isatty) and isatty())


def progress_enabled(*, stream=None) -> bool:
    """Progress lines belong on stderr of a tty, never in a pipe."""
    if "NO_COLOR" in os.environ:
        return False
    stream = sys.stderr if stream is None else stream
    isatty = getattr(stream, "isatty", None)
    return bool(callable(isatty) and isatty())


def paint(tag: str, *, stream=None) -> str:
    """Return ``tag`` wrapped in color when stdout is a tty."""
    if tag in _COLORS and color_enabled(stream=stream):
        return f"{_COLORS[tag]}{tag}{_RESET}"
    return tag


def section(title: str, *, file=None) -> None:
    print(title, file=sys.stdout if file is None else file)


def kv(key: str, value: object, *, file=None, width: int = _KEY_WIDTH) -> None:
    print(f"  {key:<{width}} {value}", file=sys.stdout if file is None else file)


def status(tag: str, message: str, *, file=None) -> None:
    print(f"{paint(tag)} {message}", file=sys.stdout if file is None else file)


def next_steps(commands: Sequence[str], *, file=None, note: str = "") -> None:
    """Print copyable commands under a ``Next steps`` heading."""
    out = sys.stdout if file is None else file
    print(file=out)
    print("Next steps", file=out)
    for line in commands:
        print(f"  {line}", file=out)
    if note:
        print(note, file=out)


def progress(message: str) -> None:
    """Write a single progress line to stderr, or nothing when piped."""
    if not progress_enabled():
        return
    print(message, file=sys.stderr)
