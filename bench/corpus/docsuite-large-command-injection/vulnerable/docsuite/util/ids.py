"""Identifier helpers."""

import itertools
import re

_COUNTERS = {}
_ID = re.compile(r"[a-z]+-[0-9]+")


def next_id(kind):
    """The next identifier of a kind: ``doc-4``, ``job-12``."""
    counter = _COUNTERS.setdefault(kind, itertools.count(1))
    return f"{kind}-{next(counter)}"


def reserve(kind, used):
    """Make ``next_id(kind)`` continue after the highest of the identifiers in ``used``."""
    highest = 0
    for name in used:
        match = _ID.fullmatch(name)
        if match and name.startswith(kind + "-"):
            highest = max(highest, int(name.rsplit("-", 1)[1]))
    _COUNTERS[kind] = itertools.count(highest + 1)


def is_id(text, kind):
    """Whether ``text`` looks like an identifier of ``kind``."""
    return bool(_ID.fullmatch(text)) and text.startswith(kind + "-")
