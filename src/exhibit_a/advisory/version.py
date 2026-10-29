"""Minimal PEP 440 version parsing and ordering for PyPI advisory ranges.

`packaging` is not a declared dependency of Exhibit A, so this module implements the
subset of PEP 440 that advisory range evaluation needs: parsing (with the spelling
normalizations PEP 440 allows), total ordering, and a coarse "how big is this upgrade"
classification. It does not implement specifier sets (``>=1,<2``); ranges come from OSV
events, which are single versions.

A small SemVer 2.0 key is included for OSV ``SEMVER`` ranges.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# PEP 440 public version plus optional local label, case-insensitive, with the optional
# separators the standard permits between components.
_PEP440 = re.compile(
    r"""
    ^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?:[-_.]?(?P<pre_l>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?:
        -(?P<post_implicit>[0-9]+)
        |
        [-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n>[0-9]+)?
    )?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$
    """,
    re.VERBOSE | re.IGNORECASE,
)

_PRE_PHASE = {"a": "a", "alpha": "a", "b": "b", "beta": "b", "c": "rc", "rc": "rc",
              "pre": "rc", "preview": "rc"}
_PHASE_RANK = {"a": 0, "b": 1, "rc": 2}


_MAX_DIGITS = 20  # longer numeric components are rejected, not converted (int() cost and limits)


def _num(text: str) -> int:
    if len(text) > _MAX_DIGITS:
        raise InvalidVersion(f"numeric version component longer than {_MAX_DIGITS} digits")
    return int(text)


class InvalidVersion(ValueError):
    """The string is not a valid PEP 440 (or SemVer) version."""


@dataclass(frozen=True)
class Version:
    """A parsed PEP 440 version. Ordering follows PEP 440, equality ignores
    trailing zero release components (``1.0 == 1.0.0``)."""

    text: str
    epoch: int
    release: tuple[int, ...]
    pre: tuple[str, int] | None
    post: int | None
    dev: int | None
    local: tuple[int | str, ...] | None
    _key: tuple = field(repr=False, compare=False)

    @classmethod
    def parse(cls, text: str) -> "Version":
        if not isinstance(text, str):
            raise InvalidVersion(f"version must be a string, got {type(text).__name__}")
        m = _PEP440.match(text)
        if m is None:
            raise InvalidVersion(f"not a PEP 440 version: {text!r}")
        epoch = _num(m["epoch"] or "0")
        release = tuple(_num(part) for part in m["release"].split("."))
        pre = None
        if m["pre_l"]:
            pre = (_PRE_PHASE[m["pre_l"].lower()], _num(m["pre_n"] or "0"))
        post = None
        if m["post_implicit"] is not None:
            post = _num(m["post_implicit"])
        elif m["post_l"]:
            post = _num(m["post_n"] or "0")
        dev = _num(m["dev_n"] or "0") if m["dev_l"] else None
        local = None
        if m["local"]:
            local = tuple(
                _num(seg) if seg.isdigit() else seg.lower()
                for seg in re.split(r"[-_.]", m["local"])
            )
        key = _sort_key(epoch, release, pre, post, dev, local)
        return cls(text, epoch, release, pre, post, dev, local, key)

    @property
    def is_prerelease(self) -> bool:
        return self.pre is not None or self.dev is not None

    def __str__(self) -> str:
        parts = []
        if self.epoch:
            parts.append(f"{self.epoch}!")
        parts.append(".".join(str(n) for n in self.release))
        if self.pre:
            parts.append(f"{self.pre[0]}{self.pre[1]}")
        if self.post is not None:
            parts.append(f".post{self.post}")
        if self.dev is not None:
            parts.append(f".dev{self.dev}")
        if self.local:
            parts.append("+" + ".".join(str(s) for s in self.local))
        return "".join(parts)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key == other._key

    def __hash__(self) -> int:
        return hash(self._key)

    def __lt__(self, other: "Version") -> bool:
        return self._key < other._key

    def __le__(self, other: "Version") -> bool:
        return self._key <= other._key

    def __gt__(self, other: "Version") -> bool:
        return self._key > other._key

    def __ge__(self, other: "Version") -> bool:
        return self._key >= other._key


def _sort_key(epoch, release, pre, post, dev, local) -> tuple:
    trimmed = list(release)
    while len(trimmed) > 1 and trimmed[-1] == 0:
        trimmed.pop()
    # A dev release of a final version (1.0.dev1) sorts before its pre-releases (1.0a1).
    if pre is None and post is None and dev is not None:
        pre_key: tuple = (0,)
    elif pre is not None:
        pre_key = (1, _PHASE_RANK[pre[0]], pre[1])
    else:
        pre_key = (2,)
    post_key = (0,) if post is None else (1, post)
    dev_key = (1,) if dev is None else (0, dev)
    # No local label sorts first; within labels, alphanumeric segments sort before numeric.
    local_key: tuple = ()
    if local is not None:
        local_key = tuple((1, seg, "") if isinstance(seg, int) else (0, 0, seg) for seg in local)
    return (epoch, tuple(trimmed), pre_key, post_key, dev_key, local_key)


def upgrade_kind(installed: Version, target: Version) -> str:
    """Classify the jump from `installed` to `target`: 'major', 'minor', or 'patch'.

    An epoch change or a different first release component is 'major'; a different second
    component is 'minor'; anything else (third component, post release, pre release) is
    'patch'. This is a heuristic about the size of the change, not about API stability.
    """
    if installed.epoch != target.epoch:
        return "major"
    a = installed.release + (0,) * 3
    b = target.release + (0,) * 3
    if a[0] != b[0]:
        return "major"
    if a[1] != b[1]:
        return "minor"
    return "patch"


_SEMVER = re.compile(
    r"^v?(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\.(?P<patch>0|[1-9][0-9]*)"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def semver_key(text: str) -> tuple:
    """Sort key for a SemVer 2.0 string; build metadata is ignored, as the spec says."""
    m = _SEMVER.match(text.strip()) if isinstance(text, str) else None
    if m is None:
        raise InvalidVersion(f"not a SemVer version: {text!r}")
    core = (_num(m["major"]), _num(m["minor"]), _num(m["patch"]))
    if m["pre"] is None:
        return (core, (1,))
    idents = tuple(
        (0, _num(i), "") if i.isdigit() else (1, 0, i) for i in m["pre"].split(".")
    )
    return (core, (0, idents))
