"""Bounded, non-executing parser for unified diffs (git or plain).

The diff is untrusted text. It is only ever split into lines and matched with
anchored regular expressions; it is never interpolated into a shell, passed to
``eval``/``exec`` or applied to a working tree. Work is bounded by
``MAX_DIFF_CHARS`` and ``MAX_FILES`` (the caller enforces both and reports the
overflow), and a ``diff --git`` line always starts a new file entry even in the
middle of a hunk, so a miscounted hunk cannot hide a later file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_DIFF_CHARS = 1_000_000
MAX_FILES = 200
MAX_PATH_CHARS = 1024

_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "a": "\a", "b": "\b", "f": "\f", "v": "\v"}


@dataclass
class FileChange:
    """One file entry of a diff. ``paths`` lists every path spelling seen."""

    paths: list[str] = field(default_factory=list)
    status: str = "modified"  # modified | added | deleted | renamed | copied
    binary: bool = False
    old_mode: str | None = None
    new_mode: str | None = None
    body: list[str] = field(default_factory=list)

    def add_path(self, path: str | None) -> None:
        if path and path not in self.paths:
            self.paths.append(path)


@dataclass
class ParsedDiff:
    files: list[FileChange] = field(default_factory=list)
    truncated: bool = False  # more than MAX_FILES entries were present
    has_nul: bool = False


def _unquote(token: str) -> str:
    """Decode a git C-style quoted path (without the surrounding quotes)."""
    out = bytearray()
    i = 0
    while i < len(token):
        ch = token[i]
        if ch != "\\" or i + 1 >= len(token):
            out += ch.encode("utf-8", "replace")
            i += 1
            continue
        nxt = token[i + 1]
        if nxt in _ESCAPES:
            out += _ESCAPES[nxt].encode()
            i += 2
        elif nxt in "01234567":
            digits = token[i + 1 : i + 4]
            j = 0
            while j < len(digits) and digits[j] in "01234567":
                j += 1
            out.append(int(digits[:j], 8) & 0xFF)
            i += 1 + j
        else:
            out += nxt.encode("utf-8", "replace")
            i += 2
    return out.decode("utf-8", "replace")


def _take_token(text: str) -> tuple[str, str]:
    """Split one possibly quoted path off the front of ``text``."""
    if text.startswith('"'):
        i = 1
        while i < len(text) and text[i] != '"':
            i += 2 if text[i] == "\\" else 1
        return _unquote(text[1:i]), text[i + 1 :].lstrip(" ")
    head, _, rest = text.partition(" ")
    return head, rest


def _whole_path(text: str) -> str:
    """A path that fills the rest of the line (rename/copy headers)."""
    return _take_token(text)[0] if text.startswith('"') else text


def _strip_prefix(path: str, prefixes: tuple[str, ...] = ("a/", "b/")) -> str:
    for prefix in prefixes:
        if path.startswith(prefix):
            return path[len(prefix) :]
    return path


def _header_paths(rest: str) -> list[str]:
    """Best-effort paths from ``diff --git a/X b/Y`` (ambiguous with spaces)."""
    if rest.startswith('"'):
        first, tail = _take_token(rest)
        second, _ = _take_token(tail)
        return [_strip_prefix(first), _strip_prefix(second)]
    length = (len(rest) - 5) // 2
    if length > 0 and rest.startswith("a/") and rest[2 : 2 + length] == rest[5 + length :]:
        return [rest[2 : 2 + length]]
    cut = rest.rfind(" b/")
    if cut > 0:
        return [_strip_prefix(rest[:cut]), rest[cut + 1 :][2:]]
    return [rest]


def _file_path(text: str) -> str | None:
    """Path from a ``--- `` / ``+++ `` line (None for /dev/null)."""
    token, _ = _take_token(text.split("\t", 1)[0])
    if token == "/dev/null":
        return None
    return _strip_prefix(token)


def parse_diff(text: str) -> ParsedDiff:
    """Parse ``text`` (already size-capped by the caller) into file entries."""
    result = ParsedDiff(has_nul="\x00" in text)
    current: FileChange | None = None
    git_mode = False
    old_left = new_left = 0
    in_binary = False

    def start() -> FileChange:
        change = FileChange()
        if len(result.files) >= MAX_FILES:
            result.truncated = True
        else:
            result.files.append(change)
        return change

    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        if line.startswith("diff --git "):
            current, git_mode, in_binary, old_left, new_left = start(), True, False, 0, 0
            for path in _header_paths(line[len("diff --git ") :]):
                current.add_path(path)
            continue
        if old_left > 0 or new_left > 0:
            marker = line[:1]
            if marker == " ":
                old_left -= 1
                new_left -= 1
            elif marker == "-":
                old_left -= 1
            elif marker == "+":
                new_left -= 1
            elif marker != "\\":
                old_left = new_left = 0  # malformed counts: fall through to headers
            if marker in (" ", "-", "+", "\\"):
                if current is not None:
                    current.body.append(line)
                continue
        if in_binary:
            continue
        hunk = _HUNK.match(line)
        if hunk and current is not None:
            old_left = int(hunk.group(1) if hunk.group(1) is not None else 1)
            new_left = int(hunk.group(2) if hunk.group(2) is not None else 1)
            current.body.append(line)
            continue
        if not git_mode and line.startswith("--- ") and (current is None or current.body or current.paths):
            current = start()
        if current is None:
            continue
        if line.startswith("--- "):
            current.add_path(_file_path(line[4:]))
            if line[4:].startswith("/dev/null"):
                current.status = "added"
        elif line.startswith("+++ "):
            current.add_path(_file_path(line[4:]))
            if line[4:].startswith("/dev/null"):
                current.status = "deleted"
        elif line.startswith("rename from "):
            current.status = "renamed"
            current.add_path(_whole_path(line[12:]))
        elif line.startswith("rename to "):
            current.status = "renamed"
            current.add_path(_whole_path(line[10:]))
        elif line.startswith("copy from ") or line.startswith("copy to "):
            current.status = "copied"
            current.add_path(_whole_path(line.split(" ", 2)[2]))
        elif line.startswith("new file mode "):
            current.status, current.new_mode = "added", line[14:].strip()
        elif line.startswith("deleted file mode "):
            current.status, current.old_mode = "deleted", line[18:].strip()
        elif line.startswith("old mode "):
            current.old_mode = line[9:].strip()
        elif line.startswith("new mode "):
            current.new_mode = line[9:].strip()
        elif line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            current.binary = True
            in_binary = line.startswith("GIT binary patch")
            if line.startswith("Binary files "):
                for token in re.findall(r"(?:^| )(?:a|b)/(\S+)", line):
                    current.add_path(token)
    return result
