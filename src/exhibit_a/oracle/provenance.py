"""Authenticated provenance: the staged-app manifest and the host-side frame check.

Before an exploit runs, the orchestrator hashes every entry of the staged application tree
(``app_manifest``) and hands the result to the oracle plugin on stdin, after the key. The
plugin admits a frame as application code only if its file is in the manifest, still has the
manifest digest, and its code object matches the staged source (see ``plugin._Admission``).

On the host, two things happen after the run:

* the tree is hashed again and compared (``diff_manifests``); any added, removed or modified
  entry is a tamper condition and rules out a proof (reason code ``app_tree_changed``);
* every frame the plugin admitted is checked again against a copy of the staged source that
  the test could not reach (``AppTree.check``): manifest entry, digest, and a function with
  the frame's qualname starting at the frame's first line, read with ``ast``.

See docs/oracle-provenance.md for the threat model and what this does not stop.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Protocol

from exhibit_a.oracle.plugin import code_keys

# Bounds on what is hashed; a tree beyond them cannot be verified, so the run cannot prove.
MAX_ENTRIES = 200_000
MAX_BYTES = 4 * 1024 * 1024 * 1024
_CHUNK = 1 << 20


class ManifestError(OSError):
    """The application tree could not be hashed (unreadable entry, or over the bounds)."""


def staging_exclude(rel_test: str) -> frozenset[str]:
    """Entries of the staged tree that belong to the test, not the app.

    The test's directory (it holds the exploit and its conftest), or, for a test at the root
    of the tree, the test file and a root ``conftest.py``.
    """
    parent = PurePosixPath(rel_test).parent
    if str(parent) in ("", "."):
        return frozenset({str(PurePosixPath(rel_test)), "conftest.py"})
    return frozenset({str(parent)})


def _sha256_file(path: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        while chunk := os.read(fd, _CHUNK):
            digest.update(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest(), size


def app_manifest(root: str | Path, exclude: Collection[str] = ()) -> dict[str, str]:
    """``{relative POSIX path: digest}`` for every entry under ``root``, symlinks not followed.

    A regular file maps to its sha256 hex digest, a directory to ``"dir"``, a symlink to
    ``"symlink:<target>"`` and anything else to ``"special"``. Entries in ``exclude`` (relative
    paths) are skipped with everything below them. Raises ``ManifestError``.
    """
    root = os.fspath(root)
    excluded = {str(PurePosixPath(e)) for e in exclude}
    out: dict[str, str] = {}
    total = 0
    todo = [("", root)]
    try:
        while todo:
            rel_dir, directory = todo.pop()
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
            for entry in entries:
                rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
                if rel in excluded:
                    continue
                if len(out) >= MAX_ENTRIES:
                    raise ManifestError(f"application tree has more than {MAX_ENTRIES} entries")
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISLNK(mode):
                    out[rel] = "symlink:" + os.readlink(entry.path)
                elif stat.S_ISDIR(mode):
                    out[rel] = "dir"
                    todo.append((rel, entry.path))
                elif stat.S_ISREG(mode):
                    out[rel], size = _sha256_file(entry.path)
                    total += size
                    if total > MAX_BYTES:
                        raise ManifestError(f"application tree is larger than {MAX_BYTES} bytes")
                else:
                    out[rel] = "special"
    except ManifestError:
        raise
    except OSError as exc:
        raise ManifestError(f"cannot hash the application tree: {exc}") from exc
    return out


def diff_manifests(before: Mapping[str, str], after: Mapping[str, str]) -> list[str]:
    """``added: p``, ``removed: p`` and ``modified: p`` entries, sorted by path."""
    changes = []
    for rel in sorted(set(before) | set(after)):
        if rel not in before:
            changes.append(f"added: {rel}")
        elif rel not in after:
            changes.append(f"removed: {rel}")
        elif before[rel] != after[rel]:
            changes.append(f"modified: {rel}")
    return changes


def tree_changes(root: str | Path, before: Mapping[str, str], exclude: Collection[str] = ()) -> list[str]:
    """What changed under ``root`` since ``before``; an unhashable tree is itself a change."""
    try:
        return diff_manifests(before, app_manifest(root, exclude))
    except ManifestError as exc:
        return [f"unverifiable: {exc}"]


class FrameLike(Protocol):
    file: str
    qualname: str
    line: int | None
    admitted: bool | None
    admission: str | None


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


@dataclass
class AppTree:
    """The staged application, for the host-side frame check.

    ``root`` is the app root as the test process saw it (the prefix of frame files, e.g.
    ``/workspace`` in the sandbox), ``source`` a host directory holding the staged content the
    test could not modify (or the app root itself on the host path, checked by digest), and
    ``manifest`` what was hashed before the run.
    """

    root: str
    source: Path
    manifest: Mapping[str, str]
    _keys: dict[str, frozenset | str] = field(default_factory=dict, repr=False)

    def relative(self, file: str) -> str | None:
        try:
            rel = PurePosixPath(file).relative_to(PurePosixPath(self.root))
        except ValueError:
            return None
        return None if str(rel) in ("", ".") else str(rel)

    def _source_keys(self, rel: str, digest: str) -> frozenset | str:
        if rel not in self._keys:
            try:
                data = (self.source / rel).read_bytes()
            except OSError:
                self._keys[rel] = "staged source unreadable on the host"
                return self._keys[rel]
            if hashlib.sha256(data).hexdigest() != digest:
                self._keys[rel] = "staged source on the host does not match the manifest"
            else:
                try:
                    self._keys[rel] = code_keys(data)
                except (SyntaxError, ValueError, RecursionError, MemoryError):
                    self._keys[rel] = "the staged file is not Python source"
        return self._keys[rel]

    def check(self, frame: FrameLike) -> str | None:
        """Why ``frame`` is not staged application code, or None if it is.

        The plugin's admission is required (only it can compare code objects); the host then
        re-checks the manifest entry and the ``ast`` qualname/line on its own copy.
        """
        if frame.admitted is not True:
            return frame.admission or "not admitted by the oracle plugin (no manifest reached it)"
        rel = self.relative(frame.file)
        digest = self.manifest.get(rel) if rel is not None else None
        if digest is None or not _is_digest(digest):
            return "file not in the staged app manifest"
        keys = self._source_keys(rel, digest)
        if isinstance(keys, str):
            return keys
        if frame.line is None or (frame.qualname, frame.line) not in keys:
            return f"staged source has no '{frame.qualname}' starting at line {frame.line}"
        return None
