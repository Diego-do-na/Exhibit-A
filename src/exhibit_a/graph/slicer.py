"""Slice builder: only the source of the functions on reach paths, under a size cap.

The adversary gets this instead of the whole changed file: the functions from the entry
point through the changed function to the sink, each with its file and line numbers, and a
header naming the path. The header is built from the graph, never from model output.

``SlicePlan`` is what the loop uses with ``--slice``: the slice text for the adversary, and
the entry point the oracle judges with for each suspicion, taken from the graph path the
suspicion sits on, never from the model's own ``entry_point`` text.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from exhibit_a.schemas.graph import CodeGraph, GraphNode, ReachPath

from .reach import render

MAX_SLICE_CHARS = 16_000
MAX_SLICE_PATHS = 3
_MAX_SOURCE_BYTES = 1_000_000


@dataclass(frozen=True)
class SliceFunction:
    node: str
    file: str
    start: int
    end: int
    truncated: bool = False


@dataclass(frozen=True)
class CodeSlice:
    text: str
    functions: tuple[SliceFunction, ...]
    truncated: bool

    def to_json(self) -> dict[str, Any]:
        return {
            "chars": len(self.text),
            "truncated": self.truncated,
            "functions": [
                {"node": f.node, "file": f.file, "start": f.start, "end": f.end, "truncated": f.truncated}
                for f in self.functions
            ],
        }


def _read_lines(root: Path, rel: str) -> list[str] | None:
    """Lines of ``root/rel``, refusing symlinks, non-regular files and escapes from root."""
    base = os.path.realpath(root)
    full = os.path.realpath(os.path.join(base, rel))
    if os.path.commonpath([base, full]) != base:
        return None
    current = base
    for part in Path(rel).parts:
        current = os.path.join(current, part)
        if os.path.islink(current):
            return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(full, flags)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_SOURCE_BYTES:
            return None
        data = os.read(fd, _MAX_SOURCE_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    return data.decode("utf-8", "replace").splitlines()


def _ordered_nodes(paths: list[ReachPath]) -> tuple[list[str], list[str]]:
    """Nodes in path order, and the same nodes in the order they get the size budget."""
    order: list[str] = []
    for path in paths:
        for node in [*path.to_changed, *path.to_sink]:
            if node not in order:
                order.append(node)
    priority: list[str] = []
    for path in paths:
        for node in (path.changed, path.sink.node, path.entry, *path.to_changed, *path.to_sink):
            if node not in priority:
                priority.append(node)
    return order, priority


def build_slice(
    graph: CodeGraph,
    root: str | Path,
    paths: list[ReachPath],
    *,
    max_chars: int = MAX_SLICE_CHARS,
) -> CodeSlice:
    """The source of the functions on ``paths``, numbered, under ``max_chars``."""
    nodes = {n.id: n for n in graph.nodes}
    root = Path(root)
    header = ["CALL GRAPH SLICE (static; it may miss calls and reachability is not exploitability)"]
    for i, path in enumerate(paths, 1):
        header.append(f"PATH {i} [{path.vuln_class}]: {render(path)}")
        header.append(f"ENTRY POINT {i}: {path.oracle_entry_point}")
    head = "\n".join(header) + "\n"
    order, priority = _ordered_nodes(paths)
    # Drop functions nested inside another function already on the slice.
    spans: dict[str, GraphNode] = {}
    for node_id in order:
        node = nodes.get(node_id)
        if node is None:
            continue
        if any(o.file == node.file and o.start <= node.start and node.end <= o.end
               for o in spans.values()):
            continue
        spans = {k: v for k, v in spans.items()
                 if not (v.file == node.file and node.start <= v.start and v.end <= node.end)}
        spans[node_id] = node
    cache: dict[str, list[str] | None] = {}
    bodies: dict[str, tuple[str, SliceFunction]] = {}
    budget = max_chars - len(head)
    truncated = False
    for node_id in [n for n in priority if n in spans]:
        node = spans[node_id]
        if node.file not in cache:
            cache[node.file] = _read_lines(root, node.file)
        lines = cache[node.file]
        if lines is None:
            truncated = True
            continue
        title = f"--- {node.file}:{node.start}-{node.end} {node.name}\n"
        rows = [f"{n}: {lines[n - 1]}\n" for n in range(node.start, min(node.end, len(lines)) + 1)]
        text = title + "".join(rows)
        cut = False
        if len(text) > budget:
            cut = True
            kept = title
            for row in rows:
                if len(kept) + len(row) + 20 > budget:
                    break
                kept += row
            text = kept + "... [truncated]\n"
            if len(text) > budget:
                truncated = True
                continue
        truncated = truncated or cut
        budget -= len(text)
        bodies[node_id] = (text, SliceFunction(node_id, node.file, node.start, node.end, cut))
    kept_order = [n for n in order if n in bodies]
    text = head + "".join(bodies[n][0] for n in kept_order)
    return CodeSlice(text=text, functions=tuple(bodies[n][1] for n in kept_order), truncated=truncated)


@dataclass(frozen=True)
class SlicePlan:
    """What ``--slice`` hands the loop for one source file."""

    paths: tuple[ReachPath, ...]
    slice: CodeSlice
    spans: dict[str, tuple[str, int, int]]  # node id -> (file, start, end), for path nodes

    def path_for(self, file: str, line: int) -> ReachPath:
        """The best-ranked path through a function containing ``file:line``, else the best path.

        The suspicion's location comes from the model, so it only picks among the graph's own
        paths; whatever it says, the entry point is one the graph found.
        """
        for path in self.paths:
            for node in [*path.to_changed, *path.to_sink]:
                span = self.spans.get(node)
                if span and span[0] == file and span[1] <= line <= span[2]:
                    return path
        return self.paths[0]

    def summary(self) -> dict[str, Any]:
        return {
            "paths": [
                {"path": render(p), "entry_point": p.oracle_entry_point, "entry_kind": p.entry_kind,
                 "changed": p.changed, "vuln_class": p.vuln_class, "confidence": p.confidence}
                for p in self.paths
            ],
            "slice": self.slice.to_json(),
        }


def make_plan(
    graph: CodeGraph,
    root: str | Path,
    paths: list[ReachPath],
    *,
    max_paths: int = MAX_SLICE_PATHS,
    max_chars: int = MAX_SLICE_CHARS,
) -> SlicePlan | None:
    """A plan from the best ``max_paths`` paths, or None when there is no path."""
    chosen = list(paths[:max_paths])
    if not chosen:
        return None
    nodes = {n.id: n for n in graph.nodes}
    spans = {}
    for path in chosen:
        for node in [*path.to_changed, *path.to_sink]:
            if node in nodes:
                spans[node] = (nodes[node].file, nodes[node].start, nodes[node].end)
    return SlicePlan(tuple(chosen), build_slice(graph, root, chosen, max_chars=max_chars), spans)
