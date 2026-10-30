"""Reach: which changed functions sit on a path from an entry point to a sink.

Given the functions a change touches, the search walks the call graph backward to entry
points and forward to sinks, each breadth-first with a depth limit and a shared node budget.
A path is ``entry -> ... -> changed -> ... -> sink``. When the changed function only computes
a value (a path, a name) that its caller then hands to a sink, the sink chain may start at
the immediate caller instead (``returns`` = 1): ``App.handle_request -> extract_all ->
extract_member -> _target``, back in ``extract_member``, ``-> open(..., "w")``.

Paths are ranked shortest first, then by confidence: every hop the graph did not resolve
(a method matched only by its name on a receiver of unknown type, or a sink matched only by
a method name) halves it. Reachability is not exploitability: a path only says where to
look and which entry point the oracle must see; only the sandboxed proof decides.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

from exhibit_a.schemas.graph import (
    CodeGraph,
    EntryPoint,
    GraphNode,
    ReachPath,
    ReachReport,
    SinkHit,
    Unreached,
)
from exhibit_a.triage.diffparse import parse_diff

from .catalog import find_entries, sink_hits

MAX_DEPTH = 12
NODE_BUDGET = 50_000
MAX_PATHS = 50
MAX_ENTRY_CHAINS = 8
MAX_SINKS_PER_PIVOT = 6
#: Unresolved attribute calls are followed to same-named methods only when at most this
#: many methods carry the name; each such hop halves the confidence.
MAX_WEAK_CANDIDATES = 3
WEAK_FACTOR = 0.5

_HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_CALLABLE = ("function", "method")


# -- changed functions ------------------------------------------------------------------------

def changed_lines(diff_text: str) -> dict[str, set[int]]:
    """New-side line numbers each file's hunks touch, from a unified diff.

    Added lines count as themselves; a deletion counts as the new-side line it sits before,
    so removing a check marks the function that lost it. Deleted files are left out.
    """
    lines: dict[str, set[int]] = {}
    for change in parse_diff(diff_text).files:
        if change.status == "deleted" or change.binary or not change.paths:
            continue
        path = change.paths[-1]
        touched = lines.setdefault(path, set())
        new = 0
        for row in change.body:
            hunk = _HUNK.match(row)
            if hunk:
                new = int(hunk.group(2))
                continue
            marker = row[:1]
            if marker == "+":
                touched.add(new)
                new += 1
            elif marker == "-":
                touched.add(max(new, 1))
            elif marker == " ":
                new += 1
    return {path: rows for path, rows in lines.items() if rows}


def changed_nodes(graph: CodeGraph, lines: Mapping[str, Iterable[int]]) -> tuple[list[str], list[str]]:
    """The innermost function or method around each changed line.

    Returns ``(node ids, "file:line" of changed lines outside any function)``. A change at
    module or class level is listed but starts no search (a recall cost, see
    docs/design/code-graph.md).
    """
    by_file: dict[str, list[GraphNode]] = {}
    for node in graph.nodes:
        if node.kind in _CALLABLE:
            by_file.setdefault(node.file, []).append(node)
    files = {n.file for n in graph.nodes}
    found: set[str] = set()
    outside: list[str] = []
    for file in sorted(lines):
        candidates = by_file.get(file, [])
        for line in sorted(set(lines[file])):
            around = [n for n in candidates if n.start <= line <= n.end]
            if around:
                found.add(min(around, key=lambda n: (n.end - n.start, n.id)).id)
            elif file in files:
                outside.append(f"{file}:{line}")
    return sorted(found), outside


def functions_in(graph: CodeGraph, file: str) -> list[str]:
    """Every function and method of one file (a case names a file, not a diff)."""
    return sorted(n.id for n in graph.nodes if n.kind in _CALLABLE and n.file == file)


# -- search -------------------------------------------------------------------------------------

class _Adjacency:
    def __init__(self, graph: CodeGraph) -> None:
        self.nodes = {n.id: n for n in graph.nodes}
        by_method: dict[str, list[str]] = {}
        for node in graph.nodes:
            if node.kind == "method":
                by_method.setdefault(node.name.rsplit(".", 1)[-1], []).append(node.id)
        out: dict[str, dict[str, bool]] = {}

        def link(src: str, dst: str, weak: bool) -> None:
            edges = out.setdefault(src, {})
            edges[dst] = edges.get(dst, True) and weak  # a strong edge wins over a weak one

        for edge in graph.edges:
            if edge.src not in self.nodes:
                continue
            if edge.dst in self.nodes and edge.kind not in ("external", "unresolved"):
                if self.nodes[edge.dst].kind in _CALLABLE:
                    link(edge.src, edge.dst, False)
            elif edge.kind == "unresolved" and "." in edge.text and not edge.text.startswith("<"):
                candidates = by_method.get(edge.text.rsplit(".", 1)[1], [])
                if 0 < len(candidates) <= MAX_WEAK_CANDIDATES:
                    for dst in candidates:
                        link(edge.src, dst, True)
        self.forward = {src: sorted(dsts.items()) for src, dsts in out.items()}
        back: dict[str, list[tuple[str, bool]]] = {}
        for src, dsts in self.forward.items():
            for dst, weak in dsts:
                back.setdefault(dst, []).append((src, weak))
        self.backward = {dst: sorted(srcs) for dst, srcs in back.items()}


class _Budget:
    def __init__(self, limit: int) -> None:
        self.left = limit
        self.exhausted = False

    def spend(self) -> bool:
        if self.left <= 0:
            self.exhausted = True
            return False
        self.left -= 1
        return True


def _bfs(start: str, edges: Mapping[str, list[tuple[str, bool]]], max_depth: int,
         budget: _Budget) -> dict[str, tuple[int, int, str | None]]:
    """Layered BFS: node -> (depth, weak hops, previous node). Fewest hops, then fewest weak
    hops, then the smallest previous id: deterministic whatever the edge order."""
    best: dict[str, tuple[int, int, str | None]] = {start: (0, 0, None)}
    layer = [start]
    depth = 0
    while layer and depth < max_depth:
        depth += 1
        nxt: dict[str, tuple[int, str]] = {}
        for node in layer:
            if not budget.spend():
                return best
            weak_so_far = best[node][1]
            for other, weak in edges.get(node, []):
                if other in best:
                    continue
                cand = (weak_so_far + int(weak), node)
                if other not in nxt or cand < nxt[other]:
                    nxt[other] = cand
        for node, (weak, prev) in nxt.items():
            best[node] = (depth, weak, prev)
        layer = sorted(nxt)
    return best


def _chain(best: Mapping[str, tuple[int, int, str | None]], node: str) -> list[str]:
    out = [node]
    while True:
        prev = best[out[-1]][2]
        if prev is None:
            return out
        out.append(prev)


def find_paths(
    graph: CodeGraph,
    changed: Iterable[str],
    *,
    declared_entries: list[str] | tuple[str, ...] = (),
    entries: list[EntryPoint] | None = None,
    max_depth: int = MAX_DEPTH,
    node_budget: int = NODE_BUDGET,
    max_paths: int = MAX_PATHS,
    changed_outside: list[str] | None = None,
) -> ReachReport:
    """Paths ``entry -> ... -> changed -> ... -> sink`` for every changed function."""
    changed = sorted(set(changed))
    missing: list[str] = []
    if entries is None:
        entries, missing = find_entries(graph, declared_entries)
    by_entry = {e.node: e for e in entries}
    adjacency = _Adjacency(graph)
    hits = sink_hits(graph)
    budget = _Budget(node_budget)
    sink_cache: dict[str, list[tuple[list[str], int, SinkHit]]] = {}

    def sinks_from(pivot: str) -> list[tuple[list[str], int, SinkHit]]:
        if pivot not in sink_cache:
            best = _bfs(pivot, adjacency.forward, max_depth, budget)
            routes = []
            for node in sorted(best, key=lambda n: (best[n][0], best[n][1], n)):
                for hit in hits.get(node, []):
                    routes.append((list(reversed(_chain(best, node))), best[node][1], hit))
                if len(routes) >= MAX_SINKS_PER_PIVOT:
                    break
            sink_cache[pivot] = routes[:MAX_SINKS_PER_PIVOT]
        return sink_cache[pivot]

    paths: dict[tuple, ReachPath] = {}
    unreached: list[Unreached] = []
    for node in changed:
        if node not in adjacency.nodes:
            unreached.append(Unreached(node=node, reason="not a node of the graph"))
            continue
        back = _bfs(node, adjacency.backward, max_depth, budget)
        reached = sorted((n for n in back if n in by_entry), key=lambda n: (back[n][0], back[n][1], n))
        if not reached:
            unreached.append(Unreached(node=node, reason="no entry point reaches it"))
            continue
        found_any = False
        for entry in reached[:MAX_ENTRY_CHAINS]:
            to_changed = _chain(back, entry)  # entry ... changed
            weak_in = back[entry][1]
            pivots = [(to_changed[-1], 0)]
            if len(to_changed) >= 2:
                pivots.append((to_changed[-2], 1))
            for pivot, returns in pivots:
                for to_sink, weak_out, hit in sinks_from(pivot):
                    if returns and node in to_sink:
                        continue  # the same sink reached through the changed function itself
                    unresolved = weak_in + weak_out + int(hit.weak)
                    hops = len(to_changed) - 1 + len(to_sink) - 1 + 1
                    item = by_entry[entry]
                    path = ReachPath(
                        entry=entry, entry_kind=item.kind, oracle_entry_point=item.oracle_name,
                        changed=node, pivot=pivot, to_changed=to_changed, to_sink=to_sink,
                        sink=hit, hops=hops, returns=returns, unresolved_hops=unresolved,
                        confidence=round(WEAK_FACTOR ** unresolved, 6), vuln_class=hit.vuln_class,
                    )
                    key = (entry, node, tuple(to_changed), tuple(to_sink), hit.target, hit.line, hit.node)
                    paths.setdefault(key, path)
                    found_any = True
        if not found_any:
            unreached.append(Unreached(node=node, reason="reaches no sink"))
    ranked = sorted(paths.values(), key=_rank)
    return ReachReport(
        changed=changed,
        changed_outside_functions=list(changed_outside or []),
        entries=entries,
        undeclared_entries=missing,
        paths=ranked[:max_paths],
        unreached=unreached,
        budget_exhausted=budget.exhausted,
        max_depth=max_depth,
        node_budget=node_budget,
    )


def _rank(path: ReachPath) -> tuple:
    return (
        path.hops + path.returns, path.unresolved_hops, path.returns, not path.sink.joined_path,
        path.entry, path.changed, path.to_changed, path.to_sink, path.sink.line, path.sink.target,
    )


def render(path: ReachPath) -> str:
    """``App.handle_request -> Extractor.extract_all -> ... -> builtins.open (line 71)``."""

    def short(node: str) -> str:
        return node.split(":", 1)[-1]

    parts = [f"[{short(n)}]" if n == path.changed else short(n) for n in path.to_changed]
    if path.returns:
        parts.append(f"(returns to {short(path.pivot)})")
    parts.extend(short(n) for n in path.to_sink[1:])
    parts.append(f"{path.sink.target} (line {path.sink.line})")
    return " -> ".join(parts)


def reach_from_diff(
    graph: CodeGraph, diff_text: str, *, declared_entries: list[str] | tuple[str, ...] = (), **limits: int
) -> ReachReport:
    """Map a unified diff onto the graph and search from the functions it touches."""
    nodes, outside = changed_nodes(graph, changed_lines(diff_text))
    return find_paths(graph, nodes, declared_entries=declared_entries, changed_outside=outside, **limits)
