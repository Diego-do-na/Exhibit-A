"""Graph reachability of an advisory's affected symbols: entry point -> ... -> library call.

The static call graph (``exhibit_a.graph``) records every call that leaves the repository as
an ``external`` edge to a dotted name (``starlette.staticfiles.StaticFiles``,
``yaml.load``). An advisory is *reachable* when some entry point of the application reaches,
through resolved calls, a repository function that calls or references one of the
advisory's affected symbols. Three kinds of path are reported:

* ``call``: ``entry -> ... -> f``, and ``f`` calls the symbol (or a method below it);
* ``served``: the symbol is an ASGI/WSGI application (the symbol map names the method the
  framework calls, e.g. ``StaticFiles.__call__``) and repository code hands an instance of
  it to a route table or a mount call, so the framework sends requests to it;
* ``vendored``: the repository holds its own copy of the symbol (a vendored or installed
  tree) and an entry point reaches that node.

*Not reachable* means the graph found no such path, with what it did find (uses only in
test code, at import time, or in functions no entry point reaches) and what it cannot see.
*Unknown* means there was no symbol to look for. Reachability is not exploitability: only
the sandboxed proof loop can turn a path into a finding, and a path the graph misses is a
recall cost, never a false proof.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath

from ..graph.catalog import ROUTE_TABLE_CALLS, find_entries
from ..graph.reach import MAX_DEPTH, NODE_BUDGET, WEAK_FACTOR, _Adjacency, _bfs, _Budget, _chain
from ..schemas.advisory import DependencyPath, DependencyReachability, SymbolUse
from ..schemas.graph import CodeGraph, EntryPoint, GraphEdge, GraphNode
from .symbols import SymbolInfo

#: Calls that register an ASGI/WSGI application for requests: the route-table calls the
#: entry-point catalog knows, plus ``app.mount(...)`` (Starlette, FastAPI, Flask blueprints).
MOUNT_CALLS = frozenset(ROUTE_TABLE_CALLS | {"mount", "register_blueprint", "add_middleware"})
MAX_PATHS_PER_ADVISORY = 10
MAX_USES = 200
MAX_UNRESOLVED = 20
_TEST_DIRS = frozenset({"tests", "test", "testing"})

BLIND_SPOTS = (
    "dynamic dispatch: getattr, calls on values of unknown type, monkeypatching",
    "framework magic beyond route tables and mount calls (signals, plugins, dependency injection)",
    "calls made through another dependency (the graph does not read installed packages)",
    "non-Python entry points: templates, configuration files, C extensions, shell scripts",
)


def is_test_file(path: str) -> bool:
    """Whether a repository-relative path is test code (pytest naming or a tests directory)."""
    parts = PurePosixPath(path).parts
    name = parts[-1] if parts else ""
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or name == "conftest.py"
        or any(part in _TEST_DIRS for part in parts[:-1])
    )


def _short(node: str) -> str:
    return node.split(":", 1)[-1]


def _last(dotted: str) -> str:
    return dotted.rsplit(".", 1)[-1]


def match_symbol(name: str, symbols: Iterable[str]) -> str | None:
    """The affected symbol ``name`` is, or lies below (``A.B`` matches ``A.B.c``)."""
    best: str | None = None
    for symbol in symbols:
        if name == symbol or name.startswith(symbol + "."):
            if best is None or len(symbol) > len(best):
                best = symbol
    return best


@dataclass
class _Use:
    use: SymbolUse
    mount_confidence: float = 1.0  # 1.0 when the instance is built inside the mount call


def _context(node: GraphNode) -> str:
    if is_test_file(node.file):
        return "test"
    return "function" if node.kind in ("function", "method") else "module_level"


def _mounted(edge: GraphEdge, scope_edges: list[GraphEdge]) -> float:
    """1.0 when the symbol is built inside a mount/route-table call of the same scope, 0.5
    when the scope makes such a call but the instance travels through a name, else 0."""
    leaf = _last(edge.dst) + "("
    weak = 0.0
    for other in scope_edges:
        if other is edge:
            continue
        callee = other.dst if other.kind == "external" else other.text
        if not callee or _last(callee) not in MOUNT_CALLS:
            continue
        texts = [*other.args, *other.kwargs.values()]
        if any(leaf in text for text in texts):
            return 1.0
        weak = WEAK_FACTOR
    return weak


def find_uses(graph: CodeGraph, info: SymbolInfo) -> list[_Use]:
    """Every place the repository calls, references or defines an affected symbol."""
    if not info.symbols:
        return []
    nodes = {n.id: n for n in graph.nodes}
    by_src: dict[str, list[GraphEdge]] = {}
    for edge in graph.edges:
        by_src.setdefault(edge.src, []).append(edge)
    found: dict[tuple, _Use] = {}
    for edge in graph.edges:
        if edge.kind != "external" or edge.src not in nodes:
            continue
        symbol = match_symbol(edge.dst, info.symbols)
        if symbol is None:
            continue
        node = nodes[edge.src]
        mounted = 0.0
        if info.served_entry:
            if edge.ref:
                mounted = 1.0 if _last(edge.via) in MOUNT_CALLS else 0.0
            else:
                mounted = _mounted(edge, by_src.get(edge.src, []))
        use = SymbolUse(
            node=node.id, file=node.file, line=edge.line, target=edge.dst, symbol=symbol,
            edge_kind="ref" if edge.ref else "call", context=_context(node), mounted=mounted > 0,
        )
        key = (use.node, use.line, use.target, use.edge_kind)
        found.setdefault(key, _Use(use, mounted or 1.0))
    for node in graph.nodes:
        if node.kind == "module":
            continue
        symbol = match_symbol(f"{node.module}.{node.name}", info.symbols)
        if symbol is None or node.kind == "class":
            continue
        use = SymbolUse(node=node.id, file=node.file, line=node.line, target=f"{node.module}.{node.name}",
                        symbol=symbol, edge_kind="in_repo", context=_context(node))
        found.setdefault((use.node, use.line, use.target, "in_repo"), _Use(use))
    ordered = sorted(found.values(), key=lambda u: (u.use.file, u.use.line, u.use.target, u.use.node))
    return ordered[:MAX_USES]


def entries_from_tests(graph: CodeGraph) -> list[EntryPoint]:
    """Pytest test functions, used as entry points only with ``include_tests``."""
    return [
        EntryPoint(node=n.id, kind="test", oracle_name=n.name, detail="pytest test function")
        for n in graph.nodes
        if n.kind in ("function", "method") and is_test_file(n.file) and _last(n.name).startswith("test_")
    ]


def _render(nodes: list[str], use: SymbolUse, tail: str = "") -> str:
    parts = [_short(n) for n in nodes]
    parts.append(f"{use.target} ({use.file}:{use.line})")
    if tail:
        parts.append(tail)
    return " -> ".join(parts)


def dependency_reach(
    graph: CodeGraph,
    info: SymbolInfo,
    *,
    include_tests: bool = False,
    declared_entries: list[str] | tuple[str, ...] = (),
    package_imported: bool = False,
    import_sites: list[str] | None = None,
    max_depth: int = MAX_DEPTH,
    node_budget: int = NODE_BUDGET,
) -> DependencyReachability:
    """Reachability of one advisory's symbols from the application's entry points."""
    imports = list(import_sites or [])
    blind = list(BLIND_SPOTS)
    if graph.truncated:
        blind.insert(0, "the graph stopped at its file or size cap: part of the repository was not read")
    if graph.skipped:
        blind.insert(0, f"{len(graph.skipped)} file(s) could not be parsed or were skipped")
    if graph.stats.unresolved:
        blind.append(f"{graph.stats.unresolved} call(s) in this repository could not be resolved")

    def result(status: str, reason: str, uses=(), paths=(), unresolved=()) -> DependencyReachability:
        return DependencyReachability(
            status=status, reason=reason, symbols=list(info.symbols), symbol_source=info.source,
            package_imported=package_imported, import_sites=imports, uses=[u.use for u in uses],
            paths=list(paths), possible_unresolved=list(unresolved), blind_spots=blind,
        )

    if not info.symbols:
        return result("unknown", "the advisory names no affected symbol and the symbol map has no entry "
                                 "for it, so there is nothing to look for in the graph")

    leaves = {_last(s) for s in info.symbols}
    files = {n.id: n.file for n in graph.nodes}
    unresolved = sorted({
        f"{files.get(e.src, e.src.split(':', 1)[0])}:{e.line} {e.text}"
        for e in graph.edges
        if e.kind == "unresolved" and e.text and _last(e.text.split("(", 1)[0]) in leaves
    })[:MAX_UNRESOLVED]

    entries, _missing = find_entries(graph, declared_entries)
    if include_tests:
        known = {e.node for e in entries}
        entries = entries + [e for e in entries_from_tests(graph) if e.node not in known]
    by_entry = {e.node: e for e in entries}
    adjacency = _Adjacency(graph)
    budget = _Budget(node_budget)
    uses = find_uses(graph, info)
    paths: list[DependencyPath] = []
    for item in uses:
        use = item.use
        if use.context == "test" and not include_tests:
            continue
        if use.mounted and info.served_entry:
            path = DependencyPath(
                kind="served", entry=use.node, entry_kind="mounted_app", oracle_entry_point=info.served_entry,
                nodes=[use.node], use=use, hops=1, unresolved_hops=0 if item.mount_confidence == 1.0 else 1,
                confidence=item.mount_confidence,
                rendered=_render([use.node], use, f"[framework dispatch] {info.served_entry}"),
            )
            paths.append(path)
            continue
        if use.context == "module_level":
            continue  # runs at import time, not on a request; reported as an unreached use
        back = _bfs(use.node, adjacency.backward, max_depth, budget)
        reached = sorted((n for n in back if n in by_entry), key=lambda n: (back[n][0], back[n][1], n))
        for entry in reached[:3]:
            chain = _chain(back, entry)  # entry ... use.node
            weak = back[entry][1]
            point = by_entry[entry]
            paths.append(DependencyPath(
                kind="vendored" if use.edge_kind == "in_repo" else "call",
                entry=entry, entry_kind=point.kind, oracle_entry_point=point.oracle_name,
                nodes=chain, use=use, hops=len(chain), unresolved_hops=weak,
                confidence=round(WEAK_FACTOR ** weak, 6),
                rendered=_render(chain, use) if use.edge_kind != "in_repo" else
                " -> ".join(_short(n) for n in chain) + f" ({use.file}:{use.line})",
            ))
    paths.sort(key=lambda p: (p.unresolved_hops, p.hops, p.kind != "call", p.entry, p.use.file, p.use.line))
    paths = paths[:MAX_PATHS_PER_ADVISORY]
    if paths:
        best = paths[0]
        return result("reachable", f"{len(paths)} path(s); best: {best.rendered}", uses, paths, unresolved)
    if budget.exhausted:
        blind.insert(0, "the search hit its node budget before finishing")
    if not uses:
        if package_imported:
            reason = (f"the package is imported ({', '.join(imports[:3])}) but no affected symbol "
                      f"({', '.join(info.symbols)}) is called or referenced by code the graph read")
        else:
            reason = "no Python file the graph read imports the package or uses an affected symbol"
        if unresolved:
            reason += f"; {len(unresolved)} unresolved call(s) share a symbol's name (see possible_unresolved)"
        return result("not_reachable", reason, uses, (), unresolved)
    kinds = {u.use.context for u in uses}
    where = ", ".join(f"{u.use.file}:{u.use.line}" for u in uses[:3])
    if kinds == {"test"} and not include_tests:
        reason = f"affected symbols are used only in test code ({where}); test code is not an entry point"
    elif not entries:
        reason = f"affected symbols are used ({where}) but the graph found no entry point in this repository"
    elif kinds <= {"module_level", "test"}:
        reason = f"affected symbols are used only at import time ({where}), never on a path from an entry point"
    else:
        reason = f"affected symbols are used ({where}) but no entry point reaches those functions"
    return result("not_reachable", reason, uses, (), unresolved)

