"""Sandboxed JavaScript/TypeScript graph and reachability adapter."""
from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
import subprocess

from exhibit_a.schemas.graph import CodeGraph, EntryPoint, ReachPath, ReachReport, SinkHit, Unreached
from exhibit_a.sandbox.image_node import build_node_image
from .reach import changed_lines, changed_nodes
from .slicer import make_plan

from .js_catalog import find_entries as _find_entries
from .js_catalog import sink_hits

BUILDER = Path(__file__).with_name("js").joinpath("graph_builder.js")
MAX_OUTPUT_BYTES = 10 * 1024 * 1024
TYPESCRIPT_PACKAGE = "typescript@5.7.2"


_JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
_JS_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "dist", "build", "__pycache__"}
_JS_MAX_FILES = 5000
_JS_MAX_TOTAL_BYTES = 50 * 1024 * 1024


def _collect_sources(root: Path) -> list[dict[str, str]]:
    """Collect candidate sources for the manifest the container parses.

    The container never sees the host filesystem: sources travel on stdin and
    the builder re-applies its own caps, so this only mirrors the walk filters
    (extensions, hidden names, vendored dirs, symlinks) with the same bounds.
    """
    collected: list[dict[str, str]] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            name for name in dirnames
            if not name.startswith(".") and name not in _JS_SKIP_DIRS
            and not os.path.islink(os.path.join(dirpath, name))
        )
        for name in sorted(filenames):
            if len(collected) >= _JS_MAX_FILES or total >= _JS_MAX_TOTAL_BYTES:
                return collected
            if not name.startswith(".") and os.path.splitext(name)[1] in _JS_EXTENSIONS:
                full = os.path.join(dirpath, name)
                if os.path.islink(full):
                    continue
                try:
                    text = Path(full).read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                total += len(text.encode("utf-8"))
                collected.append({
                    "rel": os.path.relpath(full, root).replace(os.sep, "/"),
                    "source": text,
                })
    return collected


def _validate(raw: object) -> CodeGraph:
    if not isinstance(raw, dict) or raw.get("schema_version") != "1":
        raise ValueError("invalid JavaScript graph schema")
    entry_points = raw.pop("entry_points", [])
    if not isinstance(entry_points, list) or len(entry_points) > 10000:
        raise ValueError("invalid JavaScript entry points")
    if len(json.dumps(raw, separators=(",", ":"))) > MAX_OUTPUT_BYTES:
        raise ValueError("JavaScript graph output is oversized")
    graph = CodeGraph.model_validate(raw)
    # Pydantic's strict contract intentionally has no language-specific extension fields.
    object.__setattr__(graph, "_js_entry_points", tuple(entry_points))
    return graph


def build_js_graph(root: str | Path, *, image: str | None = None, timeout: float = 120.0) -> CodeGraph:
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError(f"repository is not a directory: {root}")
    tag = image or build_node_image([TYPESCRIPT_PACKAGE])
    # No bind mount: the sources travel to the container on stdin as a JSON
    # manifest, so no file-sharing layer or daemon userns mapping can hide
    # them from the builder. The builder re-applies its own caps and never
    # executes the sources, it only parses them.
    with open(BUILDER, encoding="utf-8") as source:
        builder = source.read()
    manifest = json.dumps({"files": _collect_sources(root)})
    command = [
        "docker", "run", "--rm", "-i", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,size=64m,mode=1777", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        tag, "node", "-e", builder, "--", "--from-stdin",
    ]
    proc = subprocess.run(command, input=manifest.encode("utf-8"), capture_output=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"JavaScript graph builder failed: {proc.stderr.decode(errors='replace')[-2000:]}")
    if len(proc.stdout) > MAX_OUTPUT_BYTES:
        raise ValueError("JavaScript graph output is oversized")
    try:
        raw = json.loads(proc.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed JavaScript graph output") from exc
    graph = _validate(raw)
    if not graph.files:
        sources = [
            p for p in root.rglob("*")
            if p.is_file() and not p.is_symlink()
            and p.suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
            and "node_modules" not in p.parts and not p.name.startswith(".")
        ]
        if sources:
            detail = f" (skipped={list(graph.skipped)!r})" if graph.skipped else ""
            raise ValueError(
                "JavaScript graph builder returned no files for a tree "
                f"with {len(sources)} source file(s); refusing an empty graph"
                + detail
            )
    return graph


build_graph = build_js_graph


def find_entries(graph: CodeGraph, declared: list[str] | tuple[str, ...] = ()) -> tuple[list[EntryPoint], list[str]]:
    return _find_entries(graph, declared)


def functions_in(graph: CodeGraph, file: str) -> list[str]:
    return sorted(node.id for node in graph.nodes if node.kind in ("function", "method") and node.file == file)


def render(path: ReachPath) -> str:
    short = lambda node: node.split(":", 1)[-1]
    parts = [short(node) for node in path.to_changed]
    parts.extend(short(node) for node in path.to_sink[1:])
    parts.append(f"{path.sink.target} (line {path.sink.line})")
    return " -> ".join(parts)


def reach_from_diff(graph: CodeGraph, diff_text: str, *,
                    declared_entries: list[str] | tuple[str, ...] = (), **limits: int) -> ReachReport:
    changed, outside = changed_nodes(graph, changed_lines(diff_text))
    report = find_paths(graph, changed, declared_entries=declared_entries, **limits)
    return report.model_copy(update={"changed_outside_functions": outside})


def find_paths(graph: CodeGraph, changed: list[str] | tuple[str, ...], *,
               declared_entries: list[str] | tuple[str, ...] = (), max_depth: int = 12,
               max_paths: int = 50, **_: object) -> ReachReport:
    entries, missing = find_entries(graph, declared_entries)
    entry_by_node = {entry.node: entry for entry in entries}
    nodes = {node.id: node for node in graph.nodes}
    forward: dict[str, list[str]] = {}
    backward: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.dst in nodes and nodes[edge.dst].kind in ("function", "method"):
            forward.setdefault(edge.src, []).append(edge.dst)
            backward.setdefault(edge.dst, []).append(edge.src)
    hits = sink_hits(graph)
    paths, unreached = [], []
    for changed_id in sorted(set(changed)):
        if changed_id not in nodes:
            unreached.append(Unreached(node=changed_id, reason="not a node of the graph")); continue
        ancestors = _bfs(backward, changed_id, max_depth)
        reached = [node for node in ancestors if node in entry_by_node]
        if not reached:
            unreached.append(Unreached(node=changed_id, reason="no entry point reaches it")); continue
        found = False
        for entry_node in reached:
            to_changed = list(reversed(_chain(ancestors, entry_node)))
            descendants = _bfs(forward, changed_id, max_depth)
            for sink_node, (depth, prev) in descendants.items():
                for hit in hits.get(sink_node, []):
                    to_sink = _chain(descendants, sink_node)
                    paths.append(ReachPath(
                        entry=entry_node, entry_kind=entry_by_node[entry_node].kind,
                        oracle_entry_point=entry_by_node[entry_node].oracle_name, changed=changed_id,
                        pivot=changed_id, to_changed=to_changed, to_sink=to_sink, sink=hit,
                        hops=len(to_changed) + len(to_sink), returns=0, unresolved_hops=int(hit.weak),
                        confidence=0.5 if hit.weak else 1.0, vuln_class=hit.vuln_class,
                    ))
                    found = True
        if not found:
            unreached.append(Unreached(node=changed_id, reason="reaches no sink"))
    paths.sort(key=lambda p: (p.hops, p.unresolved_hops, p.entry, p.changed, p.sink.line))
    return ReachReport(entries=entries, undeclared_entries=missing, changed=sorted(set(changed)),
                       paths=paths[:max_paths], unreached=unreached, max_depth=max_depth)


def _bfs(adjacency: dict[str, list[str]], start: str, depth: int) -> dict[str, tuple[int, str | None]]:
    result = {start: (0, None)}
    queue = deque([start])
    while queue:
        current = queue.popleft()
        if result[current][0] >= depth: continue
        for other in sorted(adjacency.get(current, [])):
            if other not in result:
                result[other] = (result[current][0] + 1, current)
                queue.append(other)
    return result


def _chain(found: dict[str, tuple[int, str | None]], target: str) -> list[str]:
    result = [target]
    while found[result[-1]][1] is not None:
        result.append(found[result[-1]][1])  # type: ignore[arg-type]
    return list(reversed(result))
