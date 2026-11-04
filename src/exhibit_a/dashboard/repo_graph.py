"""Source-backed code graph for GET /api/graph, built like ``scan --graph``.

The dashboard never ships a bundled tree. When the chosen --source matches a
local checkout, this module runs the same ``build_graph`` constructor the CLI
uses and caches the aggregate by commit. GitHub sources without a matching
checkout fall back to ``graph-summary.json`` from a run artifact. Anything
else is an empty state that names ``exhibit-a scan --graph``.

Exhibit-A packages are grouped into Proof-core / Analysis / Surfaces. Every
other repository is grouped by its first-level folder. The tree is parsed
with ``ast`` only, never imported or run.
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from ..graph import build_graph, find_entries, sink_hits
from .sources import GitHubSource, LocalRunsSource, RunSource, SourceError

COMMAND = "exhibit-a scan --graph"
MAX_PACKAGES = 80
MAX_MODULES = 400
MAX_EDGES = 800
MAX_FUNCTIONS_PER_MODULE = 40
MAX_HOTSPOTS = 8
CACHE_SIZE = 8

#: Exhibit-A engine layers. Applied only when the checkout is this project.
_CORE = frozenset({"oracle", "sandbox", "loop", "models", "ledger", "schemas"})
_ANALYSIS = frozenset({
    "graph", "advisory", "findings", "triage", "audit", "scan", "attestation",
})
_SURFACE = frozenset({"cli", "dashboard", "live", "report", "ci"})
_LAYER_META = {
    "core": ("Proof-core", "#0f2557", "#ffffff",
             "oracle, sandbox, loop, models, ledger and schemas"),
    "analysis": ("Analysis", "#6a8fd8", "#0d1b3e",
                 "call graph, advisories, findings, triage, audit, attestation and scan"),
    "surface": ("Surfaces", "#b7834f", "#ffffff",
                "CLI, dashboard, reports, live view and the GitHub Action gate"),
}
_LAYER_PALETTE = (
    "#0f2557", "#6a8fd8", "#b7834f", "#2c4fc4", "#4b3fa0", "#4a5873", "#9aa3e0",
)
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
_NWO_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$"
)

_cache: dict[str, dict[str, Any]] = {}
_cache_lock = threading.Lock()
_cache_order: list[str] = []


def _empty(*, reason: str, summary: dict[str, Any] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "available": False,
        "from": "",
        "commit": "",
        "reason": reason,
        "command": COMMAND,
        "packages": [],
        "modules": [],
        "module_edges": [],
        "package_edges": [],
        "functions": {},
        "uses": [],
        "layers": [],
        "hotspots": {},
        "stats": {},
        "entries": [],
        "sinks": [],
        "paths": [],
        "source_file": "",
    }
    if summary:
        body.update(_from_summary(summary))
    return body


def _from_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """Compact artifact summary: counts and paths, never another project's tree."""
    stats = summary.get("stats") or {}
    entries = list(summary.get("entries") or [])
    paths = list(summary.get("paths") or [])
    return {
        "available": True,
        "from": "graph-summary.json",
        "reason": summary.get("reason") or (
            "no local checkout; showing graph-summary.json from the run artifact"
        ),
        "command": COMMAND,
        "stats": {
            "packages": 0,
            "modules": int(stats.get("files") or 0),
            "imports": int(stats.get("edges") or 0),
            "lines": None,
            "functions": int(stats.get("nodes") or 0),
        },
        "entries": entries[:60],
        "sinks": [],
        "paths": paths[:60],
        "source_file": str(summary.get("source_file") or "")[:300],
        "effect": str(summary.get("effect") or "")[:64],
        "status": str(summary.get("status") or "")[:64],
    }


def _looks_like_python_tree(root: Path) -> bool:
    if not root.is_dir():
        return False
    if (root / "src").is_dir() or (root / "pyproject.toml").is_file() or (root / "setup.py").is_file():
        return True
    try:
        with os.scandir(root) as entries:
            for item in entries:
                if item.name.endswith(".py") and item.is_file(follow_symlinks=False):
                    return True
    except OSError:
        return False
    return False


def _github_nwo(cwd: Path) -> str:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        done = subprocess.run(
            ["git", "remote", "-v"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=5,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if done.returncode != 0:
        return ""
    urls: dict[str, str] = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        if parts[0] not in urls:
            urls[parts[0]] = parts[1]
    for name in ("origin", *tuple(urls)):
        nwo = _parse_nwo(urls.get(name, ""))
        if nwo:
            return nwo
    return ""


def _parse_nwo(url: str) -> str:
    raw = url.strip()
    if raw.endswith(".git"):
        raw = raw[: -len(".git")]
    raw = raw.rstrip("/")
    prefixes = (
        "https://github.com/", "https://www.github.com/",
        "http://github.com/", "http://www.github.com/",
        "git@github.com:", "ssh://git@github.com/", "git://github.com/",
    )
    lower = raw.lower()
    rest = None
    for prefix in prefixes:
        if lower.startswith(prefix):
            rest = raw[len(prefix):]
            break
    if rest is None:
        return ""
    parts = rest.split("/")
    if len(parts) != 2:
        return ""
    nwo = f"{parts[0]}/{parts[1]}"
    return nwo if _NWO_RE.match(nwo) else ""


def git_head(root: Path) -> str:
    """Commit SHA of ``root``, or empty when it is not a git checkout."""
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        done = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if done.returncode != 0:
        return ""
    sha = done.stdout.strip()
    return sha if _SHA_RE.match(sha) else ""


def matching_checkout(source: RunSource, cwd: Path) -> Path | None:
    """Return cwd only when it is the repository of this --source."""
    try:
        here = cwd.resolve()
    except OSError:
        return None
    if not here.is_dir():
        return None
    repo = getattr(source, "repo", "") or ""
    if repo:
        nwo = _github_nwo(here)
        if nwo.lower() == str(repo).lower():
            return here
        return None
    root = getattr(source, "root", None)
    if root is None:
        return None
    try:
        runs = Path(root).resolve()
    except OSError:
        return None
    if here != runs and here != runs.parent:
        return None
    candidate = runs.parent if runs.name == "runs" else here
    if _looks_like_python_tree(candidate):
        return candidate
    if _looks_like_python_tree(here):
        return here
    return None


def _is_exhibit_a(root: Path) -> bool:
    return (root / "src" / "exhibit_a").is_dir()


def _package_of(file: str, *, exhibit_a: bool) -> str:
    parts = [p for p in file.replace("\\", "/").split("/") if p]
    if not parts:
        return "_"
    if exhibit_a and len(parts) >= 3 and parts[0] == "src" and parts[1] == "exhibit_a":
        name = parts[2]
        return name[:-3] if name.endswith(".py") else name
    name = parts[0]
    return name[:-3] if name.endswith(".py") else name


def _layer_of(package: str, *, exhibit_a: bool) -> str:
    if not exhibit_a:
        return package
    if package in _CORE:
        return "core"
    if package in _ANALYSIS:
        return "analysis"
    return "surface"


def _layer_rows(packages: list[tuple[str, int, str]], *, exhibit_a: bool) -> list[dict[str, Any]]:
    lines: dict[str, int] = {}
    pkgs: dict[str, list[str]] = defaultdict(list)
    for name, loc, layer in packages:
        lines[layer] = lines.get(layer, 0) + loc
        pkgs[layer].append(name)
    rows = []
    order = ("core", "analysis", "surface") if exhibit_a else tuple(
        sorted(lines, key=lambda k: (-lines[k], k))
    )
    for index, layer_id in enumerate(order):
        if layer_id not in lines:
            continue
        if exhibit_a and layer_id in _LAYER_META:
            title, color, fg, detail = _LAYER_META[layer_id]
        else:
            title = layer_id
            color = _LAYER_PALETTE[index % len(_LAYER_PALETTE)]
            fg = "#ffffff"
            detail = ", ".join(sorted(pkgs[layer_id])[:8])
        rows.append({
            "id": layer_id, "name": title, "lines": lines[layer_id],
            "color": color, "fg": fg, "detail": detail,
        })
    return rows


def _aggregate(graph: Any, *, exhibit_a: bool, commit: str) -> dict[str, Any]:
    loc_by_mod: dict[str, int] = {}
    pkg_of: dict[str, str] = {}
    file_of: dict[str, str] = {}
    functions: dict[str, list[list[Any]]] = defaultdict(list)
    for node in graph.nodes:
        pkg = _package_of(node.file, exhibit_a=exhibit_a)
        if node.kind == "module":
            loc = max(1, int(node.end) - int(node.start) + 1)
            key = node.module or node.file
            loc_by_mod[key] = loc
            pkg_of[key] = pkg
            file_of[key] = node.file
        elif node.kind in ("function", "method", "class"):
            mod = node.module or node.file
            if len(functions[mod]) >= MAX_FUNCTIONS_PER_MODULE:
                continue
            kind = "c" if node.kind == "class" else "f"
            span = max(1, int(node.end) - int(node.start) + 1)
            functions[mod].append([node.name.split(".")[-1][:80], kind, span])
            pkg_of.setdefault(mod, pkg)
            file_of.setdefault(mod, node.file)
            loc_by_mod.setdefault(mod, span)

    modules = sorted(
        ([mod, loc_by_mod[mod], pkg_of.get(mod, "_")] for mod in loc_by_mod),
        key=lambda row: (-row[1], row[0]),
    )[:MAX_MODULES]
    keep = {row[0] for row in modules}

    pkg_loc: dict[str, int] = {}
    pkg_layer: dict[str, str] = {}
    for mod, loc, pkg in modules:
        pkg_loc[pkg] = pkg_loc.get(pkg, 0) + loc
        pkg_layer[pkg] = _layer_of(pkg, exhibit_a=exhibit_a)
    packages = sorted(
        ([name, pkg_loc[name], pkg_layer[name]] for name in pkg_loc),
        key=lambda row: (-row[1], row[0]),
    )[:MAX_PACKAGES]
    keep_pkg = {row[0] for row in packages}

    id_to_mod: dict[str, str] = {}
    for node in graph.nodes:
        if node.kind == "module":
            id_to_mod[node.id] = node.module or node.file
        elif node.kind in ("function", "method", "class"):
            id_to_mod[node.id] = node.module or node.file

    incoming: Counter[str] = Counter()
    outgoing: Counter[str] = Counter()
    module_edge_w: dict[tuple[str, str], int] = defaultdict(int)
    package_edge_w: dict[tuple[str, str], int] = defaultdict(int)
    uses: list[list[str]] = []
    for edge in graph.edges:
        src_mod = id_to_mod.get(edge.src)
        dst_mod = id_to_mod.get(edge.dst)
        if not src_mod or src_mod not in keep:
            continue
        outgoing[src_mod] += 1
        if dst_mod and dst_mod in keep:
            incoming[dst_mod] += 1
            if src_mod != dst_mod:
                module_edge_w[(src_mod, dst_mod)] += 1
                sp, dp = pkg_of.get(src_mod, ""), pkg_of.get(dst_mod, "")
                if sp in keep_pkg and dp in keep_pkg and sp != dp:
                    package_edge_w[(sp, dp)] += 1
            name = edge.text or (edge.dst.split(":")[-1] if edge.dst else "")
            if name and len(uses) < MAX_EDGES:
                uses.append([src_mod, dst_mod or src_mod, name.split(".")[-1][:80]])

    module_edges = [[a, b] for (a, b), _ in sorted(
        module_edge_w.items(), key=lambda kv: (-kv[1], kv[0])
    )[:MAX_EDGES]]
    package_edges = [[a, b, w] for (a, b), w in sorted(
        package_edge_w.items(), key=lambda kv: (-kv[1], kv[0])
    )[:MAX_EDGES]]

    def _rank(counter: Counter[str]) -> list[list[Any]]:
        return [[name, n] for name, n in counter.most_common(MAX_HOTSPOTS) if name in keep]

    heaviest = [[mod, loc] for mod, loc, _ in modules[:MAX_HOTSPOTS]]
    entries = []
    try:
        found, _ = find_entries(graph)
        entries = [
            {"name": e.oracle_name, "kind": e.kind, "node": e.node, "file": ""}
            for e in found[:60]
        ]
    except (OSError, ValueError):
        entries = []
    sinks: list[dict[str, Any]] = []
    try:
        for hits in sink_hits(graph).values():
            for hit in hits:
                sinks.append({
                    "node": hit.node[:200],
                    "target": hit.target[:200],
                    "file": "",
                    "line": int(hit.line or 0),
                    "vuln_class": hit.vuln_class[:80],
                    "effect": (hit.effect or "")[:40],
                })
                if len(sinks) >= 80:
                    break
            if len(sinks) >= 80:
                break
    except (OSError, ValueError):
        sinks = []

    fn_out = {mod: functions[mod] for mod in keep if functions.get(mod)}
    total_lines = sum(loc for _, loc, _ in packages)
    layers = _layer_rows([(n, loc, layer) for n, loc, layer in packages], exhibit_a=exhibit_a)
    return {
        "available": True,
        "from": "checkout",
        "commit": commit,
        "reason": "",
        "command": COMMAND,
        "packages": packages,
        "modules": modules,
        "module_edges": module_edges,
        "package_edges": package_edges,
        "functions": fn_out,
        "uses": uses[:MAX_EDGES],
        "layers": layers,
        "hotspots": {
            "depended": _rank(incoming),
            "orchestrators": _rank(outgoing),
            "heaviest": heaviest,
        },
        "stats": {
            "packages": len(packages),
            "modules": len(modules),
            "imports": len(module_edges),
            "lines": total_lines,
            "functions": sum(len(v) for v in fn_out.values()),
            "sinks": len(sinks),
            "entries": len(entries),
        },
        "entries": entries,
        "sinks": sinks,
        "paths": [],
        "source_file": "",
        "exhibit_a": exhibit_a,
    }


def _remember(key: str, body: dict[str, Any]) -> dict[str, Any]:
    with _cache_lock:
        _cache[key] = body
        if key in _cache_order:
            _cache_order.remove(key)
        _cache_order.append(key)
        while len(_cache_order) > CACHE_SIZE:
            old = _cache_order.pop(0)
            _cache.pop(old, None)
    return body


def build_checkout_graph(root: Path, *, commit: str | None = None) -> dict[str, Any]:
    """Run ``scan --graph``'s constructor on ``root`` and aggregate for the UI."""
    try:
        here = root.resolve()
    except OSError:
        return _empty(reason="checkout is not a directory")
    if not here.is_dir():
        return _empty(reason="checkout is not a directory")
    sha = commit if commit is not None else git_head(here)
    key = f"{here}:{sha or here.stat().st_mtime}"
    with _cache_lock:
        cached = _cache.get(key)
    if cached is not None:
        return cached
    try:
        graph = build_graph(here)
    except (OSError, ValueError) as exc:
        return _empty(reason=f"code tree could not be parsed: {exc}")
    body = _aggregate(graph, exhibit_a=_is_exhibit_a(here), commit=sha)
    return _remember(key, body)


def _latest_summary(source: RunSource) -> dict[str, Any]:
    try:
        refs = list(source.list_runs())[:20]
    except SourceError:
        return {}
    for ref in refs:
        try:
            data = source.load_run(ref.run_id)
        except (KeyError, SourceError):
            continue
        summary = getattr(data, "graph_summary", None) or {}
        if summary.get("available"):
            return summary
    return {}


def load_repo_graph(
    source: RunSource,
    *,
    checkout: Path | None = None,
    cwd: Path | None = None,
) -> dict[str, Any]:
    """Graph for the chosen --source: checkout first, then graph-summary.json."""
    root = checkout
    if root is None and cwd is not None:
        root = matching_checkout(source, cwd)
    if root is not None:
        body = build_checkout_graph(root)
        if body.get("available"):
            body["source"] = getattr(source, "label", "")
            return body
    summary = _latest_summary(source)
    if summary:
        body = _empty(reason="", summary=summary)
        body["source"] = getattr(source, "label", "")
        return body
    kind = "github" if isinstance(source, GitHubSource) else (
        "local" if isinstance(source, LocalRunsSource) else "source"
    )
    reason = (
        "no local checkout for this GitHub source; graph-summary.json was not in the run artifact"
        if kind == "github"
        else "code graph is built from the repository checkout"
    )
    body = _empty(reason=reason)
    body["source"] = getattr(source, "label", "")
    return body


def clear_graph_cache() -> None:
    """Test helper: drop the commit cache."""
    with _cache_lock:
        _cache.clear()
        _cache_order.clear()
