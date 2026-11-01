"""JavaScript/TypeScript sink catalog.

The catalog is intentionally conservative: only file reads and command execution map to
effects the current Node oracle can prove. All other matches remain suspicion-only.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from exhibit_a.schemas.graph import CodeGraph, EntryPoint, GraphEdge, SinkHit

READ = "canary_read"
EXEC = "canary_exec"


@dataclass(frozen=True)
class JSSinkRule:
    names: tuple[str, ...]
    category: str
    vuln_class: str
    effect: str | None
    access: str
    dynamic_arg: int | None = None


SINKS = (
    JSSinkRule(
        ("fs.readFile", "fs.readFileSync", "fs.createReadStream", "fs.promises.readFile"),
        "filesystem", "path_traversal", READ, "read", 0,
    ),
    JSSinkRule(
        ("child_process.exec", "child_process.execSync", "child_process.spawn"),
        "process", "command_injection", EXEC, "exec", 0,
    ),
    JSSinkRule(("res.sendFile",), "filesystem", "path_traversal", READ, "read", 0),
    JSSinkRule(("path.join",), "filesystem", "path_traversal", None, "probe", None),
    JSSinkRule(("eval", "global.eval", "Function", "new Function"), "dynamic_code", "code_injection", EXEC, "code", 0),
    JSSinkRule(("http.request", "https.request", "fetch", "axios.get", "axios.post", "axios.request"),
               "outbound_request", "ssrf", None, "network", 0),
    JSSinkRule(("res.redirect",), "redirect", "open_redirect", None, "redirect", 0),
    JSSinkRule(("db.query", "client.query", "connection.query"), "database", "sql_injection", None, "query", 0),
)


def _rule(target: str) -> JSSinkRule | None:
    for rule in SINKS:
        if target in rule.names:
            return rule
    return None


def _dynamic(edge: GraphEdge, position: int) -> bool:
    if len(edge.args) <= position:
        return bool(edge.args)
    value = edge.args[position].strip()
    if re.fullmatch(r"""(['"]).*\1""", value, re.S):
        return False
    if re.fullmatch(r"`[^${}]*`", value, re.S):
        return False
    if re.fullmatch(r'''(?:['"][^'"]*['"]\s*\+\s*)+['"][^'"]*['"]''', value):
        return False
    return True


def sink_hits(graph: CodeGraph) -> dict[str, list[SinkHit]]:
    hits: dict[str, list[SinkHit]] = {}
    for edge in graph.edges:
        if edge.kind not in ("external", "unresolved"):
            continue
        rule = _rule(edge.dst or edge.text)
        if rule is None:
            continue
        if rule.vuln_class == "path_traversal" and rule.names == ("path.join",):
            if not any(_dynamic(edge, index) for index in range(len(edge.args))):
                continue
        if edge.dst == "child_process.spawn":
            options = edge.args[2] if len(edge.args) > 2 else ""
            if "shell" not in options or not re.search(r"\bshell\s*:\s*true\b", options):
                continue
        if rule.dynamic_arg is not None and not _dynamic(edge, rule.dynamic_arg):
            continue
        hit = SinkHit(
            node=edge.src, target=edge.dst or edge.text, line=edge.line, category=rule.category,
            vuln_class=rule.vuln_class, effect=rule.effect, access=rule.access,
            joined_path=any("path.join(" in arg for arg in edge.args),
            weak=edge.kind == "unresolved",
        )
        hits.setdefault(edge.src, []).append(hit)
    for values in hits.values():
        values.sort(key=lambda hit: (hit.line, hit.target))
    return hits


def find_entries(graph: CodeGraph, declared: list[str] | tuple[str, ...] = ()) -> tuple[list[EntryPoint], list[str]]:
    raw = getattr(graph, "_js_entry_points", ())
    by_id = {node.id: node for node in graph.nodes}
    if declared:
        entries, missing = [], []
        for name in declared:
            matches = [node for node in graph.nodes if node.kind in ("function", "method") and
                       (node.name == name or node.id == name)]
            if not matches:
                missing.append(name)
            entries.extend(EntryPoint(node=node.id, kind="declared", oracle_name=node.name,
                                      detail="declared entry point") for node in matches)
        return entries, missing
    entries = []
    for item in raw:
        node = by_id.get(item.get("node"))
        if node and node.kind in ("function", "method"):
            entries.append(EntryPoint(node=node.id, kind=item.get("kind", "declared"),
                                      oracle_name=item.get("oracle_name", node.name),
                                      detail=item.get("detail", "")))
    return entries, []
