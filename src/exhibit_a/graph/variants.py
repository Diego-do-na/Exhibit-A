"""Variant hunting: after a proof, where else the graph says the same mistake may sit.

A proven finding names an effect, the entry point the oracle saw, and the chain of admitted
application frames down to the function that made the sink call (``evidence.json`` ``facts``).
From that and the repository's static call graph this module lists candidate *variants*,
without a model:

* ``same_sink_function``: another entry point that reaches the very function that made the
  proven sink call (two routes into one unsafe helper);
* ``same_sink_rule``: another call site of the same catalog sink rule (``builtins.open``,
  ``subprocess.run``, ...) whose argument is not a constant;
* ``similar_caller``: a ``same_sink_rule`` site whose function is structurally similar to the
  proven sink caller and takes the sink argument from the same parameter positions (a copied
  handler).

A call whose arguments are all constants (``open("static/about.html")``) is never listed: it
cannot carry input. Candidates that repeat a proven path (same entry point and sink function)
are dropped, the rest are ranked and capped.

The list only proposes. Reachability is not exploitability, and the parameter-flow check is a
small intra-function approximation over ``ast`` (assignments, loops and ``with`` targets), not a
taint analysis. A variant becomes a finding only when the normal loop proves it in the sandbox;
an empty list means the graph found nothing, never that the code is safe.

Repository code is read as text and parsed; it is never imported or executed. The run
directory is read as data: sizes are capped and every field is type-checked.
"""

from __future__ import annotations

import ast
import difflib
import json
import os
import stat
import textwrap
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from exhibit_a.findings.dedupe import EFFECTS, proof_key
from exhibit_a.schemas.graph import CodeGraph, EntryPoint, GraphEdge, GraphNode, ReachPath, SinkHit

from .catalog import SinkRule, find_entries, match_sink, sink_hits
from .reach import find_paths, render
from .slicer import _read_lines

#: Most candidates listed per finding unless the caller asks for fewer.
MAX_VARIANTS = 20
#: Shape similarity (0..1) at or above which a same-rule caller counts as a copy.
SIMILARITY_THRESHOLD = 0.6
#: Packages read from one run directory, and the size cap of each JSON file.
MAX_PACKAGES = 500
MAX_JSON_BYTES = 5_000_000
_MAX_FRAMES = 64
_MAX_TEXT = 300
#: Keywords that set how a sink behaves, not what it acts on: their values never make a call
#: "non-constant" on their own.
_OPTION_KEYWORDS = frozenset({
    "mode", "flags", "encoding", "errors", "newline", "buffering", "closefd", "Loader", "check",
    "text", "capture_output", "timeout", "stdout", "stderr", "stdin", "universal_newlines",
})
#: Receivers tried, in order, to name the rule of a sink matched by method name only.
_WEAK_PREFIXES = ("pathlib.Path.", "zipfile.ZipFile.", "sqlite3.connect.")
_CALLABLE = ("function", "method")

SAME_SINK_FUNCTION = "same_sink_function"
SIMILAR_CALLER = "similar_caller"
SAME_SINK_RULE = "same_sink_rule"
_KIND_ORDER = {SAME_SINK_FUNCTION: 0, SIMILAR_CALLER: 1, SAME_SINK_RULE: 2}
#: Lower is more exposed to attacker input (same order as the audit's ranking).
_EXPOSURE = {"asgi": 0, "wsgi": 0, "route_decorator": 0, "route_table": 0, "django_view": 0,
             "request_handler": 0, "declared": 1, "proven": 1, "cli_main": 2}


# -- the proven finding ---------------------------------------------------------------------


@dataclass(frozen=True)
class Frame:
    file: str
    qualname: str
    line: int

    def to_json(self) -> dict[str, Any]:
        return {"file": self.file, "qualname": self.qualname, "line": self.line}


@dataclass(frozen=True)
class ProvenFinding:
    """What the oracle observed for one proven, non-duplicate finding of a run."""

    finding_id: str  # the suspicion id of the primary proof
    package: str  # its package directory, relative to the run directory
    effect: str
    chain: tuple[Frame, ...]  # admitted application frames, entry point first
    sink_line: int = 0  # observed line in the sink caller (graph-refined when the loop could)
    sink_call: str = ""  # the dotted sink the graph placed on that line, if any
    fix_verified: bool = False
    target_host: str = ""
    target_port: int | None = None
    path_class: str = ""
    input_family: str = ""
    cpu_function: str = ""

    @property
    def entry(self) -> Frame:
        return self.chain[0]

    @property
    def sink(self) -> Frame:
        return self.chain[-1]

    def facts(self) -> dict[str, Any]:
        """The shape ``findings.proof_key`` reads, to compare a variant's proof with this one."""
        out: dict[str, Any] = {"effect": self.effect, "chain": [f.to_json() for f in self.chain]}
        if self.target_host:
            out["target_host"] = self.target_host
        if self.target_port is not None:
            out["target_port"] = self.target_port
        if self.path_class:
            out["path_class"] = self.path_class
        if self.input_family:
            out["input_family"] = self.input_family
        if self.cpu_function:
            out["cpu_function"] = self.cpu_function
        return out

    def to_json(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "package": self.package,
            "effect": self.effect,
            "entry_point": self.entry.qualname,
            "entry_file": self.entry.file,
            "sink_function": self.sink.qualname,
            "sink_file": self.sink.file,
            "sink_line": self.sink_line,
            "sink_call": self.sink_call,
            "chain": [f.to_json() for f in self.chain],
            "fix_verified": self.fix_verified,
        }


def _read_json(path: Path) -> Any:
    """A JSON file of the run directory, or None (missing, not a regular file, too big, bad JSON)."""
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON_BYTES:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None


def _text(value: Any) -> str | None:
    return value[:_MAX_TEXT] if isinstance(value, str) else None


def finding_from_evidence(finding_id: str, package: str, evidence: Mapping[str, Any]) -> ProvenFinding | None:
    """A ``ProvenFinding`` from a package's ``evidence.json``, or None when its facts are unusable."""
    facts = evidence.get("facts")
    if not isinstance(facts, Mapping) or proof_key(facts) is None:
        return None
    chain = tuple(Frame(str(f["file"])[:_MAX_TEXT], str(f["qualname"])[:_MAX_TEXT], int(f["line"]))
                  for f in facts["chain"][:_MAX_FRAMES])
    observed = facts.get("observed_location")
    line, call = chain[-1].line, ""
    if isinstance(observed, Mapping):
        if isinstance(observed.get("line"), int) and not isinstance(observed.get("line"), bool):
            line = observed["line"]
        call = _text(observed.get("sink_call")) or ""
    return ProvenFinding(
        finding_id=finding_id[:_MAX_TEXT], package=package, effect=str(facts["effect"]), chain=chain,
        sink_line=line, sink_call=call, fix_verified=evidence.get("fix_verified") is True,
        target_host=str(facts.get("target_host") or ""),
        target_port=facts.get("target_port") if isinstance(facts.get("target_port"), int) else None,
        path_class=str(facts.get("path_class") or ""),
        input_family=str(facts.get("input_family") or ""),
        cpu_function=str(facts.get("cpu_function") or ""),
    )


def load_findings(run_dir: str | Path) -> tuple[list[ProvenFinding], list[dict[str, str]]]:
    """Proven, non-duplicate findings of a run directory, and the packages skipped with a reason.

    A package counts when its ``verdict.json`` says ``proven``, it is not a duplicate of another
    proof, and its ``evidence.json`` carries the oracle's facts (effect and admitted frame chain).
    A proof without those facts cannot be placed on the graph, so it is skipped and said so.
    """
    packages = Path(run_dir) / "packages"
    found: list[ProvenFinding] = []
    skipped: list[dict[str, str]] = []
    try:
        names = sorted(p.name for p in packages.iterdir() if p.is_dir() and not p.is_symlink())
    except OSError:
        return found, skipped
    for name in names[:MAX_PACKAGES]:
        rel = f"packages/{name}"
        verdict = _read_json(packages / name / "verdict.json")
        if not isinstance(verdict, Mapping) or verdict.get("verdict") != "proven":
            skipped.append({"package": rel, "reason": "verdict.json is missing or not proven"})
            continue
        if verdict.get("duplicate_of"):
            skipped.append({"package": rel, "reason": f"duplicate of {_text(verdict.get('duplicate_of'))}"})
            continue
        evidence = _read_json(packages / name / "evidence.json")
        if not isinstance(evidence, Mapping):
            skipped.append({"package": rel, "reason": "evidence.json is missing or unreadable"})
            continue
        suspicion = evidence.get("suspicion")
        sid = _text(suspicion.get("id")) if isinstance(suspicion, Mapping) else None
        finding = finding_from_evidence(sid or name, rel, evidence)
        if finding is None:
            facts = evidence.get("facts")
            effect = facts.get("effect") if isinstance(facts, Mapping) else None
            if isinstance(effect, str) and effect not in EFFECTS:
                reason = f"effect {effect[:40]!r} has no frame identity in findings.dedupe yet"
            else:
                reason = "no oracle facts (effect and admitted frames)"
            skipped.append({"package": rel, "reason": reason})
            continue
        found.append(finding)
    if len(names) > MAX_PACKAGES:
        skipped.append({"package": "packages/", "reason": f"only the first {MAX_PACKAGES} packages were read"})
    return found, skipped


# -- sink rules and constant arguments --------------------------------------------------------


def sink_rule(hit: SinkHit) -> SinkRule | None:
    """The catalog rule a sink hit stands for (a name-only hit is matched on its method)."""
    if not hit.weak:
        return match_sink(hit.target)
    method = hit.target.rsplit(".", 1)[-1]
    for prefix in _WEAK_PREFIXES:
        rule = match_sink(prefix + method)
        if rule is not None and rule.category == hit.category:
            return rule
    return None


def _rule_name(rule: SinkRule | None, hit: SinkHit) -> str:
    return rule.names[0] if rule is not None else f"{hit.category}/{hit.vuln_class}"


def _same_rule(a: SinkHit, rule_a: SinkRule | None, b: SinkHit) -> bool:
    if a.effect != b.effect:
        return False
    rule_b = sink_rule(b)
    if rule_a is not None or rule_b is not None:
        return rule_a is rule_b
    return (a.category, a.vuln_class) == (b.category, b.vuln_class)


def _constant_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(v, ast.Constant) for v in node.values)
    if isinstance(node, ast.BinOp):
        return _constant_expr(node.left) and _constant_expr(node.right)
    if isinstance(node, ast.UnaryOp):
        return _constant_expr(node.operand)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_constant_expr(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(k is not None and _constant_expr(k) for k in node.keys) and \
            all(_constant_expr(v) for v in node.values)
    return False


def constant_text(text: str) -> bool:
    """Whether the source text of one argument is fixed by the code alone.

    Literals of any type, f-strings without a field, and operators, lists, tuples, sets and
    dicts over those are constants. Names, attributes, calls, subscripts, starred arguments and
    text the graph cut at its cap (it does not parse) are not.
    """
    try:
        node = ast.parse(text.strip(), mode="eval").body
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    try:
        return _constant_expr(node)
    except RecursionError:
        return False


def constant_call(edge: GraphEdge, rule: SinkRule | None) -> bool:
    """Whether every argument a sink call acts on is a constant, so it cannot carry input.

    The mode position of an open-like call and option keywords (``mode``, ``check``, ...) do not
    count. A call whose data arguments the graph did not keep (none at all, or a method called on
    a computed value such as ``Path(x).read_text()``) is not constant: nothing shows it is.
    """
    skip = rule.mode_arg[0] if rule is not None and rule.mode_arg is not None else None
    data = [a for i, a in enumerate(edge.args) if i != skip]
    data += [v for k, v in edge.kwargs.items() if k not in _OPTION_KEYWORDS]
    return bool(data) and all(constant_text(a) for a in data)


def _edge_for(edges: Mapping[tuple[str, int], list[GraphEdge]], hit: SinkHit) -> GraphEdge | None:
    for edge in edges.get((hit.node, hit.line), []):
        if (edge.kind == "external" and edge.dst == hit.target) or (edge.kind == "unresolved" and edge.text == hit.target):
            return edge
    return None


# -- structure and parameter flow ---------------------------------------------------------------


@dataclass(frozen=True)
class Shape:
    """The ``ast`` node-type sequence of a function and which parameters reach its sink calls."""

    types: tuple[str, ...]
    flow: frozenset[int]  # positions (``self``/``cls`` dropped) of parameters that reach a sink line


def _names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _targets(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.Assign):
        return list(node.targets)
    if isinstance(node, (ast.AugAssign, ast.AnnAssign, ast.For, ast.AsyncFor, ast.NamedExpr)):
        return [node.target]
    if isinstance(node, ast.withitem) and node.optional_vars is not None:
        return [node.optional_vars]
    return []


def _source_of(node: ast.AST) -> ast.AST | None:
    if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.NamedExpr)):
        return node.value
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return node.iter
    if isinstance(node, ast.withitem):
        return node.context_expr
    return None


def function_shape(graph_node: GraphNode, lines: list[str] | None, sink_lines: Iterable[int]) -> Shape | None:
    """Parse one function from its file's lines and compute its ``Shape``, or None."""
    if lines is None or graph_node.end > len(lines):
        return None
    segment = textwrap.dedent("\n".join(lines[graph_node.start - 1:graph_node.end]))
    try:
        tree = ast.parse(segment)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    func = next((n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
    if func is None:
        return None
    offset = graph_node.start - 1
    params = [p.lstrip("*") for p in graph_node.params]
    if graph_node.kind == "method" and params:
        params = params[1:]
    # name -> parameter positions it may carry; a fixed point over assignments, loops, ``with``.
    taint: dict[str, frozenset[int]] = {p: frozenset({i}) for i, p in enumerate(params)}
    binders = [n for n in ast.walk(func) if _targets(n)]
    for _ in range(8):
        changed = False
        for binder in binders:
            source = _source_of(binder)
            if source is None:
                continue
            carried = frozenset().union(*(taint.get(n, frozenset()) for n in _names(source)))
            if not carried:
                continue
            for target in _targets(binder):
                for name in _names(target):
                    merged = taint.get(name, frozenset()) | carried
                    if merged != taint.get(name):
                        taint[name] = merged
                        changed = True
        if not changed:
            break
    wanted = set(sink_lines)
    flow: set[int] = set()
    for call in ast.walk(func):
        if isinstance(call, ast.Call) and call.lineno + offset in wanted:
            for arg in [*call.args, *(k.value for k in call.keywords), call.func]:
                for name in _names(arg):
                    flow |= taint.get(name, frozenset())
    types = tuple(type(n).__name__ for n in ast.walk(func) if not isinstance(n, (ast.Load, ast.Store, ast.Del)))
    return Shape(types=types[:4000], flow=frozenset(flow))


def similarity(a: Shape, b: Shape) -> float:
    return round(difflib.SequenceMatcher(None, a.types, b.types, autojunk=False).ratio(), 4)


# -- candidates ----------------------------------------------------------------------------------


@dataclass
class Variant:
    """One candidate variant of a proven finding."""

    finding_id: str
    kinds: list[str]
    effect: str
    vuln_class: str
    rule: str
    sink_node: str
    sink_target: str
    sink_line: int
    source_file: str  # the file of the function that makes the sink call
    path: ReachPath | None = None  # None: no entry point reaches the call site
    similarity: float | None = None
    param_flow: list[int] = field(default_factory=list)
    other_entries: int = 0  # more entry points reach this call site (same_sink_rule kinds)
    weak_sink: bool = False

    @property
    def runnable(self) -> bool:
        return self.path is not None

    @property
    def entry_point(self) -> str | None:
        return self.path.oracle_entry_point if self.path is not None else None

    def rank(self) -> tuple:
        path = self.path
        return (
            min(_KIND_ORDER[k] for k in self.kinds),
            path is None,
            -(self.similarity or 0.0),
            self.weak_sink,
            _EXPOSURE.get(path.entry_kind, 3) if path else 9,
            (path.hops + path.returns) if path else 0,
            path.unresolved_hops if path else 0,
            path.entry if path else "",
            self.sink_node,
            self.sink_line,
            self.sink_target,
        )

    def to_json(self) -> dict[str, Any]:
        path = self.path
        return {
            "variant_of": self.finding_id,
            "kinds": list(self.kinds),
            "effect": self.effect,
            "vuln_class": self.vuln_class,
            "rule": self.rule,
            "sink_node": self.sink_node,
            "sink_target": self.sink_target,
            "sink_line": self.sink_line,
            "source_file": self.source_file,
            "runnable": self.runnable,
            "entry": path.entry if path else None,
            "entry_kind": path.entry_kind if path else None,
            "entry_point": self.entry_point,
            "path": render(path) if path else None,
            "hops": (path.hops + path.returns) if path else None,
            "confidence": path.confidence if path else None,
            "similarity": self.similarity,
            "param_flow": list(self.param_flow),
            "other_entries": self.other_entries,
            "weak_sink": self.weak_sink,
        }


@dataclass
class VariantList:
    """The candidates for one finding, and what the search saw."""

    finding: ProvenFinding
    variants: list[Variant] = field(default_factory=list)
    sink_node: str | None = None  # the graph node of the proven sink caller, if the graph has it
    entry_node: str | None = None
    rule: str = ""
    considered: int = 0  # candidates before the cap
    constant_sites: int = 0  # same-rule calls left out because every argument is constant
    note: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            **self.finding.to_json(),
            "graph_sink_node": self.sink_node,
            "graph_entry_node": self.entry_node,
            "rule": self.rule,
            "considered": self.considered,
            "listed": len(self.variants),
            "constant_sites_skipped": self.constant_sites,
            "note": self.note,
            "candidates": [v.to_json() for v in self.variants],
        }


def node_for(graph: CodeGraph, frame: Frame) -> GraphNode | None:
    """The graph function an oracle frame names: same qualname, same file when that settles it."""
    named = [n for n in graph.nodes if n.kind in _CALLABLE and n.name == frame.qualname]
    in_file = [n for n in named if n.file == frame.file or frame.file.endswith("/" + n.file)]
    if len(in_file) == 1:
        return in_file[0]
    if len(named) == 1 and not in_file:
        return named[0]
    by_line = [n for n in in_file if frame.line in (n.start, n.line)]
    return by_line[0] if len(by_line) == 1 else None


def proven_key(graph: CodeGraph, finding: ProvenFinding) -> tuple[str, str] | None:
    """``(entry node, sink caller node)`` of a proven finding on the graph, or None."""
    entry, sink = node_for(graph, finding.entry), node_for(graph, finding.sink)
    return (entry.id, sink.id) if entry is not None and sink is not None else None


def find_variants(
    graph: CodeGraph,
    finding: ProvenFinding,
    *,
    root: str | Path | None = None,
    max_count: int = MAX_VARIANTS,
    exclude: Iterable[tuple[str, str]] = (),
    declared_entries: list[str] | tuple[str, ...] = (),
) -> VariantList:
    """Candidate variants of ``finding`` on ``graph``, ranked and capped at ``max_count``.

    ``exclude`` holds ``(entry node, sink caller node)`` pairs already proven (every finding of
    the run): a candidate that repeats one is the same finding, so it is never listed. ``root``
    is the repository the graph was built from; without it the structural comparison is skipped
    and no candidate is labelled ``similar_caller``.
    """
    if max_count < 1:
        raise ValueError("max_count must be at least 1")
    out = VariantList(finding=finding)
    nodes = {n.id: n for n in graph.nodes}
    sink_node = node_for(graph, finding.sink)
    entry_node = node_for(graph, finding.entry)
    out.sink_node = sink_node.id if sink_node else None
    out.entry_node = entry_node.id if entry_node else None
    excluded = set(exclude)
    if entry_node is not None and sink_node is not None:
        excluded.add((entry_node.id, sink_node.id))

    hits = sink_hits(graph)
    edges: dict[tuple[str, int], list[GraphEdge]] = {}
    for edge in graph.edges:
        if edge.kind in ("external", "unresolved"):
            edges.setdefault((edge.src, edge.line), []).append(edge)

    # The proven sink call: the hit the loop placed on the observed line, else any hit of the effect.
    own = [h for h in hits.get(sink_node.id, []) if h.effect == finding.effect] if sink_node else []
    proven_hit = next((h for h in own if finding.sink_call and h.target == finding.sink_call), None) \
        or next((h for h in own if h.line == finding.sink_line), None) \
        or (own[0] if own else None)
    if proven_hit is None and finding.sink_call:
        rule = match_sink(finding.sink_call)
        if rule is not None and rule.effect == finding.effect:
            proven_hit = SinkHit(node="", target=finding.sink_call, line=0, category=rule.category,
                                 vuln_class=rule.vuln_class, effect=rule.effect, access=rule.access)
    if proven_hit is None:
        if finding.effect == "canary_dos" and sink_node is not None:
            rule = None
            out.rule = "cpu/algorithmic_complexity"
        else:
            out.note = ("the graph has no sink call of this effect in the proven sink function "
                        "and evidence names no sink call: no rule to match variants against")
            return out
    else:
        rule = sink_rule(proven_hit)
        out.rule = _rule_name(rule, proven_hit)

    # Check if the calls inside sink_node are constant-only
    if own:
        own_edges = [_edge_for(edges, h) for h in own]
        if all(e is not None and not e.ref and constant_call(e, sink_rule(h)) for e, h in zip(own_edges, own)):
            out.constant_sites += len(own)
            return out

    # Every non-constant call site of the same rule (the proven function's own included).
    sites: list[SinkHit] = []
    if rule is not None:
        for node_id in sorted(hits):
            for hit in hits[node_id]:
                if not _same_rule(proven_hit, rule, hit):
                    continue
                edge = _edge_for(edges, hit)
                if edge is None or edge.ref:
                    continue  # a sink handed over as a callback: no call site to argue about
                if constant_call(edge, sink_rule(hit)):
                    out.constant_sites += 1
                    continue
                sites.append(hit)

    # Structure of the proven sink caller, to compare same-rule callers with.
    cache: dict[str, list[str] | None] = {}

    def shape_of(node: GraphNode, lines: Iterable[int]) -> Shape | None:
        if root is None:
            return None
        if node.file not in cache:
            cache[node.file] = _read_lines(Path(root), node.file)
        return function_shape(node, cache[node.file], lines)

    proven_shape = None
    if sink_node is not None:
        proven_shape = shape_of(sink_node, [h.line for h in own if _same_rule(proven_hit, rule, h)])

    entries, _ = find_entries(graph, declared_entries)
    if entry_node is not None and entry_node.id not in {e.node for e in entries}:
        entries = [*entries, EntryPoint(node=entry_node.id, kind="proven", oracle_name=entry_node.name,
                                        detail="the entry point of the proven finding")]
    site_nodes = sorted({h.node for h in sites})
    if finding.effect == "canary_dos" and sink_node is not None and sink_node.id not in site_nodes:
        site_nodes = sorted({*site_nodes, sink_node.id})
    report = find_paths(graph, site_nodes, entries=entries, max_paths=100_000) if site_nodes else None
    by_site: dict[tuple[str, int, str], list[ReachPath]] = {}
    for path in report.paths if report else []:
        if path.returns == 0 and path.sink.node == path.changed:
            by_site.setdefault((path.sink.node, path.sink.line, path.sink.target), []).append(path)

    candidates: list[Variant] = []
    if finding.effect == "canary_dos" and sink_node is not None:
        # canary_dos variants: same function reached from other entry points only.
        node = nodes.get(sink_node.id)
        if node is not None:
            paths_to_sink = [p for p in (report.paths if report else [])
                             if p.returns == 0 and p.sink.node == sink_node.id
                             and (p.entry, sink_node.id) not in excluded]
            seen_entries = set()
            for path in sorted(paths_to_sink, key=_path_rank):
                if path.entry in seen_entries:
                    continue
                seen_entries.add(path.entry)
                target_name = proven_hit.target if proven_hit else sink_node.name
                line_no = proven_hit.line if proven_hit else sink_node.start
                vc = proven_hit.vuln_class if proven_hit else "algorithmic_complexity"
                candidates.append(Variant(
                    finding_id=finding.finding_id, kinds=[SAME_SINK_FUNCTION], effect=finding.effect,
                    vuln_class=vc, rule=out.rule, sink_node=sink_node.id, sink_target=target_name,
                    sink_line=line_no, source_file=node.file, path=path,
                    weak_sink=proven_hit.weak if proven_hit else False,
                ))
    else:
        for hit in sites:
            node = nodes.get(hit.node)
            if node is None:
                continue
            paths = [p for p in by_site.get((hit.node, hit.line, hit.target), [])
                     if (p.entry, hit.node) not in excluded]
            base = dict(finding_id=finding.finding_id, effect=finding.effect, vuln_class=hit.vuln_class,
                        rule=out.rule, sink_node=hit.node, sink_target=hit.target, sink_line=hit.line,
                        source_file=node.file, weak_sink=hit.weak)
            if sink_node is not None and hit.node == sink_node.id:
                # Two routes into one helper: every other entry point is its own candidate.
                seen_entries = set()
                for path in sorted(paths, key=_path_rank):
                    if path.entry in seen_entries:
                        continue
                    seen_entries.add(path.entry)
                    candidates.append(Variant(kinds=[SAME_SINK_FUNCTION], path=path, **base))
                continue
            kinds = [SAME_SINK_RULE]
            sim: float | None = None
            flow: list[int] = []
            shape = shape_of(node, [hit.line]) if proven_shape is not None else None
            if shape is not None and proven_shape is not None:
                sim = similarity(proven_shape, shape)
                flow = sorted(shape.flow)
                if sim >= SIMILARITY_THRESHOLD and shape.flow and shape.flow == proven_shape.flow:
                    kinds = [SIMILAR_CALLER, SAME_SINK_RULE]
            ordered = sorted(paths, key=_path_rank)
            if not ordered and by_site.get((hit.node, hit.line, hit.target)):
                continue  # every entry point reaching it is an already proven path
            candidates.append(Variant(kinds=kinds, path=ordered[0] if ordered else None, similarity=sim,
                                      param_flow=flow, other_entries=max(0, len(ordered) - 1), **base))

    unique: dict[tuple, Variant] = {}
    for cand in candidates:
        key = (cand.path.entry if cand.path else None, cand.sink_node, cand.sink_line, cand.sink_target)
        unique.setdefault(key, cand)
    ranked = sorted(unique.values(), key=Variant.rank)
    out.considered = len(ranked)
    out.variants = ranked[:max_count]
    return out


def _path_rank(path: ReachPath) -> tuple:
    return (_EXPOSURE.get(path.entry_kind, 3), path.hops + path.returns, path.unresolved_hops, path.entry)


def hunt(
    graph: CodeGraph,
    findings: list[ProvenFinding],
    *,
    root: str | Path | None = None,
    max_count: int = MAX_VARIANTS,
    declared_entries: list[str] | tuple[str, ...] = (),
) -> list[VariantList]:
    """Candidates for every finding of a run; no candidate repeats any finding's proven path."""
    proven = {k for k in (proven_key(graph, f) for f in findings) if k is not None}
    return [find_variants(graph, f, root=root, max_count=max_count, exclude=proven,
                          declared_entries=declared_entries) for f in findings]
