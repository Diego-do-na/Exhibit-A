"""JSON contracts for the static code graph (SLICE): the call graph and the reach report.

The graph is a proposal, never evidence: it says which code a change *might* connect to an
entry point and a sink. Only sandboxed execution under the oracle proves anything.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from .base import StrictModel

GRAPH_SCHEMA_VERSION = "1"
REACH_SCHEMA_VERSION = "1"

NodeKind = Literal["module", "class", "function", "method"]
#: call: plain call of a function by name or import; method: self/cls/super method;
#: attr: module attribute (mod.func); ctor: Class(...); instance: method on a value whose
#: class is known (x = Class(); x.m(), self.attr.m(), Class().m(), instance __call__);
#: ref: a function passed as an argument (callbacks, thread pools, route tables);
#: external: a call or reference that leaves the repository (dst is a dotted name);
#: unresolved: a call nothing could resolve (dst is empty, text says what was called).
EdgeKind = Literal["call", "method", "attr", "ctor", "instance", "ref", "external", "unresolved"]


class Decorator(StrictModel):
    callee: str  # dotted text of the decorator (or of its callee when it is a call)
    call: bool  # whether the decorator is a call, as in @app.route("/x")
    path: str | None = None  # first positional argument when it is a string literal


class GraphNode(StrictModel):
    id: str  # "module:Qual.name"; the part after ':' is the CPython __qualname__
    kind: NodeKind
    module: str
    name: str  # qualified name inside the module (empty for module nodes' qualname "<module>")
    file: str  # repository-relative POSIX path
    line: int = Field(ge=1)  # the def/class line
    start: int = Field(ge=1)  # first line including decorators
    end: int = Field(ge=1)
    is_async: bool = False
    params: list[str] = Field(default_factory=list)
    decorators: list[Decorator] = Field(default_factory=list)
    bases: list[str] = Field(default_factory=list)  # classes only: the base expressions


class GraphEdge(StrictModel):
    src: str
    dst: str  # node id, external dotted name, or "" when unresolved
    kind: EdgeKind
    line: int = Field(ge=0)
    text: str = ""  # what was called, as written (capped)
    via: str = ""  # ref edges: the callee the function was handed to
    args: list[str] = Field(default_factory=list)  # external edges: positional args (capped)
    kwargs: dict[str, str] = Field(default_factory=dict)  # external edges: keyword args (capped)
    ref: bool = False  # external edges: referenced as an argument, not called here


class SkippedFile(StrictModel):
    file: str
    reason: str


class GraphStats(StrictModel):
    files: int = 0
    nodes: int = 0
    edges: int = 0
    resolved: int = 0
    external: int = 0
    unresolved: int = 0


class CodeGraph(StrictModel):
    schema_version: Literal["1"] = GRAPH_SCHEMA_VERSION
    files: list[str] = Field(default_factory=list)
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    skipped: list[SkippedFile] = Field(default_factory=list)
    truncated: bool = False  # the file-count or total-size cap was hit
    stats: GraphStats = Field(default_factory=GraphStats)


class EntryPoint(StrictModel):
    node: str
    kind: str  # asgi | wsgi | route_decorator | route_table | django_view | cli_main | declared
    oracle_name: str  # the name the oracle matches against a frame's __qualname__
    detail: str = ""


class SinkHit(StrictModel):
    node: str  # the repository function that makes the call
    target: str  # external dotted name (or unresolved text for weak hits)
    line: int = Field(ge=0)
    category: str
    vuln_class: str
    effect: str | None = None  # oracle effect that can prove it today, if any
    access: str = ""
    weak: bool = False  # matched by method name only, on a receiver nothing resolved
    joined_path: bool = False  # an argument is built with os.path.join


class ReachPath(StrictModel):
    entry: str
    entry_kind: str
    oracle_entry_point: str
    changed: str
    pivot: str  # where the sink chain starts: the changed function or the caller it returns to
    to_changed: list[str]  # entry ... changed
    to_sink: list[str]  # pivot ... the function that calls the sink
    sink: SinkHit
    hops: int = Field(ge=0)
    returns: int = Field(ge=0)  # 1 when the sink is reached after returning to the caller
    unresolved_hops: int = Field(ge=0)
    confidence: float = Field(ge=0, le=1)
    vuln_class: str


class Unreached(StrictModel):
    node: str
    reason: str


class ReachReport(StrictModel):
    schema_version: Literal["1"] = REACH_SCHEMA_VERSION
    changed: list[str] = Field(default_factory=list)
    changed_outside_functions: list[str] = Field(default_factory=list)  # "file:line"
    entries: list[EntryPoint] = Field(default_factory=list)
    undeclared_entries: list[str] = Field(default_factory=list)  # declared names matching no node
    paths: list[ReachPath] = Field(default_factory=list)
    unreached: list[Unreached] = Field(default_factory=list)
    budget_exhausted: bool = False
    max_depth: int = 0
    node_budget: int = 0
