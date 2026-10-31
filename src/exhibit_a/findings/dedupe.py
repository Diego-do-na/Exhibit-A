"""Group proofs of one effect, and say where the oracle saw the effect happen.

Two proven suspicions are the same finding when the oracle saw the same effect through the
same entry point and the same chain of application frames down to the sink caller. Nothing
the model wrote takes part: not its hypothesis, not its location, not its entry point text.
The only inputs are the oracle's admitted stack frames (the plugin admitted them against the
staged app, see docs/oracle/oracle-provenance.md), so a model cannot make two findings merge,
and two findings that differ in effect, entry point or any sink frame never merge.

The oracle records, for a frame, the function's qualified name, its file and the line the
function starts on (``co_firstlineno``), not the line being executed. The static call graph
fills the gap: inside the sink caller it knows on which line the sink is called. That line is a
proposal from an ``ast`` walk, so the location says which of the two it is (``line_source``).

Everything here is pure: dicts in, dicts out. ``proof_facts`` reads the evidence the loop
stores (``Evidence.oracle`` and ``Evidence.provenance``) or the same shape rebuilt in a test.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from exhibit_a.schemas.graph import CodeGraph

#: Which observed accesses count for each effect that watches the canary file.
_ACCESS = {"canary_read": {"read", "read_write"}, "canary_write": {"write", "read_write"}}
EFFECTS = ("canary_read", "canary_write", "canary_exec")

#: Where the observed line comes from.
FUNCTION_START = "function_start"  # the line the sink caller starts on, as the oracle saw it
GRAPH_SINK_CALL = "graph_sink_call"  # the line of the sink call inside it, from the static graph

_MAX_FRAMES = 64
_MAX_TEXT = 300


@dataclass(frozen=True)
class AppFrame:
    file: str  # relative to the app root when it could be made so
    qualname: str
    line: int  # the line the function starts on
    function: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "qualname": self.qualname, "line": self.line}


@dataclass(frozen=True)
class ProofFacts:
    """What the oracle observed for one proof: effect, entry point and sink frames."""

    effect: str
    access: str
    chain: tuple[AppFrame, ...]  # admitted application frames, entry point first
    line: int = 0  # the observed line in the sink caller's file
    line_source: str = FUNCTION_START
    sink_call: str = ""  # what the graph says is called there (a dotted name), if refined
    other_sink_lines: tuple[int, ...] = ()

    @property
    def entry(self) -> AppFrame:
        return self.chain[0]

    @property
    def sink(self) -> AppFrame:
        return self.chain[-1]

    def observed_location(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "file": self.sink.file,
            "line": self.line,
            "function": self.sink.qualname,
            "line_source": self.line_source,
        }
        if self.sink_call:
            out["sink_call"] = self.sink_call
        if self.other_sink_lines:
            out["other_sink_lines"] = list(self.other_sink_lines)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect": self.effect,
            "access": self.access,
            "entry_point": self.entry.qualname,
            "entry_file": self.entry.file,
            "sink_function": self.sink.qualname,
            "chain": [frame.to_dict() for frame in self.chain],
            "observed_location": self.observed_location(),
        }


def _relative(file: str, roots: Iterable[str]) -> str:
    for root in roots:
        prefix = root.rstrip("/") + "/"
        if file.startswith(prefix):
            return file[len(prefix):]
    return file


def _relevant(event: Mapping[str, Any], effect: str) -> bool:
    """Whether the event is a kind this effect is proven with (as the oracle's judge sees it)."""
    if event.get("via_symlink"):
        return False
    if effect == "canary_exec":
        return event.get("op") == "process" and bool(event.get("names_canary")) and bool(event.get("sink_named"))
    return event.get("access") in _ACCESS.get(effect, ())


def proof_facts(
    evidence: Mapping[str, Any],
    *,
    roots: Iterable[str] = (),
    entry_points: Collection[str] | None = None,
) -> ProofFacts | None:
    """The oracle's facts for one proof, or None when the evidence cannot support them.

    ``evidence`` is the stored ``Evidence`` (``oracle``: effect and events; ``provenance``).
    The deciding event is the first one of the kind the effect is proven with whose admitted
    frames start at a declared entry point (``entry_points``, or ``provenance["entry_points"]``
    when the evidence has them; none known means any admitted frame may start the chain). Missing
    ``admitted`` flags, an unknown effect or no such event give None: such a proof is reported
    as it is and never grouped.
    """
    oracle = evidence.get("oracle")
    if not isinstance(oracle, Mapping):
        return None
    effect = oracle.get("effect")
    if effect not in EFFECTS:
        return None
    events = oracle.get("events")
    if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
        return None
    if entry_points is None:
        provenance = evidence.get("provenance")
        recorded = provenance.get("entry_points") if isinstance(provenance, Mapping) else None
        entry_points = [e for e in recorded if isinstance(e, str)] if isinstance(recorded, list) else None
    names = set(entry_points) if entry_points else None
    root_list = list(roots)
    for event in events:
        if not isinstance(event, Mapping) or not _relevant(event, effect):
            continue
        stack = event.get("stack")
        if not isinstance(stack, list):
            continue
        frames = [f for f in stack if isinstance(f, Mapping) and f.get("admitted") is True]
        if not frames or len(frames) > _MAX_FRAMES:
            continue
        chain = []
        for f in frames:
            file, qualname, line = f.get("file"), f.get("qualname"), f.get("line")
            if not isinstance(file, str) or not isinstance(qualname, str) or not isinstance(line, int):
                chain = []
                break
            chain.append(AppFrame(_relative(file, root_list), qualname, line, str(f.get("function") or "")))
        if not chain:
            continue
        if names is not None and chain[0].qualname not in names and chain[0].function not in names:
            continue
        sink = chain[-1]
        return ProofFacts(effect=effect, access=str(event.get("access") or ""), chain=tuple(chain), line=sink.line)
    return None


def refine_with_graph(proof: ProofFacts, graph: CodeGraph) -> ProofFacts:
    """Move the observed line to the sink call inside the sink caller, when the graph knows it.

    The graph is matched to the oracle's frame by file, qualified name and start line, so a
    function the graph cannot identify exactly leaves the oracle's own line in place. Calls the
    catalog recognises as a sink for this effect win over weaker, name-only matches.
    """
    from exhibit_a.graph.catalog import sink_hits

    sink = proof.sink
    for node in graph.nodes:
        if node.kind not in ("function", "method") or node.file != sink.file or node.name != sink.qualname:
            continue
        if sink.line not in (node.start, node.line):
            continue
        hits = [h for h in sink_hits(graph).get(node.id, []) if h.effect == proof.effect and h.line > 0]
        strong = [h for h in hits if not h.weak]
        chosen = strong or hits
        if not chosen:
            return proof
        lines = sorted({h.line for h in chosen})
        first = next(h for h in chosen if h.line == lines[0])
        return replace(
            proof, line=lines[0], line_source=GRAPH_SINK_CALL, sink_call=first.target[:_MAX_TEXT],
            other_sink_lines=tuple(lines[1:6]),
        )
    return proof


# -- grouping --------------------------------------------------------------------------------


def proof_key(facts: Mapping[str, Any] | None) -> tuple | None:
    """The identity of a proof: effect plus the chain of application frames, or None."""
    if not isinstance(facts, Mapping) or facts.get("effect") not in EFFECTS:
        return None
    chain = facts.get("chain")
    if not isinstance(chain, list) or not chain or len(chain) > _MAX_FRAMES:
        return None
    frames = []
    for frame in chain:
        if not isinstance(frame, Mapping):
            return None
        file, qualname, line = frame.get("file"), frame.get("qualname"), frame.get("line")
        if not isinstance(file, str) or not isinstance(qualname, str) or not isinstance(line, int):
            return None
        frames.append((file, qualname, line))
    return (facts["effect"], tuple(frames))


@dataclass(frozen=True)
class FindingGroup:
    primary: str  # the first proven suspicion of the group
    duplicates: tuple[str, ...] = ()


def group_findings(items: Iterable[tuple[str, Mapping[str, Any] | None]]) -> list[FindingGroup]:
    """Group ``(suspicion id, proof facts)`` pairs given in the order they were proven.

    The first of each identity is the primary; later ones with the same identity are its
    duplicates. A proof without usable facts is its own group and never absorbs another.
    """
    order: list[str] = []
    members: dict[str, list[str]] = {}
    by_key: dict[tuple, str] = {}
    for sid, facts in items:
        if sid in members or any(sid in dups for dups in members.values()):
            continue
        key = proof_key(facts)
        primary = by_key.get(key) if key is not None else None
        if primary is None:
            order.append(sid)
            members[sid] = []
            if key is not None:
                by_key[key] = sid
        else:
            members[primary].append(sid)
    return [FindingGroup(sid, tuple(members[sid])) for sid in order]
