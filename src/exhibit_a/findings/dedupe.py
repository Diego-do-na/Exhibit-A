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

from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, get_args
from urllib.parse import urlsplit

from exhibit_a.oracle.oracle import Effect
from exhibit_a.schemas.graph import CodeGraph

#: Which observed accesses count for each effect that watches the canary file.
_ACCESS = {"canary_read": {"read", "read_write"}, "canary_write": {"write", "read_write"}}
#: Table-driven from Effect: all effects known to the engine.
EFFECTS: tuple[str, ...] = tuple(get_args(Effect))

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
    target_host: str = ""
    target_port: int | None = None
    path_class: str = ""
    input_family: str = ""
    cpu_function: str = ""

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
        out: dict[str, Any] = {
            "effect": self.effect,
            "access": self.access,
            "entry_point": self.entry.qualname,
            "entry_file": self.entry.file,
            "sink_function": self.sink.qualname,
            "chain": [frame.to_dict() for frame in self.chain],
            "observed_location": self.observed_location(),
        }
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


def _relative(file: str, roots: Iterable[str]) -> str:
    for root in roots:
        prefix = root.rstrip("/") + "/"
        if file.startswith(prefix):
            return file[len(prefix):]
    return file


def _relevant_file(event: Mapping[str, Any], effect: str) -> bool:
    return not event.get("via_symlink") and event.get("access") in _ACCESS.get(effect, ())


def _relevant_exec(event: Mapping[str, Any], effect: str) -> bool:
    return not event.get("via_symlink") and event.get("op") == "process" and bool(event.get("names_canary")) and bool(event.get("sink_named"))


def _relevant_sql(event: Mapping[str, Any], effect: str) -> bool:
    return (not event.get("via_symlink") and event.get("op") == "sql_read" and event.get("column") == "token"
            and bool(event.get("declared_db")) and event.get("database") == "main")


def _relevant_connect(event: Mapping[str, Any], effect: str) -> bool:
    return not event.get("via_symlink") and (
        event.get("op") in ("request", "connect") or event.get("access") in ("network", "connect")
    )


def _relevant_dos(event: Mapping[str, Any], effect: str) -> bool:
    return not event.get("via_symlink") and (event.get("op") == "dos" or event.get("access") == "cpu")


def _relevant_generic(event: Mapping[str, Any], effect: str) -> bool:
    """Documented generic fallback for an effect added later.

    Accepts any event that did not traverse a symlink and has admitted stack frames
    or an access/op matching the effect.
    """
    if event.get("via_symlink"):
        return False
    if event.get("effect") == effect or event.get("type") == effect or event.get("op") == effect:
        return True
    return bool(event.get("access")) or event.get("op") in ("open", "process", "sql_read", "connect", "request", "dos")


_RELEVANT_RULES: dict[str, Callable[[Mapping[str, Any], str], bool]] = {
    "canary_read": _relevant_file,
    "canary_write": _relevant_file,
    "canary_exec": _relevant_exec,
    "canary_sql": _relevant_sql,
    "canary_connect": _relevant_connect,
    "canary_dos": _relevant_dos,
}


def _relevant(event: Mapping[str, Any], effect: str) -> bool:
    """Whether the event is a kind this effect is proven with (as the oracle's judge sees it)."""
    rule = _RELEVANT_RULES.get(effect, _relevant_generic)
    return rule(event, effect)


def _extract_connect_facts(event: Mapping[str, Any], events: Sequence[Any]) -> dict[str, Any]:
    host = ""
    port = None
    raw_path = ""
    if event.get("url"):
        try:
            u = urlsplit(str(event["url"]))
            host = u.hostname or ""
            port = u.port
            raw_path = u.path or ""
        except Exception:
            raw_path = str(event["url"])
    if event.get("host"):
        host = host or str(event["host"])
    if event.get("port") is not None:
        try:
            port = port if port is not None else int(event["port"])
        except (ValueError, TypeError):
            pass
    if not host or port is None:
        for ev in events:
            if not isinstance(ev, Mapping):
                continue
            if not host and ev.get("host"):
                host = str(ev["host"])
            if port is None and ev.get("port") is not None:
                try:
                    port = int(ev["port"])
                except (ValueError, TypeError):
                    pass
    pclass = str(event.get("path_class") or "")
    if not pclass:
        target = raw_path or str(event.get("requested") or event.get("path") or "")
        p = target
        if "://" in p:
            try:
                p = urlsplit(p).path
            except Exception:
                pass
        parts = [seg for seg in p.strip("/").split("/") if seg]
        if not parts:
            pclass = "/"
        elif len(parts[0]) >= 16 and all(c in "0123456789abcdefABCDEF" for c in parts[0]):
            sub = "/".join(parts[1:])
            pclass = "canary" if not sub else f"canary/{sub}"
        elif "canary" in parts[0].lower():
            pclass = "canary"
        else:
            pclass = "/" + parts[0]
    return {
        "target_host": host.lower() if host else "",
        "target_port": port,
        "path_class": pclass,
        "access": str(event.get("access") or "network"),
    }


def _extract_dos_facts(event: Mapping[str, Any], sink: AppFrame) -> dict[str, Any]:
    family = str(event.get("input_family") or "")
    if not family:
        cmd = str(event.get("command") or "")
        if "=" in cmd:
            try:
                m_len = int(cmd.split("=")[0])
                family = "redos" if m_len <= 100 else "quadratic"
            except ValueError:
                family = cmd
        elif cmd:
            family = cmd
        else:
            family = "dos"
    return {
        "input_family": family,
        "cpu_function": sink.qualname,
        "access": str(event.get("access") or "cpu"),
    }


def proof_facts(
    evidence: Mapping[str, Any],
    *,
    roots: Iterable[str] = (),
    entry_points: Collection[str] | None = None,
    allow_unregistered: bool = False,
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
    if not isinstance(effect, str) or not effect:
        return None
    if not allow_unregistered and effect not in EFFECTS:
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
        extra: dict[str, Any] = {}
        if effect == "canary_connect":
            extra = _extract_connect_facts(event, events)
        elif effect == "canary_dos":
            extra = _extract_dos_facts(event, sink)
        access = extra.pop("access", str(event.get("access") or ""))
        return ProofFacts(
            effect=effect, access=access, chain=tuple(chain), line=sink.line,
            **extra,
        )
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
        family = proof.input_family
        if proof.effect == "canary_dos" and (not family or family == "dos"):
            family = first.vuln_class
        return replace(
            proof, line=lines[0], line_source=GRAPH_SINK_CALL, sink_call=first.target[:_MAX_TEXT],
            other_sink_lines=tuple(lines[1:6]), input_family=family,
        )
    return proof


# -- grouping --------------------------------------------------------------------------------


def _key_connect(facts: Mapping[str, Any], frames: tuple) -> tuple:
    host = str(facts.get("target_host") or "")
    port = facts.get("target_port")
    pclass = str(facts.get("path_class") or "")
    return ("canary_connect", host, port, pclass, frames)


def _key_dos(facts: Mapping[str, Any], frames: tuple) -> tuple:
    cpu_fn = str(facts.get("cpu_function") or (frames[-1][1] if frames else ""))
    family = str(facts.get("input_family") or "")
    return ("canary_dos", cpu_fn, family, frames)


def _key_generic(facts: Mapping[str, Any], frames: tuple) -> tuple:
    """Explicit generic fallback: effect + observed app frame chain."""
    return (str(facts.get("effect") or ""), frames)


_KEY_BUILDERS: dict[str, Callable[[Mapping[str, Any], tuple], tuple]] = {
    "canary_read": _key_generic,
    "canary_write": _key_generic,
    "canary_exec": _key_generic,
    "canary_sql": _key_generic,
    "canary_connect": _key_connect,
    "canary_dos": _key_dos,
}


def proof_key(facts: Mapping[str, Any] | None, *, allow_unregistered: bool = False) -> tuple | None:
    """The identity of a proof: table-driven by effect with an explicit documented generic fallback."""
    if not isinstance(facts, Mapping):
        return None
    effect = facts.get("effect")
    if not isinstance(effect, str) or not effect:
        return None
    if not allow_unregistered and effect not in EFFECTS:
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
    builder = _KEY_BUILDERS.get(effect, _key_generic)
    return builder(facts, tuple(frames))


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
