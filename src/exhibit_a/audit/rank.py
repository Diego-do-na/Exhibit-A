"""Ranking of whole-repository reach paths for the audit.

Every path the static graph finds from an entry point to a sink the oracle can
prove is ranked by, in order:

1. sink severity by effect (execution/SQL first, then file write, then file read);
2. path length (fewer hops first);
3. entry-point exposure (network-reachable first, then declared, then CLI);
4. determinism tiebreakers (confidence, names, sink line).

Paths are grouped by sink so one sink is one audit target: the loop runs once
per sink group with a slice of that group's paths. The group's rank is its best
path's rank.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from exhibit_a.schemas.graph import CodeGraph, ReachPath

#: Lower is more severe. Sinks with ``effect=None`` cannot be proven and are
#: never ranked (they are filtered before grouping).
EFFECT_SEVERITY: dict[str, int] = {
    "canary_exec": 0,
    "canary_sql": 0,
    "canary_write": 1,
    "canary_read": 2,
}

#: Lower is more exposed to attacker input.
ENTRY_EXPOSURE: dict[str, int] = {
    "asgi": 0,
    "wsgi": 0,
    "route_decorator": 0,
    "route_table": 0,
    "django_view": 0,
    "request_handler": 0,
    "declared": 1,
    "cli_main": 2,
}


def effect_severity(effect: str | None) -> int:
    """Severity rank of an oracle effect; unprovable sinks sort last."""
    if effect is None:
        return 99
    return EFFECT_SEVERITY.get(effect, 50)


def entry_exposure(entry_kind: str) -> int:
    """Exposure rank of an entry-point kind; unknown kinds sort last."""
    return ENTRY_EXPOSURE.get(entry_kind, 3)


def rank_key(path: ReachPath) -> tuple:
    """Sort key for one reach path (lower is a better audit target)."""
    return (
        effect_severity(path.sink.effect),
        path.hops + path.returns,
        entry_exposure(path.entry_kind),
        path.unresolved_hops,
        round(1.0 - float(path.confidence), 6),
        path.entry,
        path.changed,
        path.sink.line,
        path.sink.target,
        path.sink.node,
    )


@dataclass
class AuditTarget:
    """One sink to audit: every ranked path that reaches it."""

    sink_key: str
    sink_node: str
    sink_target: str
    sink_line: int
    effect: str
    vuln_class: str
    source_file: str
    paths: tuple[ReachPath, ...] = field(default_factory=tuple)
    rank: tuple = field(default_factory=tuple)

    def to_json(self) -> dict[str, Any]:
        return {
            "sink": self.sink_key,
            "sink_node": self.sink_node,
            "sink_target": self.sink_target,
            "sink_line": self.sink_line,
            "effect": self.effect,
            "vuln_class": self.vuln_class,
            "source_file": self.source_file,
            "paths": [
                {
                    "entry": p.entry,
                    "entry_kind": p.entry_kind,
                    "oracle_entry_point": p.oracle_entry_point,
                    "changed": p.changed,
                    "hops": p.hops,
                    "returns": p.returns,
                    "confidence": p.confidence,
                    "vuln_class": p.vuln_class,
                }
                for p in self.paths
            ],
        }


def _sink_group_key(path: ReachPath) -> str:
    return f"{path.sink.node} -> {path.sink.target} (line {path.sink.line})"


def group_by_sink(
    graph: CodeGraph, paths: list[ReachPath]
) -> list[AuditTarget]:
    """Group provable paths by sink and rank the groups by their best path."""
    by_file = {node.id: node.file for node in graph.nodes}
    groups: dict[tuple[str, str, int], list[ReachPath]] = {}
    for path in paths:
        if path.sink.effect is None:
            continue
        groups.setdefault(
            (path.sink.node, path.sink.target, path.sink.line), []
        ).append(path)
    targets: list[AuditTarget] = []
    for (node, target, line), members in groups.items():
        ordered = tuple(sorted(members, key=rank_key))
        best = ordered[0]
        sink_file = by_file.get(node, "")
        if not sink_file:
            changed_node = next(
                (n for n in graph.nodes if n.id == best.changed), None
            )
            sink_file = changed_node.file if changed_node is not None else ""
        if not sink_file or not best.sink.effect:
            continue
        targets.append(
            AuditTarget(
                sink_key=_sink_group_key(best),
                sink_node=node,
                sink_target=target,
                sink_line=line,
                effect=str(best.sink.effect),
                vuln_class=best.vuln_class,
                source_file=sink_file,
                paths=ordered,
                rank=rank_key(best),
            )
        )
    targets.sort(key=lambda t: (t.rank, t.sink_key))
    return targets
