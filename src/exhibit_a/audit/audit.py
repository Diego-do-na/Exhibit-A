"""Whole-repository audit orchestration.

This module builds the static call graph of a repository, ranks every reach
path the graph finds, groups paths by sink, and runs the normal verification
loop on the top targets. The loop is the same code path ``exhibit-a run
--slice`` uses: :class:`exhibit_a.loop.pipeline.VerificationLoop` with a
:class:`exhibit_a.graph.slicer.SlicePlan` from
:func:`exhibit_a.graph.slicer.make_plan`. Nothing of that path is copied here;
it is imported and called.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Same code path as `exhibit-a run --slice`: imported, not copied.
from exhibit_a.graph import build_graph, find_paths
from exhibit_a.graph.slicer import make_plan
from exhibit_a.ledger import Ledger
from exhibit_a.loop.pipeline import Roles, VerificationLoop
from exhibit_a.models import BudgetExceeded
from exhibit_a.models.cost import CostMeter
from exhibit_a.schemas.graph import CodeGraph

from .rank import AuditTarget, group_by_sink, rank_key

RolesFactory = Callable[[CostMeter | None], Roles]
RunnerFactory = Callable[[], Any]


@dataclass
class AuditOutcome:
    """What the audit tried, proved, and left untried."""

    repo: str
    targets: list[AuditTarget] = field(default_factory=list)
    tried: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    untried: list[dict[str, Any]] = field(default_factory=list)
    spent_usd: float = 0.0
    budget_usd: float | None = None
    stopped: str = "completed"
    started_ts: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "started": self.started_ts,
            "stopped": self.stopped,
            "budget_usd": self.budget_usd,
            "spent_usd": round(self.spent_usd, 6),
            "targets_ranked": len(self.targets),
            "targets_tried": len(self.tried),
            "targets": [t.to_json() | {"rank": list(t.rank)} for t in self.targets],
            "tried": self.tried,
            "findings": self.findings,
            "untried": self.untried,
        }


def collect_targets(
    repo: str | Path,
    *,
    declared: list[str] | tuple[str, ...] = (),
) -> tuple[CodeGraph, list[AuditTarget]]:
    """Build the graph of ``repo`` and rank every provable reach path by sink.

    Every callable of the repository counts as changed: with no diff, the
    search in :func:`exhibit_a.graph.find_paths` runs from each function and
    method, so the report holds every entry-point-to-sink path. Only paths to
    a sink the oracle can prove (``sink.effect`` is set) become targets.
    """
    root = Path(repo)
    graph = build_graph(root)
    changed = sorted(
        {n.id for n in graph.nodes if n.kind in ("function", "method")}
    )
    report = find_paths(graph, changed, declared_entries=list(declared))
    provable = [p for p in report.paths if p.sink.effect is not None]
    provable.sort(key=rank_key)
    return graph, group_by_sink(graph, provable)


def _slug(value: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in value).strip(".") or "target"


def run_audit(
    repo: str | Path,
    out: str | Path,
    *,
    budget_usd: float | None,
    max_targets: int = 10,
    roles_factory: RolesFactory,
    runner_factory: RunnerFactory,
    baseline: str = ".",
    profile: str = "standard",
    declared: list[str] | tuple[str, ...] = (),
) -> AuditOutcome:
    """Audit ``repo`` with the normal verification loop and write the outputs.

    The top ``max_targets`` sink groups run through
    :class:`VerificationLoop` with a slice plan, sharing one
    :class:`CostMeter` so the budget is never exceeded by more than one model
    call: the meter is checked before each target starts, and a target already
    running may be the one call that spends past it. Writes ``audit.json`` and
    ``audit.md`` into ``out`` and returns the outcome.
    """
    if max_targets < 1:
        raise ValueError("max_targets must be at least 1")
    repo_path = Path(repo).resolve()
    out_path = Path(out).resolve()
    out_path.mkdir(parents=True, exist_ok=True)
    graph, targets = collect_targets(repo_path, declared=declared)
    meter = CostMeter(budget_usd) if budget_usd is not None else None
    ledger = Ledger(out_path / "ledger.jsonl")
    outcome = AuditOutcome(
        repo=str(repo_path),
        targets=targets,
        budget_usd=budget_usd,
        started_ts=datetime.now(timezone.utc).isoformat(),
    )
    chosen = targets[:max_targets]
    for index, target in enumerate(chosen):
        if meter is not None:
            try:
                meter.check()
            except BudgetExceeded:
                outcome.stopped = "budget"
                break
        plan = make_plan(graph, repo_path, list(target.paths))
        if plan is None:  # pragma: no cover - group_by_sink never yields this
            continue
        roles = roles_factory(meter)
        runner = runner_factory()
        loop = VerificationLoop(
            repo_path,
            out_path,
            ledger,
            roles,
            baseline,
            run_id=f"audit-{index}-{_slug(target.sink_node)}",
            runner=runner,
            effect=target.effect,
            prompt_profile=profile,
            slice_plan=plan,
        )
        tried_entry: dict[str, Any] = {
            "sink": target.sink_key,
            "effect": target.effect,
            "vuln_class": target.vuln_class,
            "source_file": target.source_file,
            "run_id": loop.run_id,
        }
        try:
            result = loop.run(target.source_file)
        except BudgetExceeded:
            tried_entry["status"] = "budget_exceeded"
            outcome.tried.append(tried_entry)
            outcome.stopped = "budget"
            break
        except Exception as exc:  # model/runner failure aborts this target only
            tried_entry["status"] = f"error: {exc}"
            outcome.tried.append(tried_entry)
            continue
        if result.aborted and "baseline" in result.aborted:
            tried_entry["status"] = f"aborted: {result.aborted}"
            outcome.tried.append(tried_entry)
            continue
        tried_entry["status"] = "completed"
        tried_entry["proven"] = len(result.proven)
        outcome.tried.append(tried_entry)
        for proven in result.findings:
            outcome.findings.append(
                {
                    "suspicion_id": proven.suspicion.id,
                    "effect": target.effect,
                    "vuln_class": target.vuln_class,
                    "entry_point": (proven.facts or {}).get(
                        "entry_point", target.paths[0].oracle_entry_point
                    ),
                    "sink": target.sink_key,
                    "source_file": target.source_file,
                    "package": str(proven.package_dir) if proven.package_dir else "",
                    "run_id": loop.run_id,
                }
            )
    if meter is not None:
        outcome.spent_usd = meter.total_usd
    if outcome.stopped != "budget" and len(chosen) < len(targets):
        rest = len(targets) - len(chosen)
        if max_targets is not None and rest > 0 and outcome.stopped == "completed":
            outcome.stopped = "max_targets"
    if outcome.stopped == "completed" and meter is not None:
        try:
            meter.check()
        except BudgetExceeded:  # pragma: no cover - exact-spend edge
            outcome.stopped = "budget"
    tried_sinks = {t.get("sink") for t in outcome.tried}
    for target in targets:
        if target.sink_key not in tried_sinks:
            outcome.untried.append(
                {
                    "sink": target.sink_key,
                    "effect": target.effect,
                    "vuln_class": target.vuln_class,
                    "source_file": target.source_file,
                    "reason": "not attempted: ranked below the budget/max-targets cut",
                }
            )
    (out_path / "audit.json").write_text(
        json.dumps(outcome.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_path / "audit.md").write_text(render_markdown(outcome), encoding="utf-8")
    return outcome


def render_markdown(outcome: AuditOutcome) -> str:
    """Human-readable audit summary: tried targets, proven findings, untried."""
    lines = [
        "# Exhibit A audit",
        "",
        f"Repository: `{outcome.repo}`",
        "",
        f"Targets ranked: {len(outcome.targets)}. "
        f"Targets tried: {len(outcome.tried)}. "
        f"Proven findings: {len(outcome.findings)}. "
        f"Stopped: {outcome.stopped}.",
        "",
        "A green audit means nothing could be proven, never safe.",
        "",
        "## Targets tried",
        "",
    ]
    if not outcome.tried:
        lines.append("No target was tried (nothing reachable, or --list-only).")
    else:
        lines.append("| # | Sink | Effect | Status |")
        lines.append("| --- | --- | --- | --- |")
        for i, tried in enumerate(outcome.tried, 1):
            lines.append(
                f"| {i} | `{tried.get('sink', '')}` | {tried.get('effect', '')} "
                f"| {tried.get('status', '')} |"
            )
    lines += ["", "## Proven findings", ""]
    if not outcome.findings:
        lines.append("No finding was proven: nothing could be proven.")
    else:
        lines.append("| Suspicion | Effect | Entry point | Sink | Package |")
        lines.append("| --- | --- | --- | --- | --- |")
        for found in outcome.findings:
            lines.append(
                f"| {found.get('suspicion_id', '')} | {found.get('effect', '')} "
                f"| `{found.get('entry_point', '')}` | `{found.get('sink', '')}` "
                f"| `{found.get('package', '')}` |"
            )
    lines += ["", "## Untried paths", ""]
    if not outcome.untried:
        lines.append("Every ranked target was tried.")
    else:
        lines.append(
            f"{len(outcome.untried)} ranked target(s) were not attempted "
            "(budget or --max-targets cut). The most important first:"
        )
        lines.append("")
        for item in outcome.untried[:50]:
            lines.append(
                f"- `{item['sink']}` [{item['effect']}] ({item['vuln_class']}) — {item['reason']}"
            )
        if len(outcome.untried) > 50:
            lines.append(f"- ... and {len(outcome.untried) - 50} more (see audit.json).")
    lines.append("")
    return "\n".join(lines)
