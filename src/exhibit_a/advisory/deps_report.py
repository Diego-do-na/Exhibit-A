"""``exhibit-a deps``: advisories for pinned dependencies, graph reachability, optional proof.

1. Pinned dependencies come from ``--requirements``, else ``requirements.txt``,
   ``pyproject.toml`` or a corpus ``case.json`` (``run.requirements``) in the repository.
2. OSV (live, or a recorded fixture) proposes advisories; whether the pinned version is
   affected is re-evaluated locally from the record's ranges (``report._match``).
3. The repository's static call graph is built once (``ast`` only: repository code is never
   imported or run here) and each advisory's affected symbols are searched for on paths
   from the application's entry points (``graph_reach``).
4. With ``prove``, each reachable advisory whose class maps to an oracle effect and that has
   a fixed version runs through the proof loop (``proof.prove``) in the sandbox.

Nothing here calls a model unless ``prove`` is set. ``reachable`` is not a finding; only a
``proven`` proof is, and everything else means "nothing could be proven".
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..graph import build_graph, find_entries
from ..ledger import Ledger
from ..loop.pipeline import Roles
from ..models import BudgetExceeded
from ..models.cost import CostMeter
from ..schemas.advisory import (
    AdvisoryMatch,
    DependencyAdvisory,
    DependencyProof,
    DependencyRef,
    DepsCounts,
    DepsReport,
    GraphSummary,
    ProveSettings,
    UnsupportedRef,
)
from ..schemas.graph import CodeGraph
from .deps import PinnedDependency, Unsupported, parse_pyproject, parse_requirement, parse_requirements
from .graph_reach import dependency_reach
from .osv import Advisory, OsvBackend
from .proof import ProofRequest, advisory_block, default_installer, default_runner_factory, prove
from .reachability import default_import_names, reachability_hint
from .report import _match
from .symbols import affected_symbols, severity_label

DEPS_JSON = "deps.json"


@dataclass
class Inputs:
    dependencies: list[PinnedDependency]
    unsupported: list[Unsupported]
    files: list[str]
    declared_entries: list[str] = field(default_factory=list)


def _rel(path: Path, repo: Path) -> str:
    """Repository-relative label of a dependency file, or its absolute path when outside."""
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _parse_file(path: Path, label: str) -> tuple[list[PinnedDependency], list[Unsupported]]:
    text = path.read_text(encoding="utf-8")
    result = parse_pyproject(text, label) if path.name.endswith(".toml") else parse_requirements(text, label)
    return result.dependencies, result.unsupported


def discover(repo: str | Path, requirements: str | Path | None = None) -> Inputs:
    """Pinned dependencies of ``repo`` (see the module docstring for the search order)."""
    repo = Path(repo)
    if requirements is not None:
        path = Path(requirements)
        if not path.is_file() and (repo / path).is_file():
            path = repo / path
        deps, unsupported = _parse_file(path, _rel(path, repo))
        return Inputs(deps, unsupported, [_rel(path, repo)], _declared(repo))
    deps: list[PinnedDependency] = []
    unsupported: list[Unsupported] = []
    files: list[str] = []
    for name in ("requirements.txt", "pyproject.toml"):
        path = repo / name
        if path.is_file() and not path.is_symlink():
            found, bad = _parse_file(path, name)
            deps.extend(found)
            unsupported.extend(bad)
            files.append(name)
    case = repo / "case.json"
    if not files and case.is_file() and not case.is_symlink():
        settings = json.loads(case.read_text(encoding="utf-8")).get("run") or {}
        items = settings.get("requirements") if isinstance(settings, dict) else None
        for index, item in enumerate(items if isinstance(items, list) else []):
            source = f"case.json:run.requirements[{index}]"
            if not isinstance(item, str):
                unsupported.append(Unsupported(repr(item), source, "non-string entry"))
                continue
            result = parse_requirement(item, source)
            (deps if isinstance(result, PinnedDependency) else unsupported).append(result)
        files.append("case.json")
    return Inputs(deps, unsupported, files, _declared(repo))


def _declared(repo: Path) -> list[str]:
    """``case.json`` ``run.entry_points``, which win over detection as in ``run --slice``."""
    case = repo / "case.json"
    try:
        settings = json.loads(case.read_text(encoding="utf-8")).get("run") or {}
    except (OSError, ValueError, AttributeError):
        return []
    names = settings.get("entry_points") if isinstance(settings, dict) else None
    return [n for n in names if isinstance(n, str)] if isinstance(names, list) else []


@dataclass
class Scan:
    report: DepsReport
    graph: CodeGraph
    advisories: dict[int, Advisory]  # index in report.advisories -> the OSV record
    inputs: Inputs


def _fixed_by(fixed_in: str | None, proof: DependencyProof) -> str:
    if fixed_in is None:
        return "no fixed version"
    if proof.status == "proven":
        return f"upgrade to {fixed_in} (verified)" if proof.upgrade_verified else \
            f"upgrade to {fixed_in} + app patch (verified)"
    if proof.status in ("not_proven", "error"):
        return f"upgrade to {fixed_in} (not verified)"
    return f"upgrade to {fixed_in}"


def _entry(match: AdvisoryMatch, adv: Advisory, reach, info, proof: DependencyProof) -> DependencyAdvisory:
    return DependencyAdvisory(
        advisory_id=match.advisory_id, aliases=match.aliases, package=match.package,
        installed_version=match.installed_version, dependency_source=match.dependency_source,
        summary=match.summary, severity=match.severity, severity_label=severity_label(adv),
        affected_status=match.affected_status, fixed_in=match.fixed_in, upgrade_kind=match.upgrade_kind,
        evidence_urls=match.evidence_urls, vuln_class=info.vuln_class, effect=info.effect,
        reachability=reach, proof=proof, fixed_by=_fixed_by(match.fixed_in, proof),
    )


def scan(
    repo: str | Path,
    backend: OsvBackend,
    *,
    requirements: str | Path | None = None,
    include_tests: bool = False,
    repo_label: str | None = None,
) -> Scan:
    """Advisories plus graph reachability for every pinned dependency; no model is called."""
    root = Path(repo)
    inputs = discover(root, requirements)
    keys = list(dict.fromkeys((d.name, d.version) for d in inputs.dependencies))
    candidates = backend.query(keys) if keys else {}
    graph = build_graph(root)
    entries, _ = find_entries(graph, inputs.declared_entries)
    notes = ["reachable is not a finding: only a proven proof is; anything else means nothing could be proven"]
    if backend.source == "recorded":
        notes.append("advisory data came from recorded records, not from a live OSV query")
    notes.extend(getattr(backend, "warnings", []))
    items: list[DependencyAdvisory] = []
    records: dict[int, Advisory] = {}
    seen: set[tuple[str, str, str]] = set()
    for dep in inputs.dependencies:
        for adv in candidates.get((dep.name, dep.version), []):
            key = (dep.name, dep.version, adv.id)
            if key in seen or adv.withdrawn:
                continue
            match = _match(dep, adv, backend, None, None)
            if isinstance(match, str):
                continue  # not_affected / unevaluable: the installed version is not shown affected
            seen.add(key)
            info = affected_symbols(adv, dep.name)
            names = sorted(set(default_import_names(dep.name)) | {s.split(".", 1)[0] for s in info.symbols})
            hint = reachability_hint(root, dep.name, info.symbols, names)
            reach = dependency_reach(
                graph, info, include_tests=include_tests, declared_entries=inputs.declared_entries,
                package_imported=hint.package_imported, import_sites=hint.import_sites,
            )
            proof = DependencyProof(status="not_attempted", reason="--prove was not given", effect=info.effect)
            records[len(items)] = adv
            items.append(_entry(match, adv, reach, info, proof))
    report = DepsReport(
        repo=repo_label if repo_label is not None else str(repo),
        generated_at=datetime.now(timezone.utc).isoformat(),
        data_source="recorded" if backend.source == "recorded" else "live",
        dependency_files=inputs.files,
        dependencies=[DependencyRef(name=d.name, version=d.version, source=d.source) for d in inputs.dependencies],
        unsupported=[UnsupportedRef(text=u.text, source=u.source, reason=u.reason) for u in inputs.unsupported],
        include_tests=include_tests,
        graph=GraphSummary(
            files=graph.stats.files, nodes=graph.stats.nodes, edges=graph.stats.edges,
            external=graph.stats.external, unresolved=graph.stats.unresolved, entry_points=len(entries),
            truncated=graph.truncated, skipped=len(graph.skipped),
        ),
        prove=ProveSettings(requested=False),
        counts=_counts(items),
        advisories=items,
        notes=notes,
    )
    return Scan(report, graph, records, inputs)


def _counts(items: list[DependencyAdvisory]) -> DepsCounts:
    status = [i.reachability.status for i in items]
    return DepsCounts(
        advisories=len(items), reachable=status.count("reachable"), not_reachable=status.count("not_reachable"),
        unknown=status.count("unknown"), proven=sum(1 for i in items if i.proof.status == "proven"),
    )


def prove_reachable(
    result: Scan,
    repo: str | Path,
    out: str | Path,
    roles_factory: Callable[[CostMeter | None], Roles],
    *,
    budget_usd: float | None,
    profile: str = "compact",
    provider: str | None = None,
    model: str | None = None,
    baseline: str | None = None,
    installer=default_installer,
    runner_factory=default_runner_factory,
    runs: int = 3,
    timeout: float = 120.0,
) -> DepsReport:
    """Run the proof loop for every reachable, provable advisory, under one budget."""
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    meter = CostMeter(budget_usd) if budget_usd is not None else None
    roles = roles_factory(meter)
    ledger = Ledger(out / "ledger.jsonl")
    pins = [f"{d.name}=={d.version}" for d in result.inputs.dependencies]
    items = list(result.report.advisories)
    for index, item in enumerate(items):
        skip = None
        if item.reachability.status != "reachable":
            skip = f"not attempted: reachability is {item.reachability.status}"
        elif item.effect is None:
            skip = f"no oracle effect can observe {item.vuln_class or 'this class'} today"
        elif item.fixed_in is None:
            skip = "no fixed version: there is no upgrade to verify"
        elif meter is not None:
            try:
                meter.check()
            except BudgetExceeded:
                skip = "budget spent before this advisory"
        if skip is not None:
            proof = DependencyProof(status="skipped", reason=skip, effect=item.effect)
        else:
            adv = result.advisories[index]
            details = adv.raw.get("details") if isinstance(adv.raw.get("details"), str) else ""
            info = affected_symbols(adv, item.package)
            request = ProofRequest(
                advisory_id=item.advisory_id, package=item.package, installed_version=item.installed_version,
                fixed_in=item.fixed_in, dependency_source=item.dependency_source,
                vuln_class=item.vuln_class or "dependency", effect=item.effect,
                paths=list(item.reachability.paths),
                advisory_text=advisory_block(item.advisory_id, item.package, item.installed_version,
                                             item.fixed_in, item.summary, details, info.note),
                requirements=pins, baseline=baseline,
            )
            proof = prove(repo, out, result.graph, request, roles, ledger=ledger, installer=installer,
                          runner_factory=runner_factory, profile=profile, runs=runs, timeout=timeout)
        items[index] = item.model_copy(update={"proof": proof, "fixed_by": _fixed_by(item.fixed_in, proof)})
    spent = meter.total_usd if meter is not None else sum(i.proof.cost_usd for i in items)
    report = result.report.model_copy(update={
        "advisories": items,
        "counts": _counts(items),
        "prove": ProveSettings(requested=True, profile=profile, provider=provider, model=model,
                               budget_usd=budget_usd, spent_usd=round(spent, 6)),
    })
    result.report = report
    return report


def write_report(report: DepsReport, out: str | Path) -> Path:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    target = out / DEPS_JSON
    target.write_text(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    return target


_PROOF_CELL = {"not_attempted": "-", "skipped": "skipped", "proven": "PROVEN", "not_proven": "not proven",
               "error": "error"}


def render_table(report: DepsReport) -> str:
    """advisory | package version | severity | reachable? | proven? | fixed by, then details."""
    headers = ["ADVISORY", "PACKAGE VERSION", "SEVERITY", "REACHABLE?", "PROVEN?", "FIXED BY"]
    rows = []
    for item in report.advisories:
        reach = item.reachability
        cell = {"reachable": f"yes ({len(reach.paths)} path{'s' if len(reach.paths) != 1 else ''})",
                "not_reachable": "no", "unknown": "unknown"}[reach.status]
        rows.append([item.advisory_id, f"{item.package} {item.installed_version}", item.severity_label, cell,
                     _PROOF_CELL[item.proof.status], item.fixed_by])
    lines = []
    if rows:
        widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
        lines.append("  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip())
        lines.append("  ".join("-" * w for w in widths))
        lines.extend("  ".join(v.ljust(w) for v, w in zip(row, widths)).rstrip() for row in rows)
        lines.append("")
        for item in report.advisories:
            reach = item.reachability
            lines.append(f"{item.advisory_id} ({item.package} {item.installed_version}): {reach.status}")
            if reach.paths:
                for path in reach.paths[:3]:
                    lines.append(f"  path [{path.kind}, entry {path.oracle_entry_point}]: {path.rendered}")
            else:
                lines.append(f"  {reach.reason}")
            if item.proof.status != "not_attempted":
                lines.append(f"  proof: {item.proof.status}: {item.proof.reason}")
                if item.proof.package:
                    lines.append(f"  package: {item.proof.package}")
    else:
        lines.append("No advisory affects a pinned dependency.")
    counts = report.counts
    lines.append("")
    lines.append(f"{counts.advisories} advisor{'y' if counts.advisories == 1 else 'ies'}: {counts.reachable} reachable, "
                 f"{counts.not_reachable} not reachable, {counts.unknown} unknown, {counts.proven} proven "
                 f"({len(report.dependencies)} pinned dependencies, data: {report.data_source})")
    if report.unsupported:
        lines.append(f"{len(report.unsupported)} requirement(s) not checked (not exact pins); see deps.json")
    lines.append("Reachable is not a finding; not proven means nothing could be proven, never safe.")
    return "\n".join(lines)


def relative_label(repo: str | Path) -> str:
    """The repository as the user wrote it when relative, so deps.json carries no home path."""
    text = str(repo)
    home = str(Path.home())
    return "~" + text[len(home):] if os.path.isabs(text) and text.startswith(home + os.sep) else text


__all__ = ["DEPS_JSON", "Inputs", "Scan", "discover", "prove_reachable", "relative_label", "render_table",
           "scan", "write_report"]
