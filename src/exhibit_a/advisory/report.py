"""Turn pinned dependencies plus OSV candidates into `AdvisoryMatch` records."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from ..schemas.advisory import ADVISORY_SCHEMA_VERSION, AdvisoryMatch, Severity
from .deps import PinnedDependency
from .osv import ECOSYSTEM, Advisory, OsvBackend, evaluate
from .reachability import reachability_hint
from .version import InvalidVersion, Version, upgrade_kind


@dataclass
class AdvisoryReport:
    """All matches for one lookup, plus counts of what was looked at and dropped."""

    matches: list[AdvisoryMatch]
    data_source: str
    packages_checked: int
    candidates_seen: int
    not_affected: int  # candidates whose ranges exclude the installed version
    unevaluable: int  # recorded candidates with no range that could be checked
    withdrawn: int
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "schema_version": ADVISORY_SCHEMA_VERSION,
            "data_source": self.data_source,
            "packages_checked": self.packages_checked,
            "candidates_seen": self.candidates_seen,
            "not_affected": self.not_affected,
            "unevaluable": self.unevaluable,
            "withdrawn": self.withdrawn,
            "notes": self.notes,
            "matches": [m.model_dump(mode="json") for m in self.matches],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def _smallest(versions: tuple[str, ...]) -> str | None:
    parsed = []
    for text in versions:
        try:
            parsed.append((Version.parse(text), text))
        except InvalidVersion:
            continue  # SEMVER-only fix strings that are not PEP 440 are left out
    return min(parsed)[1] if parsed else None


def _match(dep: PinnedDependency, adv: Advisory, backend: OsvBackend,
           project_root: str | os.PathLike | None,
           import_names: dict[str, list[str]] | None) -> AdvisoryMatch | str:
    """Return the match, or 'not_affected' / 'unevaluable' when there is none."""
    entries = [p for p in adv.affected if p.name == dep.name and p.ecosystem == ECOSYSTEM]
    affected_flags: list[bool | None] = []
    fixes: list[str] = []
    notes: list[str] = []
    symbols: list[str] = []
    for entry in entries:
        result = evaluate(entry, dep.version)
        affected_flags.append(result.affected)
        fixes.extend(result.fixed_versions)
        notes.extend(result.notes)
        symbols.extend(entry.symbols)
    if True in affected_flags:
        status = "affected"
    elif entries and all(flag is None for flag in affected_flags) and backend.source == "live":
        # The live service says this version is affected but gave no range we can check.
        status = "unverified"
        notes.append("OSV returned this advisory but no range could be evaluated locally")
    elif any(flag is False for flag in affected_flags):
        return "not_affected"
    else:
        return "unevaluable"
    fixed_in = _smallest(tuple(dict.fromkeys(fixes)))
    kind = None
    if fixed_in is not None:
        try:
            kind = upgrade_kind(Version.parse(dep.version), Version.parse(fixed_in))
        except InvalidVersion:
            notes.append("installed version is not PEP 440; upgrade size not classified")
    if dep.marker:
        notes.append(f"environment marker not evaluated: {dep.marker}")
    evidence = [backend.evidence_url(adv.id)] + [u for u in adv.references]
    hint = None
    if project_root is not None:
        names = (import_names or {}).get(dep.name)
        hint = reachability_hint(project_root, dep.name, tuple(dict.fromkeys(symbols)), names)
    return AdvisoryMatch(
        package=dep.name,
        installed_version=dep.version,
        dependency_source=dep.source,
        advisory_id=adv.id,
        aliases=list(adv.aliases),
        summary=adv.summary,
        severity=[Severity(**s) for s in adv.severity],
        affected_status=status,
        fixed_in=fixed_in,
        patch_available=fixed_in is not None,
        upgrade_kind=kind,
        upgrade_is_minor_or_major=None if kind is None else kind in {"minor", "major"},
        evidence_urls=list(dict.fromkeys(evidence)),
        data_source=backend.source,
        advisory_modified=adv.modified,
        notes=list(dict.fromkeys(notes)),
        reachability=hint,
    )


def lookup(dependencies: list[PinnedDependency], backend: OsvBackend, *,
           project_root: str | os.PathLike | None = None,
           import_names: dict[str, list[str]] | None = None) -> AdvisoryReport:
    """Find advisories affecting each pinned dependency.

    `project_root`, when given, adds a static reachability hint to every match.
    `import_names` maps a normalized project name to its import names when they differ
    (for example ``{"pyyaml": ["yaml"]}``).
    """
    keys = list(dict.fromkeys((d.name, d.version) for d in dependencies))
    candidates = backend.query(keys)
    matches: list[AdvisoryMatch] = []
    seen = not_affected = unevaluable = withdrawn = 0
    reported: set[tuple[str, str, str]] = set()
    for dep in dependencies:
        for adv in candidates.get((dep.name, dep.version), []):
            if (dep.name, dep.version, adv.id) in reported:
                continue
            seen += 1
            if adv.withdrawn:
                withdrawn += 1
                continue
            match = _match(dep, adv, backend, project_root, import_names)
            if match == "not_affected":
                not_affected += 1
                continue
            if match == "unevaluable":
                unevaluable += 1
                continue
            reported.add((dep.name, dep.version, adv.id))
            matches.append(match)
    notes = ["advisory matches are a second signal; none of them is a proven finding"]
    if backend.source == "recorded":
        notes.append("data came from recorded records, not from a live OSV query")
    if unevaluable:
        notes.append(f"{unevaluable} candidate(s) had no range that could be evaluated locally")
    return AdvisoryReport(matches, backend.source, len(keys), seen, not_affected,
                          unevaluable, withdrawn, notes)
