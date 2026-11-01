"""CycloneDX 1.5 SBOM with VEX states derived from Exhibit A evidence.

The bill of materials lists the repository's pinned Python dependencies (exact
pins from ``requirements.txt``/``pyproject.toml``, versions as resolved) as
``components``. The ``vulnerabilities`` section carries one entry per advisory in
``deps.json`` with CVSS ratings from OSV when present, an EPSS rating when the
enrichment feed provided one, a KEV flag, and a CycloneDX ``analysis`` state:

* ``proof.status == "proven"`` -> ``exploitable`` (detail: the proof bundle path).
* ``reachability.status == "not_reachable"`` -> ``not_affected`` with justification
  ``code_not_reachable`` plus an honest caveat (graph coverage, not safety).
* anything else -> ``in_triage``.

``not_affected`` never comes from model text: only ``proof.status`` and
``reachability.status`` (both machine-computed) decide. A green SBOM means
"nothing could be proven", never "safe".
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..advisory.deps_report import discover
from ..advisory.enrich import Enrichment, ghsa_aliases
from ..schemas.advisory import DependencyAdvisory, DepsReport

BOM_FORMAT = "CycloneDX"
SPEC_VERSION = "1.5"
TOOL_VERSION = "0.1.0"

NOT_REACHABLE_CAVEAT = (
    "The static call graph found no path from any entry point to the affected "
    "symbol. The graph cannot see dynamic dispatch, monkeypatching, calls through "
    "another dependency, or non-Python entry points, so this is a coverage "
    "statement, not a proof of safety; any change to entry points, dependencies "
    "or pins can invalidate it."
)

KEV_TITLE = "CISA Known Exploited Vulnerabilities catalog"

_CVSS_METHODS = (
    ("CVSS_V4", "CVSSv4"),
    ("CVSS_V3", "CVSSv3"),
    ("CVSS_V2", "CVSSv2"),
)

_SEVERITIES = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "moderate",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _component_ref(name: str, version: str) -> str:
    return f"pkg:pypi/{name}@{version}"


def _cvss_method(severity_type: str) -> str:
    for prefix, method in _CVSS_METHODS:
        if severity_type.upper().startswith(prefix):
            return method
    return severity_type


def _severity_label(label: str | None) -> str | None:
    if not label:
        return None
    return _SEVERITIES.get(label.strip().upper())


def _primary_id(item: DependencyAdvisory) -> str:
    for alias in item.aliases:
        if alias.upper().startswith("CVE-"):
            return alias.upper()
    return item.advisory_id


def _bom_ref(item: DependencyAdvisory, duplicates: bool) -> str:
    if not duplicates:
        return item.advisory_id
    return f"{item.advisory_id}:{item.package}@{item.installed_version}"


def _ratings(item: DependencyAdvisory, enrichment: Enrichment | None) -> list[dict[str, Any]]:
    ratings: list[dict[str, Any]] = []
    for sev in item.severity:
        rating: dict[str, Any] = {
            "source": {"name": "OSV", "url": "https://osv.dev"},
            "method": _cvss_method(sev.type),
            "vector": sev.score,
        }
        level = _severity_label(item.severity_label)
        if level is not None:
            rating["severity"] = level
        ratings.append(rating)
    if enrichment is not None and enrichment.epss is not None:
        ratings.append({
            "source": {"name": "FIRST", "url": "https://www.first.org/epss"},
            "method": "EPSS",
            "score": enrichment.epss,
        })
    return ratings


def _advisories(item: DependencyAdvisory, enrichment: Enrichment | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    osv_url = next((u for u in item.evidence_urls if u.startswith("https://")), None)
    out.append({"title": f"OSV {item.advisory_id}",
                "url": osv_url or f"https://osv.dev/vulnerability/{item.advisory_id}"})
    for ghsa in ghsa_aliases([*item.aliases, item.advisory_id]):
        out.append({"title": f"GitHub Advisory {ghsa}",
                    "url": f"https://github.com/advisories/{ghsa}"})
    if enrichment is not None and enrichment.kev:
        from ..advisory.enrich import KEV_URL

        out.append({"title": KEV_TITLE, "url": KEV_URL})
    return out


def _references(item: DependencyAdvisory) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = [
        {"id": item.advisory_id, "source": {"name": "OSV",
         "url": f"https://osv.dev/vulnerability/{item.advisory_id}"}}
    ]
    for alias in item.aliases:
        upper = alias.upper()
        if upper.startswith("CVE-"):
            refs.append({"id": upper, "source": {"name": "NVD",
                         "url": f"https://nvd.nist.gov/vuln/detail/{upper}"}})
        elif alias in ghsa_aliases([alias]):
            refs.append({"id": alias, "source": {"name": "GitHub",
                         "url": f"https://github.com/advisories/{alias}"}})
        else:
            refs.append({"id": alias, "source": {"name": "OSV",
                         "url": f"https://osv.dev/vulnerability/{alias}"}})
    return refs


def analysis_for(item: DependencyAdvisory) -> dict[str, Any]:
    """CycloneDX ``analysis`` for one advisory, from proof/reachability states only."""
    proof = item.proof
    if proof.status == "proven":
        detail = f"Exhibit A proved this advisory through entry point {proof.entry_point}."
        if proof.package:
            detail += f" Proof bundle: {proof.package}."
        else:
            detail += " Proof bundle path not recorded."
        return {"state": "exploitable", "detail": detail.strip()}
    reach = item.reachability
    if reach.status == "not_reachable":
        detail = f"{reach.reason} {NOT_REACHABLE_CAVEAT}"
        if reach.blind_spots:
            detail += f" Blind spots: {'; '.join(reach.blind_spots)}"
        return {"state": "not_affected", "justification": "code_not_reachable",
                "detail": detail.strip()}
    if proof.status == "not_attempted":
        detail = ("Reachability was computed but the proof loop was not run "
                  "(--prove was not given); triage pending.")
    elif proof.status in ("not_proven", "error", "skipped"):
        detail = f"Exhibit A ran without a proof ({proof.status}): {proof.reason} Triage pending."
    else:  # pragma: no cover - defensive: future proof states stay in triage
        detail = f"Exhibit A status {proof.status}: {proof.reason} Triage pending."
    if reach.status == "unknown":
        detail += " The advisory names no affected symbol, so the graph has nothing to search for."
    return {"state": "in_triage", "detail": detail.strip()}


def generate_sbom(
    repo: str | Path,
    deps_report: DepsReport | None = None,
    enrichment: dict[str, Enrichment] | None = None,
    *,
    generated_at: str | None = None,
    tool_version: str = TOOL_VERSION,
) -> dict[str, Any]:
    """Build a CycloneDX 1.5 SBOM dict for ``repo``.

    Args:
        repo: repository directory whose pinned dependencies become ``components``.
        deps_report: a validated ``DepsReport`` (from ``deps.json``); its advisories
            become ``vulnerabilities``. Without it the SBOM lists components only.
        enrichment: advisory id -> :class:`Enrichment` (EPSS/KEV/GHSA). Without it,
            ratings carry CVSS only and no KEV flag is set.
        generated_at: metadata timestamp; defaults to now (UTC).
        tool_version: recorded under ``metadata.tools``.
    """
    root = Path(repo)
    inputs = discover(root)
    components = [{
        "type": "library",
        "bom-ref": _component_ref(dep.name, dep.version),
        "name": dep.name,
        "version": dep.version,
        "purl": _component_ref(dep.name, dep.version),
        "properties": [{"name": "exhibit-a:dependency-source", "value": dep.source}],
    } for dep in inputs.dependencies]
    ref_of = {dep.name: _component_ref(dep.name, dep.version) for dep in inputs.dependencies}

    vulnerabilities: list[dict[str, Any]] = []
    advisories = list(deps_report.advisories) if deps_report is not None else []
    seen_refs = [a.advisory_id for a in advisories]
    for item in advisories:
        duplicates = seen_refs.count(item.advisory_id) > 1
        enrich = (enrichment or {}).get(item.advisory_id)
        vuln: dict[str, Any] = {
            "bom-ref": _bom_ref(item, duplicates),
            "id": _primary_id(item),
            "source": {"name": "OSV",
                       "url": f"https://osv.dev/vulnerability/{item.advisory_id}"},
            "references": _references(item),
            "description": item.summary,
            "advisories": _advisories(item, enrich),
            "analysis": analysis_for(item),
            "affects": [{"ref": ref_of.get(item.package,
                                           _component_ref(item.package, item.installed_version))}],
        }
        ratings = _ratings(item, enrich)
        if ratings:
            vuln["ratings"] = ratings
        vuln["properties"] = [
            {"name": "exhibit-a:kev", "value": "true" if (enrich is not None and enrich.kev) else "false"},
            {"name": "exhibit-a:advisory-id", "value": item.advisory_id},
        ]
        if enrich is not None and enrich.epss_percentile is not None:
            vuln["properties"].append(
                {"name": "exhibit-a:epss-percentile", "value": str(enrich.epss_percentile)})
        vulnerabilities.append(vuln)

    sbom: dict[str, Any] = {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": generated_at or _utcnow(),
            "tools": [{"vendor": "Exhibit A", "name": "exhibit-a", "version": tool_version}],
            "component": {"type": "application", "name": root.name or str(root),
                          "bom-ref": f"pkg:local/{root.name or 'repo'}"},
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }
    validate_sbom(sbom)
    return sbom


def validate_sbom(data: Any) -> None:
    """Minimal structural check for the CycloneDX 1.5 fields this module writes."""
    if not isinstance(data, dict):
        raise ValueError("SBOM must be a JSON object")
    if data.get("bomFormat") != BOM_FORMAT:
        raise ValueError(f"SBOM bomFormat must be {BOM_FORMAT!r}")
    if data.get("specVersion") != SPEC_VERSION:
        raise ValueError(f"SBOM specVersion must be {SPEC_VERSION!r}")
    if not isinstance(data.get("version"), int):
        raise ValueError("SBOM version must be an integer")
    metadata = data.get("metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("timestamp"), str):
        raise ValueError("SBOM metadata.timestamp must be a string")
    if not isinstance(data.get("components"), list):
        raise ValueError("SBOM components must be an array")
    for index, component in enumerate(data["components"]):
        if not isinstance(component, dict):
            raise ValueError(f"components[{index}] must be an object")
        for key in ("type", "bom-ref", "name", "version"):
            if not isinstance(component.get(key), str) or not component[key]:
                raise ValueError(f"components[{index}].{key} must be a non-empty string")
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("SBOM vulnerabilities must be an array")
    for index, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            raise ValueError(f"vulnerabilities[{index}] must be an object")
        for key in ("bom-ref", "id"):
            if not isinstance(vuln.get(key), str) or not vuln[key]:
                raise ValueError(f"vulnerabilities[{index}].{key} must be a non-empty string")
        analysis = vuln.get("analysis")
        if not isinstance(analysis, dict) or analysis.get("state") not in (
                "exploitable", "in_triage", "not_affected", "resolved", "false_positive"):
            raise ValueError(f"vulnerabilities[{index}].analysis.state is missing or invalid")
        if analysis["state"] == "not_affected" and not isinstance(analysis.get("justification"), str):
            raise ValueError(f"vulnerabilities[{index}].analysis.justification is required "
                             "when not_affected")
        affects = vuln.get("affects")
        if not isinstance(affects, list) or not affects or not all(
                isinstance(a.get("ref"), str) for a in affects if isinstance(a, dict)):
            raise ValueError(f"vulnerabilities[{index}].affects must list component refs")
        for rating in vuln.get("ratings", []):
            if not isinstance(rating, dict) or not isinstance(rating.get("method"), str):
                raise ValueError(f"vulnerabilities[{index}].ratings entries need a method")


__all__ = ["BOM_FORMAT", "SPEC_VERSION", "TOOL_VERSION", "analysis_for", "generate_sbom",
           "validate_sbom"]
