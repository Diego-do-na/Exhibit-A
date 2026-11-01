"""Which symbols an advisory says are affected, and which oracle effect could prove it.

Sources, in order:

1. the OSV record itself: ``affected[].ecosystem_specific`` and then
   ``affected[].database_specific`` for the package, in either of the two shapes seen in the
   wild (``imports: [{path, symbols}]``, the Go shape, and ``affected_functions: [...]``);
2. ``symbols.json`` next to this module, a hand-maintained map keyed by advisory id (or any
   alias) for advisories that name no symbol.

With neither, reachability is ``unknown``: the graph cannot look for a call it has no name
for. The vulnerability class and effect come from the map entry, else from the record's CWE
ids (``database_specific.cwe_ids``); an unknown class gets no effect, so the loop is never
asked to prove what the oracle cannot observe.

Advisory records are untrusted data: every value read here is type-checked and capped.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from .osv import Advisory

SYMBOL_MAP = Path(__file__).with_name("symbols.json")
MAX_SYMBOLS = 64
_DOTTED = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")

#: CWE id -> (vulnerability class, oracle effect). Path traversal maps to the read effect: a
#: write traversal is also caught by canary_read only when the app reads, so a wrong guess
#: costs recall, never a false proof.
CWE_CLASSES: dict[str, tuple[str, str | None]] = {
    "CWE-22": ("path_traversal", "canary_read"),
    "CWE-23": ("path_traversal", "canary_read"),
    "CWE-36": ("path_traversal", "canary_read"),
    "CWE-73": ("path_traversal", "canary_read"),
    "CWE-77": ("command_injection", "canary_exec"),
    "CWE-78": ("command_injection", "canary_exec"),
    "CWE-88": ("command_injection", "canary_exec"),
    "CWE-89": ("sql_injection", "canary_sql"),
    "CWE-94": ("code_injection", "canary_exec"),
    "CWE-95": ("code_injection", "canary_exec"),
    "CWE-502": ("insecure_deserialization", "canary_exec"),
    "CWE-918": ("ssrf", None),
    "CWE-79": ("xss", None),
    "CWE-400": ("denial_of_service", None),
    "CWE-1333": ("denial_of_service", None),
}
EFFECTS = frozenset({"canary_read", "canary_write", "canary_exec", "canary_sql"})


@dataclass(frozen=True)
class SymbolInfo:
    symbols: tuple[str, ...]
    source: str  # osv_ecosystem_specific | osv_database_specific | symbol_map | none
    vuln_class: str | None
    effect: str | None
    served_entry: str | None  # framework-called method when the symbol is a mountable app
    note: str = ""


def _dotted(value: Any) -> str | None:
    if isinstance(value, str) and len(value) <= 200 and _DOTTED.match(value):
        return value
    return None


def _from_block(block: Any) -> list[str]:
    """Symbols from one ``ecosystem_specific`` / ``database_specific`` object."""
    if not isinstance(block, dict):
        return []
    found: list[str] = []
    imports = block.get("imports")
    for entry in imports if isinstance(imports, list) else []:
        if not isinstance(entry, dict) or _dotted(entry.get("path")) is None:
            continue
        names = entry.get("symbols")
        names = [n for n in names if _dotted(n)] if isinstance(names, list) else []
        if names:
            found.extend(f"{entry['path']}.{n}" for n in names)
        else:
            found.append(entry["path"])
    functions = block.get("affected_functions")
    for name in functions if isinstance(functions, list) else []:
        if _dotted(name):
            found.append(name)
    return found


def _record_symbols(adv: Advisory, package: str, key: str) -> list[str]:
    affected = adv.raw.get("affected") if isinstance(adv.raw, dict) else None
    found: list[str] = []
    for item in affected if isinstance(affected, list) else []:
        if not isinstance(item, dict):
            continue
        pkg = item.get("package")
        if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str):
            continue
        if re.sub(r"[-_.]+", "-", pkg["name"]).lower() != package:
            continue
        found.extend(_from_block(item.get(key)))
    return list(dict.fromkeys(found))[:MAX_SYMBOLS]


@lru_cache(maxsize=4)
def _load_map(path: str) -> dict[str, dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = data.get("advisories") if isinstance(data, dict) else None
    if not isinstance(entries, dict):
        raise ValueError(f"{path}: 'advisories' must be an object")
    by_key: dict[str, dict[str, Any]] = {}
    for advisory_id, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        by_key[advisory_id] = entry
        for alias in entry.get("aliases") or []:
            if isinstance(alias, str):
                by_key.setdefault(alias, entry)
    return by_key


def map_entry(adv: Advisory, package: str, path: Path = SYMBOL_MAP) -> dict[str, Any] | None:
    """The ``symbols.json`` entry for this advisory and package, or None."""
    by_key = _load_map(str(path))
    for key in (adv.id, *adv.aliases):
        entry = by_key.get(key)
        if entry is not None and entry.get("package", package) == package:
            return entry
    return None


def cwe_ids(adv: Advisory) -> list[str]:
    block = adv.raw.get("database_specific") if isinstance(adv.raw, dict) else None
    ids = block.get("cwe_ids") if isinstance(block, dict) else None
    return [i for i in ids if isinstance(i, str) and len(i) <= 20][:16] if isinstance(ids, list) else []


def severity_label(adv: Advisory) -> str:
    block = adv.raw.get("database_specific") if isinstance(adv.raw, dict) else None
    label = block.get("severity") if isinstance(block, dict) else None
    if isinstance(label, str) and 0 < len(label) <= 20 and label.upper() not in {"CVSS_V3", "CVSS_V4"}:
        return label.upper()
    for severity in adv.severity:
        if severity.get("type") != "CVSS_V3":
            continue
        score = _cvss_v3_base_score(severity.get("score", ""))
        if score is not None:
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MODERATE"
            return "LOW"
    return "unrated"


def _cvss_v3_base_score(vector: str) -> float | None:
    """Compute the CVSS v3 base score from a CVSS:3.x vector."""
    parts = vector.split("/")
    if not parts or not parts[0].startswith("CVSS:3."):
        return None
    metrics = dict(part.split(":", 1) for part in parts[1:] if ":" in part)
    weights = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
        "UI": {"N": 0.85, "R": 0.62},
        "C": {"N": 0.0, "L": 0.22, "H": 0.56},
        "I": {"N": 0.0, "L": 0.22, "H": 0.56},
        "A": {"N": 0.0, "L": 0.22, "H": 0.56},
    }
    try:
        av, ac, pr, ui = (weights[key][metrics[key]] for key in ("AV", "AC", "PR", "UI"))
        c, i, a = (weights[key][metrics[key]] for key in ("C", "I", "A"))
        scope = metrics["S"]
    except (KeyError, TypeError):
        return None
    isc_base = 1 - (1 - c) * (1 - i) * (1 - a)
    if isc_base <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if scope == "U":
        impact = 6.42 * isc_base
        score = min(impact + exploitability, 10)
    elif scope == "C":
        pr_changed = {"N": 0.85, "L": 0.68, "H": 0.5}
        try:
            pr = pr_changed[metrics["PR"]]
        except KeyError:
            return None
        impact = 7.52 * (isc_base - 0.029) - 3.25 * math.pow(isc_base - 0.02, 15)
        score = min(1.08 * (impact + 8.22 * av * ac * pr * ui), 10)
    else:
        return None
    return math.ceil(score * 10) / 10


def affected_symbols(adv: Advisory, package: str, path: Path = SYMBOL_MAP) -> SymbolInfo:
    """Symbols, class and effect for one advisory on one (normalized) package."""
    entry = map_entry(adv, package, path)
    symbols: list[str] = []
    source = "none"
    for key, label in (("ecosystem_specific", "osv_ecosystem_specific"),
                       ("database_specific", "osv_database_specific")):
        symbols = _record_symbols(adv, package, key)
        if symbols:
            source = label
            break
    if not symbols and entry is not None:
        symbols = [s for s in entry.get("symbols") or [] if _dotted(s)][:MAX_SYMBOLS]
        source = "symbol_map" if symbols else "none"
    vuln_class: str | None = None
    effect: str | None = None
    if entry is not None and isinstance(entry.get("vuln_class"), str):
        vuln_class = entry["vuln_class"]
        effect = entry.get("effect") if entry.get("effect") in EFFECTS else None
    else:
        for cwe in cwe_ids(adv):
            if cwe in CWE_CLASSES:
                vuln_class, effect = CWE_CLASSES[cwe]
                break
    served = entry.get("served_entry") if entry is not None else None
    note = entry.get("note") if entry is not None and isinstance(entry.get("note"), str) else ""
    return SymbolInfo(
        symbols=tuple(symbols),
        source=source,
        vuln_class=vuln_class,
        effect=effect,
        served_entry=served if _dotted(served) else None,
        note=note,
    )
