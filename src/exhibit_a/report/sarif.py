"""Generate SARIF 2.1.0 reports for proven Exhibit A findings.

This module converts proven findings from an Exhibit A run directory into the
OASIS Static Analysis Results Interchange Format (SARIF) 2.1.0 JSON format
suitable for uploading to GitHub Code Scanning.

Only proven findings (verdict == 'proven') produce results. Discarded suspicions
are not results. When a run has zero proven findings, a valid SARIF 2.1.0 document
with zero results is produced.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .cwe import (
    get_cwe,
    sarif_level_from_severity,
    security_severity_score,
    severity_from_effect,
)

SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
TOOL_NAME = "Exhibit A"
TOOL_URI = "https://github.com/diego-do-na/Exhibit-A"
TOOL_VERSION = "0.1.0"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            return value
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    return {}


def _normalize_uri(
    path_str: str | None,
    run_dir: Path,
    target_repo: Path | None,
    model_file: str | None,
) -> str:
    """Normalize file path to a repository-relative URI with forward slashes."""
    if not path_str:
        return (model_file or "unknown").replace("\\", "/")

    norm_target = path_str.replace("\\", "/")

    # If model_file is known and the path ends with it, prefer the relative model_file
    if model_file:
        norm_model = model_file.replace("\\", "/").lstrip("/")
        if norm_target.endswith("/" + norm_model) or norm_target == norm_model:
            return norm_model

    p = Path(path_str)
    # Check relative to target_repo
    if target_repo is not None:
        try:
            return str(p.resolve().relative_to(target_repo.resolve())).replace("\\", "/")
        except (ValueError, OSError):
            pass

    # Check relative to clone dir inside run_dir
    clone_dir = run_dir / "clone"
    if clone_dir.is_dir():
        try:
            return str(p.resolve().relative_to(clone_dir.resolve())).replace("\\", "/")
        except (ValueError, OSError):
            pass

    # Check relative to run_dir
    try:
        return str(p.resolve().relative_to(run_dir.resolve())).replace("\\", "/")
    except (ValueError, OSError):
        pass

    # Check relative to cwd
    try:
        return str(p.resolve().relative_to(Path.cwd().resolve())).replace("\\", "/")
    except (ValueError, OSError):
        pass

    # If it looks like an absolute path, strip leading root
    clean = norm_target.lstrip("/")
    # If path contains common markers like 'vulnerable/' or 'fixed/' or 'starlette/'
    for marker in ("vulnerable/", "fixed/", "starlette/", "src/"):
        if marker in clean:
            return clean[clean.index(marker):]

    return clean or (model_file or "unknown").replace("\\", "/")


def _find_package_dirs(run_dir: Path) -> list[Path]:
    """Find directories containing verdict.json under run_dir."""
    packages_dir = run_dir / "packages"
    if packages_dir.is_dir():
        found = [p for p in sorted(packages_dir.iterdir()) if (p / "verdict.json").is_file()]
        if found:
            return found

    # Check if run_dir itself is a package
    if (run_dir / "verdict.json").is_file():
        return [run_dir]

    # Search one level deeper for package directories
    return [p.parent for p in sorted(run_dir.glob("**/verdict.json"))]


def _cost_from_ledger(run_dir: Path) -> float:
    """Read total cost from ledger.jsonl if present."""
    ledger_path = run_dir / "ledger.jsonl"
    if not ledger_path.is_file():
        ledger_path = run_dir.parent / "ledger.jsonl"
    if not ledger_path.is_file():
        return 0.0

    cost = 0.0
    try:
        for line in ledger_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                cost += float(ev.get("cost_usd", 0.0))
            except (json.JSONDecodeError, ValueError, TypeError):
                continue
    except OSError:
        pass
    return round(cost, 6)


def generate_sarif(
    run_dir: str | Path,
    *,
    target_repo: str | Path | None = None,
) -> dict[str, Any]:
    """Generate a SARIF 2.1.0 document from an Exhibit A run directory.

    Args:
        run_dir: Directory holding run output (packages/ and optional ledger.jsonl).
        target_repo: Optional path to target repository root for relativizing paths.

    Returns:
        SARIF 2.1.0 dictionary conforming to the standard specification.
    """
    run_path = Path(run_dir).resolve()
    target_path = Path(target_repo).resolve() if target_repo else None

    package_dirs = _find_package_dirs(run_path)
    total_run_cost = _cost_from_ledger(run_path)

    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for pkg in package_dirs:
        verdict = _read_json(pkg / "verdict.json")
        # Discarded suspicions are NOT results
        if verdict.get("verdict") != "proven":
            continue

        evidence = _read_json(pkg / "evidence.json")
        suspicion = evidence.get("suspicion") if isinstance(evidence.get("suspicion"), dict) else {}
        model_loc = suspicion.get("location") if isinstance(suspicion.get("location"), dict) else {}
        model_file = model_loc.get("file")

        vuln_class = str(suspicion.get("class") or suspicion.get("vuln_class") or "path_traversal")
        entry_point = str(suspicion.get("entry_point") or "")

        proof = evidence.get("evidence") if isinstance(evidence.get("evidence"), dict) else verdict.get("evidence", {})
        if not isinstance(proof, dict):
            proof = {}

        oracle = proof.get("oracle") if isinstance(proof.get("oracle"), dict) else {}
        effect = str(oracle.get("effect") or verdict.get("effect") or "canary_read")

        provenance = proof.get("provenance") if isinstance(proof.get("provenance"), dict) else {}
        provenance_ok = bool(provenance.get("ok", True))
        has_entry_point = bool(entry_point or provenance.get("entry_point"))

        fix_verified = bool(evidence.get("fix_verified", verdict.get("fix_verified", False)))

        usage = evidence.get("usage") if isinstance(evidence.get("usage"), dict) else {}
        cost = float(usage.get("cost_usd", 0.0))
        if cost == 0.0 and total_run_cost > 0.0:
            cost = total_run_cost

        try:
            package_path = str(pkg.relative_to(run_path))
        except ValueError:
            package_path = str(pkg)

        # CWE and Severity
        cwe = get_cwe(effect, vuln_class)
        severity = severity_from_effect(
            effect,
            vuln_class=vuln_class,
            provenance_ok=provenance_ok,
            has_entry_point=has_entry_point,
        )
        level = sarif_level_from_severity(severity)
        rule_id = cwe.cwe_id

        # Rule definition
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": cwe.cwe_id,
                "name": cwe.name,
                "shortDescription": {"text": cwe.name},
                "fullDescription": {"text": f"{cwe.cwe_id}: {cwe.name}. {cwe.description}".strip()},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "security-severity": security_severity_score(severity),
                    "tags": ["security", f"external/cwe/{cwe.cwe_id.lower()}"],
                },
            }

        # Admitted stack from oracle events
        events = oracle.get("events") if isinstance(oracle.get("events"), list) else []
        admitted_frames: list[dict[str, Any]] = []
        for ev in events:
            if not isinstance(ev, dict):
                continue
            stack = ev.get("stack")
            if isinstance(stack, list):
                # Look for admitted application frames
                admitted = [f for f in stack if isinstance(f, dict) and f.get("admitted") is True]
                if not admitted:
                    # Fallback when admitted flag is not present (mock/synthetic frames)
                    admitted = [
                        f for f in stack
                        if isinstance(f, dict) and not str(f.get("file", "")).startswith("<") and f.get("line")
                    ]
                if admitted:
                    admitted_frames = admitted
                    break

        # Location: observed location when present else model location
        observed_file: str | None = None
        observed_line: int | None = None
        if admitted_frames:
            sink_frame = admitted_frames[-1]
            observed_file = sink_frame.get("file")
            observed_line = sink_frame.get("line")

        if observed_file and observed_line:
            result_file = _normalize_uri(str(observed_file), run_path, target_path, model_file)
            result_line = int(observed_line)
        else:
            result_file = _normalize_uri(model_file, run_path, target_path, model_file)
            result_line = int(model_loc.get("line") or 1)

        result_location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": result_file,
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": max(1, result_line),
                    "startColumn": 1,
                },
            },
            "message": {
                "text": f"Proven {cwe.name} ({effect})",
            },
        }

        # CodeFlows: from oracle's admitted stack entry point to sink
        code_flows: list[dict[str, Any]] = []
        if admitted_frames:
            thread_flow_locs = []
            for idx, frame in enumerate(admitted_frames, 1):
                frame_file = _normalize_uri(frame.get("file"), run_path, target_path, model_file)
                frame_line = max(1, int(frame.get("line") or 1))
                qualname = frame.get("qualname") or frame.get("function") or "frame"
                if idx == 1:
                    step_text = f"Entry point: {qualname}"
                elif idx == len(admitted_frames):
                    step_text = f"Sink reached: {qualname}"
                else:
                    step_text = f"Call: {qualname}"

                thread_flow_locs.append({
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": frame_file,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": frame_line,
                                "startColumn": 1,
                            },
                        },
                        "message": {"text": step_text},
                    },
                    "executionOrder": idx,
                })

            code_flows.append({
                "message": {"text": "Admitted execution call flow from entry point to sink"},
                "threadFlows": [{"locations": thread_flow_locs}],
            })

        message_text = (
            f"Exhibit A proven finding: {cwe.cwe_id} ({cwe.name}). "
            f"Effect '{effect}' verified by execution proof. "
            f"Fix verified: {'yes' if fix_verified else 'no'}."
        )

        res_dict: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
            "locations": [result_location],
            "properties": {
                "effect": effect,
                "verdict": "proven",
                "fix_verified": fix_verified,
                "package_path": package_path,
                "package path": package_path,
                "cost": cost,
            },
        }
        if code_flows:
            res_dict["codeFlows"] = code_flows

        results.append(res_dict)

    rules_list = sorted(rules_by_id.values(), key=lambda r: r["id"])

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_URI,
                        "semanticVersion": TOOL_VERSION,
                        "rules": rules_list,
                    }
                },
                "results": results,
            }
        ],
    }

    validate_sarif(sarif_doc)
    return sarif_doc


def validate_sarif(data: Any) -> None:
    """Minimal structural validator for SARIF 2.1.0 output (vendors no third-party libraries).

    Raises:
        ValueError: If data does not strictly satisfy required SARIF 2.1.0 structure.
    """
    if not isinstance(data, dict):
        raise ValueError("SARIF document must be a JSON object (dict)")

    if data.get("version") != SARIF_VERSION:
        raise ValueError(f"SARIF version must be {SARIF_VERSION!r}, got {data.get('version')!r}")

    runs = data.get("runs")
    if not isinstance(runs, list):
        raise ValueError("SARIF document must have a 'runs' array")

    for r_idx, run in enumerate(runs):
        if not isinstance(run, dict):
            raise ValueError(f"run[{r_idx}] must be a JSON object")

        tool = run.get("tool")
        if not isinstance(tool, dict) or not isinstance(tool.get("driver"), dict):
            raise ValueError(f"run[{r_idx}].tool.driver must be a JSON object")

        driver = tool["driver"]
        if not isinstance(driver.get("name"), str) or not driver.get("name"):
            raise ValueError(f"run[{r_idx}].tool.driver.name must be a non-empty string")

        results = run.get("results")
        if not isinstance(results, list):
            raise ValueError(f"run[{r_idx}].results must be an array")

        for res_idx, res in enumerate(results):
            if not isinstance(res, dict):
                raise ValueError(f"result[{res_idx}] must be an object")

            if not isinstance(res.get("ruleId"), str) or not res.get("ruleId"):
                raise ValueError(f"result[{res_idx}].ruleId must be a non-empty string")

            level = res.get("level")
            if level not in ("error", "warning", "note", "none"):
                raise ValueError(f"result[{res_idx}].level must be one of error/warning/note/none, got {level!r}")

            msg = res.get("message")
            if not isinstance(msg, dict) or not isinstance(msg.get("text"), str):
                raise ValueError(f"result[{res_idx}].message.text must be a string")

            locations = res.get("locations")
            if not isinstance(locations, list):
                raise ValueError(f"result[{res_idx}].locations must be an array")

            for loc_idx, loc in enumerate(locations):
                phys = loc.get("physicalLocation")
                if not isinstance(phys, dict):
                    raise ValueError(f"result[{res_idx}].locations[{loc_idx}].physicalLocation missing")
                art = phys.get("artifactLocation")
                if not isinstance(art, dict) or not isinstance(art.get("uri"), str):
                    raise ValueError(f"result[{res_idx}].locations[{loc_idx}].artifactLocation.uri missing")

            props = res.get("properties")
            if not isinstance(props, dict):
                raise ValueError(f"result[{res_idx}].properties must be an object")

            for req_key in ("effect", "verdict", "fix_verified", "cost"):
                if req_key not in props:
                    raise ValueError(f"result[{res_idx}].properties missing required key {req_key!r}")

            if "package_path" not in props and "package path" not in props:
                raise ValueError(f"result[{res_idx}].properties missing package path")

            code_flows = res.get("codeFlows")
            if code_flows is not None:
                if not isinstance(code_flows, list):
                    raise ValueError(f"result[{res_idx}].codeFlows must be an array")
                for cf_idx, cf in enumerate(code_flows):
                    tflows = cf.get("threadFlows")
                    if not isinstance(tflows, list):
                        raise ValueError(f"codeFlow[{cf_idx}].threadFlows must be an array")
                    for tf_idx, tf in enumerate(tflows):
                        tf_locs = tf.get("locations")
                        if not isinstance(tf_locs, list):
                            raise ValueError(f"threadFlow[{tf_idx}].locations must be an array")
