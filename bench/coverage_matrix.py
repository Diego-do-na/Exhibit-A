"""Generate the corpus-to-oracle coverage matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, get_args

from exhibit_a.oracle.oracle import Effect
from exhibit_a.report.cwe import (
    CWE_22,
    CWE_23,
    CWE_73,
    CWE_77,
    CWE_78,
    CWE_89,
    CWE_95,
    CWE_434,
    CWE_502,
    CWE_611,
    CWE_1336,
    CWE_TABLE,
    CWEDefinition,
    get_cwe,
)

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "bench" / "corpus"
DOC = REPO / "docs" / "coverage.md"
BEGIN_MARKER = "<!-- BEGIN GENERATED: python -m bench.coverage_matrix -->"
END_MARKER = "<!-- END GENERATED -->"

#: Per-case CWE when the class-to-CWE default would collapse distinct ids.
CASE_CWE: dict[str, CWEDefinition] = {
    "static-route-traversal": CWE_23,
    "docsuite-large-command-injection": CWE_77,
    "upload-avatar": CWE_434,
    "xxe-catalog": CWE_611,
    "ssti-jinja-preview": CWE_1336,
}

CLASS_CWE: dict[str, CWEDefinition] = {
    "path_traversal": CWE_22,
    "path_traversal_write": CWE_73,
    "archive_extraction_path_traversal": CWE_22,
    "command_injection": CWE_78,
    "code_injection": CWE_95,
    "eval_injection": CWE_95,
    "insecure_deserialization": CWE_502,
    "unsafe_deserialization": CWE_502,
    "sql_injection": CWE_89,
    "xml_external_entity": CWE_611,
    "server_side_template_injection": CWE_1336,
    "ssti": CWE_1336,
    "unrestricted_file_upload": CWE_434,
    "arbitrary_file_write": CWE_73,
}

def _normalise(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")


def _class_definitions() -> dict[tuple[str, str], CWEDefinition]:
    """Return one deterministic CWE mapping for each class/effect pair."""
    definitions: dict[tuple[str, str], CWEDefinition] = {}
    for (effect, vuln_class), definition in sorted(CWE_TABLE.items()):
        if not effect.startswith("canary_"):
            continue
        key = (vuln_class, effect)
        definitions.setdefault(key, definition)
    return definitions


def _cwe_for(
    case_id: str,
    vuln_class: str,
    effect: str,
    declared: dict[str, Any] | None,
) -> CWEDefinition:
    if declared and declared.get("cwe_id") and declared.get("cwe_name"):
        return CWEDefinition(cwe_id=str(declared["cwe_id"]), name=str(declared["cwe_name"]))
    if case_id in CASE_CWE:
        return CASE_CWE[case_id]
    mapped = CLASS_CWE.get(_normalise(vuln_class))
    if mapped is not None:
        return mapped
    return get_cwe(effect, vuln_class)


def _proven_live(case_dir: Path) -> bool:
    """Whether a committed model recording for this case ended in a proven verdict."""
    recordings = case_dir / "recordings"
    if not recordings.is_dir():
        return False
    for recording in sorted(recordings.glob("*.json")):
        try:
            data = json.loads(recording.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        if any(
            isinstance(verdict, dict) and verdict.get("verdict") == "proven"
            for verdict in data.get("verdicts") or []
        ):
            return True
    return False


def _read_cases(corpus: Path) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    case_ids: list[str] = []
    for case_file in sorted(corpus.glob("*/case.json")):
        data = json.loads(case_file.read_text(encoding="utf-8"))
        run = data.get("run") if isinstance(data.get("run"), dict) else {}
        effect = str(run.get("effect") or "canary_read")
        measured = bool(data.get("measured") or run.get("measured"))
        if not measured:
            measured = any(case_file.parent.glob("recordings/*.jsonl"))
        analog = data.get("real_world_analog") if isinstance(data.get("real_world_analog"), dict) else {}
        declared_cwe = data.get("cwe") if isinstance(data.get("cwe"), dict) else analog
        proven = _proven_live(case_file.parent)
        for case in data.get("cases", []):
            case_id = str(case.get("id") or case_file.parent.name)
            case_ids.append(case_id)
            held_out = bool(
                case.get(
                    "held_out",
                    case.get(
                        "held-out",
                        run.get("held_out", run.get("held-out", data.get("held_out", data.get("held-out", False)))),
                    ),
                )
            )
            ground_truth = case.get("ground_truth") or []
            if not ground_truth:
                continue
            for finding in ground_truth:
                vuln_class = str(finding.get("class") or "")
                if vuln_class:
                    rows.append(
                        {
                            "case_id": case_id,
                            "class": _normalise(vuln_class),
                            "effect": effect,
                            "cwe": _cwe_for(case_id, vuln_class, effect, declared_cwe),
                            "held_out": held_out,
                            "measured": measured,
                            "proven": proven,
                        }
                    )
    return rows, sorted(case_ids)


def _status(cases: list[dict[str, Any]], vuln_class: str, effect: str) -> tuple[int, int, str]:
    matching = [case for case in cases if case["class"] == vuln_class and case["effect"] == effect]
    count = len(matching)
    held_out = sum(case["held_out"] for case in matching)
    if not matching:
        return count, held_out, "not covered"
    return count, held_out, "measured" if any(case["measured"] for case in matching) else "unmeasured"


def render(corpus: Path = CORPUS) -> str:
    """Render the generated Markdown section for ``corpus``."""
    cases, case_ids = _read_cases(corpus)
    definitions = _class_definitions()
    lines = [
        BEGIN_MARKER,
        "Coverage is derived from the corpus case manifests, the oracle effects, and the CWE table.",
        "A green result still means nothing could be proven, never that the target is safe.",
        'The sandbox is isolated and resource-limited, never "100% safe".',
        "",
        "| vulnerability class | CWE id and name | oracle effect | corpus cases | held-out cases | proven live | measured status |",
        "|---|---|---|---|---:|---|---|",
    ]
    for (vuln_class, effect), cwe in sorted(definitions.items(), key=lambda item: (item[0][0], item[0][1])):
        count, held_out, status = _status(cases, vuln_class, effect)
        matching = [
            case for case in cases if case["class"] == vuln_class and case["effect"] == effect
        ]
        case_ids_for_row = sorted({case["case_id"] for case in matching})
        proven = "yes" if any(case["proven"] for case in matching) else "not yet recorded"
        case_cell = ", ".join(f"`{case_id}`" for case_id in case_ids_for_row) or "not covered"
        if matching and any(case["cwe"] != cwe for case in matching):
            cwe_values = sorted({f"{case['cwe'].cwe_id} {case['cwe'].name}" for case in matching})
            cwe_cell = "<br>".join(cwe_values)
        else:
            cwe_cell = f"{cwe.cwe_id} {cwe.name}"
        lines.append(
            f"| {vuln_class} | {cwe_cell} | {effect} | {case_cell} ({count}) | "
            f"{held_out} | {proven} | {status} |"
        )

    lines.extend(["", "### Corpus case IDs", ""])
    lines.extend(f"- `{case_id}`" for case_id in case_ids)
    lines.extend(
        [
            "",
            "### Classes Exhibit A does not claim",
            "",
            "These classes have no oracle-observable effect in the current proof loop, so a",
            "suspicion of them is never a finding. A green result means nothing could be",
            "proven, never that the code is free of them.",
            "",
            "- **Weak cryptography** (for example CWE-327, CWE-328): a short key or a broken",
            "  hash does not read, write, execute, query or connect in a way the oracle can",
            '  observe. There is no canary for "this ciphertext is weakly protected".',
            "- **Hard-coded secrets** (CWE-798): a token sitting in source is not an",
            "  observed effect. Exhibit A does not scan configuration or secrets.",
            "- **Logic bugs without an observable effect**: a wrong discount, a skipped",
            "  authorisation check that does not reach a sink, or a state machine that",
            "  accepts a bad transition. The oracle proves a read, write, exec, SQL or",
            "  connect through an entry point; it does not prove that business rules hold.",
            "",
            "### Not covered by design",
            "",
            "- Weak cryptography has no oracle-observable effect in the current proof loop.",
            "- Business logic flaws have no oracle-observable effect in the current proof loop.",
            END_MARKER,
        ]
    )
    return "\n".join(lines) + "\n"


def update_document(document: Path = DOC, corpus: Path = CORPUS) -> None:
    """Replace the generated section in ``document`` without changing surrounding prose."""
    generated = render(corpus).rstrip("\n")
    if document.is_file():
        existing = document.read_text(encoding="utf-8")
        starts = [
            index
            for marker in (
                BEGIN_MARKER,
                "<!-- BEGIN GENERATED: python -m bench.coverage -->",
            )
            for index in [existing.find(marker)]
            if index >= 0
        ]
        if starts:
            start = min(starts)
            end_markers = [
                existing.find(marker, start)
                for marker in (END_MARKER, "<!-- END GENERATED: python -m bench.coverage -->")
            ]
            end = max(end_markers)
            if end >= start:
                suffix_start = end + len(
                    "<!-- END GENERATED: python -m bench.coverage -->"
                    if existing.startswith("<!-- END GENERATED: python -m bench.coverage -->", end)
                    else END_MARKER
                )
                suffix = existing[suffix_start:]
                document.write_text(existing[:start] + generated + suffix, encoding="utf-8")
                return
        if existing and not existing.endswith("\n"):
            existing += "\n"
        document.write_text(existing + generated + "\n", encoding="utf-8")
        return
    document.parent.mkdir(parents=True, exist_ok=True)
    document.write_text("# Coverage matrix\n\n" + generated + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--doc", type=Path, default=DOC)
    args = parser.parse_args()
    update_document(args.doc, args.corpus)


if __name__ == "__main__":
    main()
