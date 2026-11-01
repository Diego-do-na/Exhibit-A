"""Generate the corpus-to-oracle coverage matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, get_args

from exhibit_a.oracle.oracle import Effect
from exhibit_a.report.cwe import CWE_TABLE, CWEDefinition

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "bench" / "corpus"
DOC = REPO / "docs" / "coverage.md"
BEGIN_MARKER = "<!-- BEGIN GENERATED: python -m bench.coverage_matrix -->"
END_MARKER = "<!-- END GENERATED -->"


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
                            "held_out": held_out,
                            "measured": measured,
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
        "Coverage is derived from the corpus case manifests, the oracle effects, and the SARIF CWE table.",
        "",
        "| vulnerability class | CWE | oracle effect | corpus cases (count) | held-out cases (count) | measured status |",
        "|---|---|---|---:|---:|---|",
    ]
    for (vuln_class, effect), cwe in sorted(definitions.items(), key=lambda item: (item[0][0], item[0][1])):
        count, held_out, status = _status(cases, vuln_class, effect)
        lines.append(f"| {vuln_class} | {cwe.cwe_id} | {effect} | {count} | {held_out} | {status} |")

    lines.extend(["", "### Corpus case IDs", ""])
    lines.extend(f"- `{case_id}`" for case_id in case_ids)
    lines.extend(
        [
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
        start = existing.find(BEGIN_MARKER)
        end = existing.find(END_MARKER)
        if start >= 0 and end >= start:
            prefix = existing[:start]
            suffix = existing[end + len(END_MARKER) :]
            document.write_text(prefix + generated + suffix, encoding="utf-8")
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
