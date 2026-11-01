"""Generate the CWE coverage matrix from corpus ``case.json`` files.

The committed ``docs/coverage.md`` is this script's output. Re-run
``python -m bench.coverage`` after adding a case so the table cannot drift.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

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
    CWEDefinition,
    get_cwe,
)

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "bench" / "corpus"
DOC = REPO / "docs" / "coverage.md"
BEGIN_MARKER = "<!-- BEGIN GENERATED: python -m bench.coverage -->"
END_MARKER = "<!-- END GENERATED: python -m bench.coverage -->"

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


def _cwe_for(case_id: str, vuln_class: str, effect: str, declared: dict[str, Any] | None) -> CWEDefinition:
    if declared and declared.get("cwe_id") and declared.get("cwe_name"):
        return CWEDefinition(cwe_id=str(declared["cwe_id"]), name=str(declared["cwe_name"]))
    if case_id in CASE_CWE:
        return CASE_CWE[case_id]
    mapped = CLASS_CWE.get(vuln_class.strip().lower().replace("-", "_").replace(" ", "_"))
    if mapped is not None:
        return mapped
    return get_cwe(effect, vuln_class)


def _proven_live(case_dir: Path) -> bool:
    """Whether a committed Meta recording of this case ended with a proven verdict."""
    recordings = case_dir / "recordings"
    if not recordings.is_dir():
        return False
    for meta_path in sorted(recordings.glob("*.json")):
        if meta_path.name.endswith(".jsonl"):
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(meta, dict):
            continue
        for verdict in meta.get("verdicts") or []:
            if isinstance(verdict, dict) and verdict.get("verdict") == "proven":
                return True
    return False


def _read_rows(corpus: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for case_file in sorted(corpus.glob("*/case.json")):
        data = json.loads(case_file.read_text(encoding="utf-8"))
        run = data.get("run") if isinstance(data.get("run"), dict) else {}
        effect = str(run.get("effect") or "canary_read")
        analog = data.get("real_world_analog") if isinstance(data.get("real_world_analog"), dict) else {}
        declared_cwe = data.get("cwe") if isinstance(data.get("cwe"), dict) else analog
        live = _proven_live(case_file.parent)
        for case in data.get("cases") or []:
            if not isinstance(case, dict):
                continue
            case_id = str(case.get("id") or case_file.parent.name)
            for finding in case.get("ground_truth") or []:
                if not isinstance(finding, dict):
                    continue
                vuln_class = str(finding.get("class") or "")
                if not vuln_class:
                    continue
                cwe = _cwe_for(case_id, vuln_class, effect, declared_cwe)
                notes = str(analog.get("cve") or analog.get("summary") or vuln_class).split("\n")[0]
                if len(notes) > 80:
                    notes = notes[:77] + "..."
                rows.append(
                    {
                        "cwe": f"{cwe.cwe_id} {cwe.name}",
                        "cwe_id": cwe.cwe_id,
                        "effect": effect,
                        "case": case_id,
                        "proven": "yes" if live else "not yet recorded",
                        "notes": notes.replace("|", "/"),
                    }
                )
    return rows


def render(corpus: Path = CORPUS) -> str:
    """Render the generated Markdown section for ``corpus``."""
    rows = _read_rows(corpus)
    lines = [
        BEGIN_MARKER,
        "Coverage is generated from corpus `case.json` files (`python -m bench.coverage`).",
        "A green result still means nothing could be proven, never that the target is safe.",
        "The sandbox is isolated and resource-limited, never \"100% safe\".",
        "",
        "| CWE id and name | effect | corpus case | proven live | notes |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['cwe']} | {row['effect']} | `{row['case']}` | {row['proven']} | {row['notes']} |"
        )
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
            "  observe. There is no canary for \"this ciphertext is weakly protected\".",
            "- **Hard-coded secrets** (CWE-798): a token sitting in source is not an",
            "  observed effect. Exhibit A does not scan configuration or secrets.",
            "- **Logic bugs without an observable effect**: a wrong discount, a skipped",
            "  authorisation check that does not reach a sink, or a state machine that",
            "  accepts a bad transition. The oracle proves a read, write, exec, SQL or",
            "  connect through an entry point; it does not prove that business rules hold.",
            "",
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
    document.write_text(
        "# Coverage matrix\n\n"
        "Which CWEs Exhibit A can prove, from the corpus cases and the oracle effects "
        "they exercise. Generated by `python -m bench.coverage`; do not edit the "
        "generated block by hand.\n\n"
        + generated
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--doc", type=Path, default=DOC)
    args = parser.parse_args()
    update_document(args.doc, args.corpus)


if __name__ == "__main__":
    main()
