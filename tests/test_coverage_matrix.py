"""Coverage matrix generator tests."""

import json
from pathlib import Path

from bench.coverage_matrix import update_document


def _case(root: Path, name: str, vuln_class: str, effect: str, *, held_out: bool = False) -> None:
    case_dir = root / name
    case_dir.mkdir(parents=True)
    case = {
        "id": name,
        "kind": "vulnerable",
        "ground_truth": [{"class": vuln_class}],
    }
    if held_out:
        case["held_out"] = True
    (case_dir / "case.json").write_text(
        json.dumps({"cases": [case], "run": {"effect": effect}}),
        encoding="utf-8",
    )


def test_synthetic_corpus_renders_all_effects_and_counts(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    _case(corpus, "read-case", "path_traversal", "canary_read", held_out=True)
    _case(corpus, "exec-case", "command_injection", "canary_exec")
    (corpus / "exec-case" / "recordings").mkdir()
    (corpus / "exec-case" / "recordings" / "run.jsonl").write_text("{}\n", encoding="utf-8")
    document = tmp_path / "coverage.md"

    update_document(document, corpus)
    output = document.read_text(encoding="utf-8")

    assert "| path_traversal | CWE-22 | canary_read | 1 | 1 | unmeasured |" in output
    assert "| command_injection | CWE-78 | canary_exec | 1 | 0 | measured |" in output
    assert "| sql_injection | CWE-89 | canary_sql | 0 | 0 | not covered |" in output
    assert "- `read-case`" in output
    assert "- `exec-case`" in output
    assert "Weak cryptography" in output
    assert "Business logic" in output


def test_generator_is_idempotent(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    _case(corpus, "case", "path_traversal", "canary_read")
    document = tmp_path / "coverage.md"

    update_document(document, corpus)
    first = document.read_text(encoding="utf-8")
    update_document(document, corpus)

    assert document.read_text(encoding="utf-8") == first
