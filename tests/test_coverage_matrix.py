"""Coverage matrix generator tests."""

import json
from pathlib import Path

from bench import coverage as coverage_t103
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


def test_t103_synthetic_corpus_renders_cwe_rows(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    _case(corpus, "xxe-case", "xml_external_entity", "canary_read")
    _case(corpus, "ssti-case", "server_side_template_injection", "canary_exec")
    document = tmp_path / "coverage.md"

    coverage_t103.update_document(document, corpus)
    output = document.read_text(encoding="utf-8")

    assert "| CWE id and name | effect | corpus case | proven live | notes |" in output
    assert "`xxe-case`" in output and "`ssti-case`" in output
    assert "not yet recorded" in output
    assert "Weak cryptography" in output
    assert "Hard-coded secrets" in output
    assert "Logic bugs without an observable effect" in output


def test_t103_generator_is_idempotent(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    _case(corpus, "case", "path_traversal", "canary_read")
    document = tmp_path / "coverage.md"

    coverage_t103.update_document(document, corpus)
    first = document.read_text(encoding="utf-8")
    coverage_t103.update_document(document, corpus)

    assert document.read_text(encoding="utf-8") == first


def test_committed_coverage_matches_the_generator() -> None:
    committed = coverage_t103.DOC.read_text(encoding="utf-8")
    generated = coverage_t103.render()
    start = committed.find(coverage_t103.BEGIN_MARKER)
    end = committed.find(coverage_t103.END_MARKER)
    assert start >= 0 and end > start
    block = committed[start:end + len(coverage_t103.END_MARKER)] + "\n"
    assert block == generated
    cwes = {line.split("|")[1].strip().split()[0]
            for line in generated.splitlines() if line.startswith("| CWE-")}
    assert len(cwes) >= 10, sorted(cwes)
