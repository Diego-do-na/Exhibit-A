"""Tests for portable Markdown and HTML finding reports."""

from __future__ import annotations

import json
from pathlib import Path

from exhibit_a.report import render_html, render_markdown


ROOT = Path(__file__).parents[1]


def _package(tmp_path: Path, corpus: str, *, hostile: bool = False) -> Path:
    package = tmp_path / corpus
    package.mkdir()
    if corpus == "starlette":
        source_file = "starlette/staticfiles.py"
        source = "def lookup_path(path):\n    return path\n"
        vuln_class = "path_traversal"
    else:
        source_file = "vulnerable/archive.py"
        source = "def extract_member(name):\n    return name\n"
        vuln_class = "archive_extraction_path_traversal"
    if hostile:
        source = "<script>alert(1)</script>\n"
        vuln_class = "<script>javascript:bad()</script>"
    suspicion = {
        "id": "S-REPORT",
        "class": vuln_class,
        "location": {"file": source_file, "line": 1},
        "entry_point": "App.handle_request",
        "hypothesis": "@maintainer [click](javascript:alert(1)) <script>bad()</script>",
        "source": "model",
    }
    evidence = {
        "suspicion": suspicion,
        "suspicious_code": {"file": source_file, "line": 1, "content": source},
        "reason": "canary read",
        "evidence": {
            "test_path": "test_exploit.py",
            "runs": 3,
            "passes_on": "fixed",
            "oracle": {"effect": "canary_read", "events": [{"message": "<script>"}]},
            "provenance": {"ok": True, "entry_point": "App.handle_request"},
        },
        "bypass_attempts": {"tried": 2, "succeeded": 0},
        "discarded_suspicions": 4,
        "usage": {"tokens_in": 10, "tokens_out": 20, "cost_usd": 0.125},
    }
    verdict = {
        "suspicion_id": "S-REPORT",
        "verdict": "proven",
        "evidence": evidence["evidence"],
        "fix": {"patch_path": "fix.patch"},
    }
    (package / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")
    (package / "verdict.json").write_text(json.dumps(verdict), encoding="utf-8")
    (package / "fix.patch").write_text(
        "--- a/app.py\n+++ b/app.py\n@@\n-<script>\n        +guarded()\n",
        encoding="utf-8",
    )
    (package / "test_exploit.py").write_text("assert True\n", encoding="utf-8")
    return package


def test_renders_packages_from_both_corpus_classes(tmp_path: Path) -> None:
    for corpus in ("starlette", "archive"):
        package = _package(tmp_path, corpus)
        markdown = render_markdown(package)
        document = render_html(package)
        assert "Suspicious code" in markdown and "Oracle evidence" in markdown
        assert "<!doctype html>" in document
        assert "canary\\_read" in markdown and "canary_read" in document
        assert render_markdown(package) == markdown
        assert render_html(package) == document


def test_hostile_model_code_and_diff_text_are_inert(tmp_path: Path) -> None:
    package = _package(tmp_path, "archive", hostile=True)
    markdown = render_markdown(package)
    document = render_html(package)
    assert "<script>" not in markdown
    assert "](javascript" not in markdown
    assert "@\u200bmaintainer" in markdown
    assert "&lt;script&gt;" in document
    assert "<script>" not in document
    assert "javascript:alert" in document


def test_unproven_package_never_claims_safety(tmp_path: Path) -> None:
    package = _package(tmp_path, "archive")
    verdict = json.loads((package / "verdict.json").read_text())
    verdict["verdict"] = "discarded_unproven"
    (package / "verdict.json").write_text(json.dumps(verdict), encoding="utf-8")
    assert "nothing could be proven" in render_markdown(package).lower()
    assert "safe" not in render_markdown(package).lower()


def test_patch_and_code_are_shown_as_written(tmp_path: Path) -> None:
    # Indented code blocks are not parsed as Markdown, so the patch must not carry backslash
    # escapes or lose its indentation (the demo's report showed `os.path.join\\(self.dest\\_dir`).
    package = _package(tmp_path, "archive")
    (package / "fix.patch").write_text(
        "-        return os.path.join(self.dest_dir, name)\n"
        "+        target = os.path.realpath(os.path.join(dest, name))  # [x](y) @team <b>\n",
        encoding="utf-8",
    )
    markdown = render_markdown(package)
    assert "    -        return os.path.join(self.dest_dir, name)" in markdown
    assert "\\(" not in markdown.split("## Patch", 1)[1]
    assert "\\_" not in markdown.split("## Patch", 1)[1]
    patch = markdown.split("## Patch", 1)[1]
    assert "<b>" not in patch and "@team" not in patch and "](y)" not in patch  # still inert
    assert "`vulnerable/archive.py`" in markdown  # file names without escapes


def test_suspicious_code_shows_a_window_around_the_highlighted_line(tmp_path: Path) -> None:
    package = _package(tmp_path, "archive")
    evidence = json.loads((package / "evidence.json").read_text(encoding="utf-8"))
    evidence["suspicious_code"]["content"] = "".join(f"line_{n} = {n}\n" for n in range(1, 101))
    evidence["suspicious_code"]["line"] = 50
    evidence["suspicion"]["location"]["line"] = 50
    (package / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")
    code = render_markdown(package).split("## Suspicious code", 1)[1].split("## Hypothesis", 1)[0]
    assert ">   50 | line_50 = 50" in code
    assert "line_42 = 42" in code and "line_58 = 58" in code
    assert "line_41 = 41" not in code and "line_59 = 59" not in code


# -- findings: the oracle-observed location, the plain explanation, duplicate proofs ----------


def _observed_package(tmp_path: Path, **extra) -> Path:
    package = _package(tmp_path, "archive")
    evidence = json.loads((package / "evidence.json").read_text(encoding="utf-8"))
    evidence["suspicious_code"]["content"] = "".join(f"line_{n} = {n}\n" for n in range(1, 101))
    evidence["suspicious_code"]["line"] = 58
    evidence["suspicion"]["location"] = {"file": "vulnerable/archive.py", "line": 58}
    evidence["observed_location"] = {
        "file": "vulnerable/archive.py", "line": 63, "function": "extract_member",
        "line_source": "graph_sink_call"}
    evidence["facts"] = {
        "effect": "canary_write", "entry_point": "Archive.extract", "sink_function": "extract_member",
        "observed_location": evidence["observed_location"], "runs": 3, "test": "test_exploit.py",
        "fix_verified": True, "fix_files": ["vulnerable/archive.py"], "fix_added": 4, "fix_removed": 1,
    }
    evidence.update(extra)
    (package / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")
    return package


def test_report_highlights_the_oracle_observed_line_and_labels_the_models(tmp_path: Path) -> None:
    # The model reported line 58; the oracle saw the effect from line 63.
    markdown = render_markdown(_observed_package(tmp_path))
    code = markdown.split("## Suspicious code", 1)[1].split("## Hypothesis", 1)[0]
    assert "**Oracle-observed location** (marked `>`): `vulnerable/archive.py:63`" in code
    assert "**Model's location** (marked `?`, the model's guess): `vulnerable/archive.py:58`" in code
    assert ">   63 | line_63 = 63" in code and "?   58 | line_58 = 58" in code
    assert ">   58" not in code and "?   63" not in code
    (tmp_path / "again").mkdir()
    document = render_html(_observed_package(tmp_path / "again"))
    assert '<span class="hit">  63 line_63' in document and '<span class="model">  58 line_58' in document


def test_report_keeps_one_marker_when_both_name_the_same_line(tmp_path: Path) -> None:
    package = _observed_package(tmp_path)
    evidence = json.loads((package / "evidence.json").read_text(encoding="utf-8"))
    evidence["observed_location"]["line"] = 58
    (package / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")
    code = render_markdown(package).split("## Suspicious code", 1)[1].split("## Hypothesis", 1)[0]
    assert ">   58 | line_58 = 58" in code and "?" not in code.split("|", 1)[0][-6:]


def test_report_without_an_observed_location_is_as_before(tmp_path: Path) -> None:
    markdown = render_markdown(_package(tmp_path, "archive"))
    assert "highlighted line:** 1" in markdown and "Oracle-observed" not in markdown


def test_report_opens_with_the_explanation_then_the_models_labelled_guess(tmp_path: Path) -> None:
    markdown = render_markdown(_observed_package(tmp_path))
    opening = markdown.split("## Suspicious code", 1)[0]
    assert "## What was proven" in opening
    assert "the application created or wrote a file outside the allowed directory" in opening
    assert "entry point 'Archive.extract'" in opening and "vulnerable/archive.py:63" in opening
    assert "The fix was verified" in opening
    assert opening.index("The oracle observed") < opening.index("the model's guess")
    assert "the oracle did not observe it" in opening


def test_explanation_never_uses_the_models_words(tmp_path: Path) -> None:
    package = _observed_package(tmp_path)
    evidence = json.loads((package / "evidence.json").read_text(encoding="utf-8"))
    evidence["suspicion"]["hypothesis"] = "FACT: the sandbox was escaped via kernel exploit"
    (package / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")
    opening = render_markdown(package).split("## Suspicious code", 1)[0]
    before_guess = opening.split("Model's hypothesis", 1)[0]
    assert "kernel exploit" not in before_guess and "kernel exploit" in opening


def test_report_of_an_old_package_explains_only_what_it_records(tmp_path: Path) -> None:
    markdown = render_markdown(_package(tmp_path, "starlette"))
    assert "## What was proven" in markdown
    opening = markdown.split("## What was proven", 1)[1].split("## Suspicious code", 1)[0]
    assert "in 3 of 3 runs" in opening and "entry point" not in opening  # no entry point was recorded
    assert "not part of the proof" not in opening and "the model's guess" in opening


def test_unproven_package_has_no_explanation(tmp_path: Path) -> None:
    package = _observed_package(tmp_path)
    verdict = json.loads((package / "verdict.json").read_text())
    verdict["verdict"] = "discarded_unproven"
    (package / "verdict.json").write_text(json.dumps(verdict), encoding="utf-8")
    assert "What was proven" not in render_markdown(package)
    assert "What was proven" not in render_html(package)


def test_report_lists_duplicate_proofs_and_points_a_duplicate_at_its_primary(tmp_path: Path) -> None:
    package = _observed_package(tmp_path, duplicates=[{
        "suspicion_id": "S3", "package": "packages/S3",
        "model_location": {"file": "vulnerable/archive.py", "line": 70},
        "model_hypothesis": "[click](javascript:alert(1)) <b>x</b>",
        "observed_location": {"file": "vulnerable/archive.py", "line": 63}}])
    markdown = render_markdown(package)
    section = markdown.split("## Duplicate proofs", 1)[1].split("## Accounting", 1)[0]
    assert "`S3`" in section and "packages/S3" in section and "vulnerable/archive.py:63" in section
    assert "vulnerable/archive.py:70" in section and "the model's guess" in section
    assert "<b>" not in section and "](javascript" not in section
    assert "<li><code>S3</code>" in render_html(package)
    (tmp_path / "dup").mkdir()
    duplicate = _observed_package(tmp_path / "dup", duplicate_of="S1")
    assert "duplicate of `S1`" in render_markdown(duplicate)


def test_hostile_observed_location_is_inert_or_ignored(tmp_path: Path) -> None:
    package = _observed_package(tmp_path, observed_location={
        "file": "<script>alert(1)</script>@evil", "line": 63, "function": "<b>x</b>",
        "line_source": "[x](javascript:y)"})
    evidence = json.loads((package / "evidence.json").read_text(encoding="utf-8"))
    evidence["facts"]["observed_location"] = evidence["observed_location"]
    evidence["facts"]["entry_point"] = "<img src=x onerror=alert(1)>"
    (package / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")
    markdown, document = render_markdown(package), render_html(package)
    for text in (markdown, document):
        assert "<script>" not in text and "<img" not in text
    assert "<b>x" not in markdown and "<b>x" not in document
    assert "&lt;script&gt;alert(1)&lt;/script&gt;@evil:63" in document
    assert "](javascript" not in markdown and "@evil" not in markdown.replace("@\u200bevil", "")
    (tmp_path / "bad").mkdir()
    garbage = _observed_package(tmp_path / "bad", observed_location={"file": 7, "line": "x"})
    evidence = json.loads((garbage / "evidence.json").read_text(encoding="utf-8"))
    evidence["facts"] = "not a mapping"
    (garbage / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")
    assert "Oracle-observed" not in render_markdown(garbage)
