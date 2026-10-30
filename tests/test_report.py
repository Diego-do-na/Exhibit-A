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
