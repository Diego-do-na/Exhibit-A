"""Idempotent ``exhibit-a init``: template diff, --update/.bak, scan files."""

from __future__ import annotations

import json

from exhibit_a.cli import main
from exhibit_a.cli.ext.init import compact_graph_summary, workflow_text


def _tiny_python_repo(root) -> None:
    (root / "app.py").write_text(
        "def handle_request(path):\n    return open(path).read()\n",
        encoding="utf-8",
    )
    (root / "tests").mkdir()
    (root / "tests" / "test_app.py").write_text(
        "import unittest\n\nclass T(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n",
        encoding="utf-8",
    )


def test_init_is_idempotent_when_the_template_matches(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _tiny_python_repo(tmp_path)
    assert main(["init"]) == 0
    target = tmp_path / ".github" / "workflows" / "exhibit-a.yml"
    assert target.read_text(encoding="utf-8") == workflow_text()
    capsys.readouterr()
    assert main(["init"]) == 0
    err = capsys.readouterr().err
    assert "differs" not in err
    assert not target.with_name(target.name + ".bak").exists()


def test_init_prints_a_short_diff_then_update_keeps_a_bak(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _tiny_python_repo(tmp_path)
    assert main(["init"]) == 0
    target = tmp_path / ".github" / "workflows" / "exhibit-a.yml"
    target.write_text("stale workflow\n", encoding="utf-8")
    capsys.readouterr()
    assert main(["init"]) == 2
    err = capsys.readouterr().err
    assert "--update" in err and "--force" in err
    assert "stale workflow" in err
    assert main(["init", "--update"]) == 0
    bak = target.with_name(target.name + ".bak")
    assert bak.read_text(encoding="utf-8") == "stale workflow\n"
    assert target.read_text(encoding="utf-8") == workflow_text()


def test_init_force_overwrites_without_a_bak(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _tiny_python_repo(tmp_path)
    assert main(["init"]) == 0
    target = tmp_path / ".github" / "workflows" / "exhibit-a.yml"
    target.write_text("stale\n", encoding="utf-8")
    assert main(["init", "--force"]) == 0
    assert target.read_text(encoding="utf-8") == workflow_text()
    assert not target.with_name(target.name + ".bak").exists()


def test_init_writes_profile_and_graph_summary(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _tiny_python_repo(tmp_path)
    assert main(["init"]) == 0
    out = capsys.readouterr().out
    profile = json.loads((tmp_path / ".exhibit-a" / "profile.json").read_text(encoding="utf-8"))
    summary = json.loads((tmp_path / ".exhibit-a" / "graph-summary.json").read_text(encoding="utf-8"))
    assert profile["language"] == "python"
    assert profile["framework"] == "unittest"
    assert profile["test_cmd"] == "python -m unittest"
    assert summary["schema_version"] == "1"
    assert summary["available"] is True
    assert summary["status"] == "built"
    assert "files" in summary["stats"]
    assert ".exhibit-a/profile.json" in out
    assert ".exhibit-a/graph-summary.json" in out
    assert "exhibit-a dashboard" in out
    assert "gh secret set EXHIBIT_A_API_KEY --env exhibit-a" in out
    text = (tmp_path / ".github" / "workflows" / "exhibit-a.yml").read_text(encoding="utf-8")
    assert "name: exhibit-a / analyze" in text
    assert "fail-on: never" in text
    assert "name: exhibit-a / verify" in text
    assert "needs: analyze" in text


def test_compact_graph_summary_matches_artifact_schema_keys():
    raw = {
        "schema_version": "1",
        "stats": {"files": 2, "nodes": 4, "edges": 1, "resolved": 1, "external": 0, "unresolved": 0},
        "build_seconds": 0.01,
        "entries": [{"name": "app.handle_request", "kind": "http"}],
    }
    compact = compact_graph_summary(raw)
    assert set(compact) >= {
        "schema_version", "available", "status", "effect", "reason", "stats",
        "build_seconds", "entries", "changed", "paths", "paths_to_other_sinks", "source_file",
    }
    assert compact["entries"] == ["app.handle_request"]
    assert compact["available"] is True
