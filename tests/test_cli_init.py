"""Idempotent ``exhibit-a init``: template diff, --update/.bak, scan files."""

from __future__ import annotations

import io
import json
import sys

from exhibit_a.cli import main
from exhibit_a.cli.ext import init as init_mod
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


def test_init_meta_base_url_renders_env_block(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _tiny_python_repo(tmp_path)
    assert main(["init", "--meta-base-url", "https://meta.example/v1/"]) == 0
    text = (tmp_path / ".github" / "workflows" / "exhibit-a.yml").read_text(encoding="utf-8")
    assert "META_BASE_URL: https://meta.example/v1" in text
    assert "__META_ENV__" not in text
    assert "META_BASE_URL" not in workflow_text()


def test_init_rejects_non_https_meta_base_url(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _tiny_python_repo(tmp_path)
    assert main(["init", "--meta-base-url", "http://plain"]) == 2
    assert "https://" in capsys.readouterr().err


def test_init_model_renders_into_workflow_and_rejects_spaces(tmp_path, monkeypatch, capsys):
    import yaml

    monkeypatch.chdir(tmp_path)
    _tiny_python_repo(tmp_path)
    assert main(["init", "--model", "muse-spark-1.3", "--meta-base-url", "https://meta.example/v1"]) == 0
    text = (tmp_path / ".github" / "workflows" / "exhibit-a.yml").read_text(encoding="utf-8")
    assert "model: muse-spark-1.3" in text
    parsed = yaml.safe_load(text)
    exhibit = parsed["jobs"]["analyze"]["steps"][1]
    assert exhibit["with"]["model"] == "muse-spark-1.3"
    assert "MODEL_API_KEY" not in text
    capsys.readouterr()
    assert main(["init", "--model", "not a model"]) == 2
    assert "--model" in capsys.readouterr().err


def test_github_slug_parses_ssh_and_https_remotes(tmp_path, monkeypatch):
    import subprocess as sp

    def fake_run(cmd, **kwargs):
        return sp.CompletedProcess(cmd, 0, stdout="git@github.com:owner/repo.git\n", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    assert init_mod._github_slug(tmp_path) == "owner/repo"

    def fake_https(cmd, **kwargs):
        return sp.CompletedProcess(cmd, 0, stdout="https://github.com/owner/repo\n", stderr="")

    monkeypatch.setattr("subprocess.run", fake_https)
    assert init_mod._github_slug(tmp_path) == "owner/repo"

    def fake_other(cmd, **kwargs):
        return sp.CompletedProcess(cmd, 0, stdout="https://gitlab.com/owner/repo.git\n", stderr="")

    monkeypatch.setattr("subprocess.run", fake_other)
    assert init_mod._github_slug(tmp_path) is None


def test_gh_setup_pipes_key_via_stdin_not_argv(monkeypatch):
    import subprocess as sp

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs.get("input")))
        return sp.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    assert init_mod._gh_setup("owner/repo", "sekret") == (True, True)
    secret_cmd, secret_input = calls[0]
    assert secret_cmd[:3] == ["gh", "secret", "set"]
    assert "sekret" not in " ".join(secret_cmd)
    assert secret_input == "sekret\n"
    assert "--env" in secret_cmd and "exhibit-a" in secret_cmd
    assert calls[1][0][:3] == ["gh", "variable", "set"]


def test_maybe_store_secrets_skips_without_a_tty(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    init_mod._maybe_store_secrets(tmp_path)
    assert capsys.readouterr().out == ""


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
