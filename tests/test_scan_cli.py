"""``exhibit-a scan`` (SLICE, M4): the real RepoProfile, the graph summary and reach paths."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from exhibit_a.cli import main
from exhibit_a.schemas import RepoProfile
from exhibit_a.schemas.graph import CodeGraph

FIXTURES = Path(__file__).parent / "fixtures" / "graph"


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "commit.gpgsign=false", *args],
        capture_output=True, text=True, check=True,
    )
    return proc.stdout.strip()


@pytest.fixture
def repo(tmp_path):
    """A git repository holding the unreachable/ fixture, one commit."""
    root = tmp_path / "repo"
    shutil.copytree(FIXTURES / "unreachable", root)
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n[project.optional-dependencies]\ndev = ["pytest"]\n')
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    return root


def _commit_change(repo: Path, old: str, new: str) -> str:
    helpers = repo / "helpers.py"
    helpers.write_text(helpers.read_text().replace(old, new))
    _git(repo, "commit", "-q", "-am", "change")
    return _git(repo, "rev-parse", "HEAD")


def test_scan_of_a_repository_prints_the_detected_profile(repo, capsys):
    assert main(["scan", str(repo)]) == 0
    profile = RepoProfile.model_validate(json.loads(capsys.readouterr().out))
    assert (profile.language, profile.framework, profile.test_cmd) == ("python", "pytest", "pytest")


def test_scan_graph_adds_a_summary_and_can_write_the_graph(repo, tmp_path, capsys):
    out_file = tmp_path / "graph.json"
    assert main(["scan", str(repo), "--graph", "--graph-out", str(out_file)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["profile"]["language"] == "python" and out["supported"] is True
    graph = out["graph"]
    assert graph["entries"] == [{"kind": "asgi", "name": "Files.__call__", "node": "app:Files.__call__"}]
    assert graph["sinks"] == {"path_traversal": 2}
    assert graph["stats"]["files"] == 2 and graph["schema_version"] == "1"
    written = CodeGraph.model_validate_json(out_file.read_text())
    assert written.stats.model_dump() == graph["stats"]


def test_declared_entry_points_replace_detection(repo, capsys):
    assert main(["scan", str(repo), "--graph", "--entry-point", "unused", "--entry-point", "Nope.x"]) == 0
    graph = json.loads(capsys.readouterr().out)["graph"]
    assert [e["name"] for e in graph["entries"]] == ["unused"]
    assert graph["undeclared_entries"] == ["Nope.x"]


def test_scan_pr_diff_reports_the_reach_path(repo, capsys):
    base = _git(repo, "rev-parse", "HEAD")
    head = _commit_change(repo, 'return _normalise(raw).strip("/")', 'return _normalise(raw).lstrip("/")')
    assert main(["scan", str(repo), "--pr-diff", f"{base}..{head}"]) == 0
    reach = json.loads(capsys.readouterr().out)["reach"]
    assert reach["changed"] == ["helpers:format_name"]
    assert reach["rendered"] == [
        "Files.__call__ -> [format_name] -> (returns to Files.__call__) -> builtins.open (line 12)"
    ]
    assert reach["paths"][0]["oracle_entry_point"] == "Files.__call__"


def test_scan_pr_diff_of_an_unreachable_change_has_no_path(repo, capsys):
    base = _git(repo, "rev-parse", "HEAD")
    head = _commit_change(repo, "return open(value).read()", "return open(value).read(10)")
    # an uncommitted edit of a reachable function must not count: the scan reads HEAD
    (repo / "helpers.py").write_text((repo / "helpers.py").read_text().replace("strip(", "rstrip("))
    assert main(["scan", str(repo), "--pr-diff", f"{base}..{head}"]) == 0
    reach = json.loads(capsys.readouterr().out)["reach"]
    assert reach["changed"] == ["helpers:orphan"] and reach["paths"] == []
    assert reach["unreached"] == [{"node": "helpers:orphan", "reason": "no entry point reaches it"}]


@pytest.mark.parametrize("spec", ["HEAD", "a..b..c", "..HEAD", "-x..HEAD", "nope..HEAD"])
def test_scan_rejects_a_bad_diff_spec(repo, spec, capsys):
    assert main(["scan", str(repo), f"--pr-diff={spec}"]) == 2
    assert "scan:" in capsys.readouterr().err


def test_scan_of_a_missing_repository_is_a_usage_error(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "missing")]) == 2
    assert "does not exist" in capsys.readouterr().err
