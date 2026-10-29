"""The engine refuses a live `--case` run under GitHub Actions (audit F8)."""

from __future__ import annotations

from exhibit_a.cli import main


def test_case_without_replay_is_refused_under_github_actions(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    case = tmp_path / "case" / "case.json"
    case.parent.mkdir()
    case.write_text("{}")
    code = main(["run", "--case", str(case), "--out", str(tmp_path / "out")])
    assert code == 2
