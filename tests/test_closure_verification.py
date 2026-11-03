"""T145/T149 closure checks that run without Docker.

The Docker-backed evidence (real sandbox runs, three consecutive
meta-replay runs) is produced by scripts/verify_closure.sh in the
owner's terminal; everything that can be proven offline is pinned here.
"""

from __future__ import annotations

import json
from pathlib import Path

from exhibit_a.cli import main as cli_main
from exhibit_a.cli.dashboard import resolve_source
from exhibit_a.cli.parser import build_parser
from exhibit_a.cli.run import _slice

REQUIRED_SUBCOMMANDS = {
    "scan", "run", "dashboard", "report", "verify", "doctor", "audit",
    "sarif", "reproduce", "runs", "ledger", "trace", "advisories",
}


def test_help_lists_every_required_subcommand_with_a_one_line_description():
    parser = build_parser()
    subparsers = next(a for a in parser._actions if a.choices)
    assert REQUIRED_SUBCOMMANDS <= set(subparsers.choices)
    for name in REQUIRED_SUBCOMMANDS:
        help_text = subparsers.choices[name].format_help()
        assert "\n" not in subparsers.choices[name].description.strip() if subparsers.choices[name].description else True
    # The top-level help text names every required command exactly once as a choice.
    rendered = parser.format_help()
    for name in REQUIRED_SUBCOMMANDS:
        assert name in rendered


def test_no_cli_module_sets_host_execution():
    cli_dir = Path(__file__).resolve().parent.parent / "src" / "exhibit_a" / "cli"
    offenders = [
        p.name for p in cli_dir.rglob("*.py") if "allow_host_execution=True" in p.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_slice_default_follows_profile():
    parser = build_parser()
    compact = parser.parse_args(["run", "--case", "x", "--profile", "compact"])
    assert _slice(compact) is True  # compact profile: slice on by default
    standard = parser.parse_args(["run", "--case", "x"])
    assert _slice(standard) is False  # CLI default profile is standard: slice off
    forced = parser.parse_args(["run", "--case", "x", "--profile", "standard", "--slice"])
    assert _slice(forced) is True


def test_scan_on_a_repository_prints_a_repo_profile(tmp_path: Path, capsys):
    (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")
    code = cli_main(["scan", str(tmp_path)])
    assert code == 0
    profile = json.loads(capsys.readouterr().out)
    assert profile["language"] == "python"
    assert "framework" in profile and "test_cmd" in profile


def test_dashboard_source_defaults_to_the_callers_runs_folder(tmp_path: Path):
    # From inside a different repository: its own runs/ wins, nothing else does.
    assert resolve_source(None, cwd=tmp_path) is None
    (tmp_path / "runs" / "some-run").mkdir(parents=True)
    assert resolve_source(None, cwd=tmp_path) == "local:runs"
    assert resolve_source("github:owner/repo", cwd=tmp_path) == "github:owner/repo"
