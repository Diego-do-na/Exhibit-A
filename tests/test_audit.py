"""Repository audit: ranked graph targets, budget cap, and --list-only output.

No Docker and no network: the loop runs with a host baseline plus the host
oracle (like ``tests/test_run_live.py``) and a scripted provider, so these
tests prove the audit orchestration, not the sandbox.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from exhibit_a.audit.audit import collect_targets, run_audit
from exhibit_a.audit.rank import effect_severity, entry_exposure, rank_key
from exhibit_a.cli import main as cli_main
from exhibit_a.loop import Roles
from exhibit_a.models import Completion, ModelRole, Role
from exhibit_a.models.cost import Pricing
from exhibit_a.oracle import run_oracle


def _write(repo: Path, name: str, text: str) -> None:
    (repo / name).write_text(text, encoding="utf-8")


def _three_effects_repo(repo: Path) -> None:
    _write(repo, "exec_mod.py", 'import subprocess\ndef main():\n    return subprocess.run("ls")\n')
    _write(
        repo, "write_mod.py",
        'def main():\n    with open("out.txt", "w") as handle:\n        handle.write("x")\n',
    )
    _write(
        repo, "read_mod.py",
        'def main():\n    with open("in.txt") as handle:\n        return handle.read()\n',
    )


def test_effect_severity_orders_exec_before_write_before_read(tmp_path) -> None:
    _three_effects_repo(tmp_path)
    _, targets = collect_targets(tmp_path)
    assert [t.effect for t in targets] == ["canary_exec", "canary_write", "canary_read"]


def test_shorter_paths_and_network_entries_rank_first(tmp_path) -> None:
    _write(
        tmp_path, "net.py",
        "def handle(scope, receive, send):\n"
        '    return open("a.txt").read()\n',
    )
    _write(
        tmp_path, "cli.py",
        "def main():\n"
        '    return open("b.txt").read()\n',
    )
    _write(
        tmp_path, "long.py",
        "def handle(scope, receive, send):\n"
        "    return middle('c.txt')\n"
        "def middle(name):\n"
        "    return leaf(name)\n"
        "def leaf(name):\n"
        '    return open(name).read()\n',
    )
    # Entry exposure and path length order the rank keys directly.
    assert entry_exposure("asgi") < entry_exposure("cli_main")
    _, targets = collect_targets(tmp_path)
    by_file = {t.source_file: t for t in targets}
    assert set(by_file) == {"net.py", "cli.py", "long.py"}
    ordered = [t.source_file for t in targets]
    # Network entry beats CLI at the same length; the short chain beats the long one.
    assert ordered.index("net.py") < ordered.index("cli.py")
    assert ordered.index("net.py") < ordered.index("long.py")
    keys = {t.source_file: t.rank for t in targets}
    assert keys["net.py"] < keys["cli.py"]
    # Sanity on the raw key: severity, hops, exposure lead.
    assert rank_key(targets[0].paths[0])[0] == effect_severity("canary_read")


class _NoSuspicions:
    """One model call per target, then nothing to prove; each call costs a dime."""

    name = "audit-fake"
    pricing = Pricing()
    cost_usd = 0.10

    def complete(self, role, prompt, schema):
        assert role == Role.ADVERSARY
        return Completion('{"suspicions": []}', 10, 10, 1, model="audit-fake",
                          cost_usd=self.cost_usd)


class _HostRunner:
    """Host baseline plus host oracle: no Docker, no network."""

    def run_baseline(self, clone, test_path, timeout):
        target = Path(clone) / str(test_path)
        if target.is_dir():
            target = target / "baseline_test.py"
            target.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
            test_path = target.name
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", test_path],
            cwd=clone, capture_output=True, timeout=timeout,
            env={"PATH": __import__("os").environ["PATH"], "PYTHONPATH": clone,
                 "PYTHONDONTWRITEBYTECODE": "1"},
        )
        return {"outcome": "passed" if proc.returncode == 0 else "failed",
                "exit_code": proc.returncode, "stdout": "", "stderr": "",
                "oracle_events": []}

    def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect="canary_read"):
        return run_oracle(app_root, test_path, entry_points, timeout=timeout, effect=effect)


def _roles(meter) -> Roles:
    provider = _NoSuspicions()
    return Roles(*(ModelRole(role, provider, meter) for role in Role))


def test_budget_stops_the_audit_and_lists_everything_untried(tmp_path) -> None:
    _three_effects_repo(tmp_path)
    out = tmp_path / "out"
    outcome = run_audit(
        tmp_path, out, budget_usd=0.10, max_targets=10,
        roles_factory=_roles, runner_factory=_HostRunner,
    )
    # One dime buys the first target's single adversary call; the meter is
    # spent, so the second target never starts.
    assert outcome.stopped == "budget"
    assert len(outcome.tried) == 1
    assert outcome.spent_usd <= 0.10 + _NoSuspicions.cost_usd + 1e-9
    assert len(outcome.untried) == len(outcome.targets) - 1
    assert (out / "audit.json").exists() and (out / "audit.md").exists()
    doc = json.loads((out / "audit.json").read_text(encoding="utf-8"))
    assert doc["stopped"] == "budget"
    assert len(doc["untried"]) == len(doc["targets"]) - 1
    md = (out / "audit.md").read_text(encoding="utf-8")
    assert "Untried paths" in md and "nothing could be proven" in md


def test_max_targets_caps_the_run(tmp_path) -> None:
    _three_effects_repo(tmp_path)
    out = tmp_path / "out"
    outcome = run_audit(
        tmp_path, out, budget_usd=100.0, max_targets=1,
        roles_factory=_roles, runner_factory=_HostRunner,
    )
    assert outcome.stopped == "max_targets"
    assert len(outcome.tried) == 1
    assert len(outcome.untried) == len(outcome.targets) - 1


def test_list_only_prints_ranked_targets_and_calls_no_model(tmp_path, capsys) -> None:
    _three_effects_repo(tmp_path)

    def _boom(meter):  # pragma: no cover - must never run under --list-only
        raise AssertionError("a model was built for --list-only")

    import exhibit_a.cli.ext.audit as audit_ext

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(audit_ext, "_build_roles", _boom)
    try:
        rc = cli_main(["audit", "--repo", str(tmp_path), "--list-only"])
    finally:
        monkeypatch.undo()
    assert rc == 0
    text = capsys.readouterr().out
    assert "canary_exec" in text and "canary_write" in text and "canary_read" in text
    # Severity order shows in the printed ranking.
    assert text.index("canary_exec") < text.index("canary_write") < text.index("canary_read")
