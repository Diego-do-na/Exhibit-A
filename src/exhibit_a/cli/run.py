"""Implementation of the ``run`` CLI subcommand."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..ledger import Ledger
from ..loop import Roles, VerificationLoop
from ..models import ModelError, ModelRole, ReplayProvider, Role


def _local_baseline(clone: str, test_path: str, timeout: float) -> dict[str, Any]:
    """Run the project's own tests in a scrubbed child process on the host."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": clone,
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", test_path]
    try:
        proc = subprocess.run(cmd, cwd=clone, env=env, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {
            "outcome": "timeout",
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "oracle_events": [],
        }
    return {
        "outcome": "passed" if proc.returncode == 0 else "failed",
        "exit_code": proc.returncode,
        "stdout": proc.stdout.decode(errors="replace"),
        "stderr": proc.stderr.decode(errors="replace"),
        "oracle_events": [],
    }


def _run_case(args: argparse.Namespace) -> int:
    """Run the verification loop on one benchmark case from its recorded answers."""
    if not args.replay:
        print(
            "run: --case needs --replay; live providers are not wired to the CLI yet",
            file=sys.stderr,
        )
        return 2
    case_file = Path(args.case)
    if case_file.is_dir():
        case_file /= "case.json"
    try:
        spec = json.loads(case_file.read_text(encoding="utf-8"))
        settings = spec["run"]
        case_id = spec["cases"][0]["id"]
    except (OSError, ValueError, KeyError, IndexError) as exc:
        print(f"run: cannot read case {case_file}: {exc}", file=sys.stderr)
        return 1
    root = case_file.parent
    out = Path(args.out).resolve()
    clone = out / "clone"
    if clone.exists():
        shutil.rmtree(clone)
    shutil.copytree(root / settings["tree"], clone)
    shutil.copyfile(root / settings["baseline_test"], clone / "test_baseline.py")

    provider = ReplayProvider(root / settings["recording"])
    roles = Roles(*(ModelRole(r, provider) for r in (
        Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
    ledger = Ledger(out / "ledger.jsonl")
    loop = VerificationLoop(
        clone, out, ledger, roles, "test_baseline.py",
        run_id=case_id, baseline_runner=_local_baseline,
    )
    try:
        result = loop.run(settings["source_file"])
    except ModelError as exc:
        print(f"run: model step failed: {exc}", file=sys.stderr)
        return 1
    if result.aborted:
        print(f"run: aborted: {result.aborted}", file=sys.stderr)
        return 1

    print(f"run {result.run_id}: {json.dumps(result.counts())} dropped={result.dropped}")
    packaged = [r for r in result.proven if r.package_dir is not None]
    for r in packaged:
        print(f"PACKAGE {r.package_dir} fix_verified={r.fix_verified}")
    print(f"ledger {out / 'ledger.jsonl'}")
    return 0 if any(r.fix_verified for r in packaged) else 1


def cmd_run(args: argparse.Namespace) -> int:
    """Run a benchmark case or report that the core loop is not wired."""
    if args.case:
        return _run_case(args)
    print(
        f"run: the core loop is not wired yet "
        f"(repo={args.repo!r}, diff={args.diff!r}, "
        f"replay={args.replay!r}, budget_usd={args.budget_usd!r})"
    )
    return 0
