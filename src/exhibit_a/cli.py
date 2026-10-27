"""Command-line interface for Exhibit A.

Run it with::

    python -m exhibit_a.cli <subcommand> [options]

There is no ``exhibit-a`` console entry point yet: ``pyproject.toml`` declares
no ``[project.scripts]`` table, so this skeleton documents the ``python -m``
invocation instead of adding one.

Skeleton subcommands (SPEC.md sections 3, 6, 9):

- ``scan`` prints a RepoProfile placeholder for the target repository.
- ``run --case <case.json> --replay`` runs the verification loop over a benchmark case
  from its recorded model answers and writes a PACKAGE directory. Without ``--case`` it
  only accepts the core-loop flags and reports the loop is not wired for them yet.
- ``ledger`` prints token, cost and verdict totals for one run id, read from a
  ledger file.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .ledger import Ledger
from .loop import Roles, VerificationLoop
from .models import ModelError, ModelRole, ReplayProvider, Role
from .schemas import Baseline, RepoProfile

# Message printed by every subcommand that has no engine behind it yet.
NOT_WIRED_YET = "not wired yet"


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the skeleton CLI."""
    parser = argparse.ArgumentParser(
        prog="exhibit_a.cli",
        description="Exhibit A skeleton CLI: proof before accusation.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser(
        "scan", help="Print a RepoProfile placeholder and exit."
    )
    scan.set_defaults(func=cmd_scan)

    run = sub.add_parser(
        "run", help="Run the core loop (wired for benchmark cases via --case)."
    )
    run.add_argument(
        "--case",
        default=None,
        help="Benchmark case.json (or its directory) to run the loop on.",
    )
    run.add_argument(
        "--out",
        default="runs/case",
        help="Output directory for the clone, ledger and packages (default: runs/case).",
    )
    run.add_argument("--repo", default=".", help="Path to the target clone.")
    run.add_argument("--diff", default=None, help="Path to the PR diff file.")
    run.add_argument(
        "--replay",
        action="store_true",
        help="Replay recorded model calls instead of calling a provider.",
    )
    run.add_argument(
        "--budget-usd",
        type=float,
        default=None,
        help="Hard cost limit in USD for this run.",
    )
    run.set_defaults(func=cmd_run)

    ledger = sub.add_parser(
        "ledger", help="Print totals for one run id from a ledger file."
    )
    ledger.add_argument("run_id", help="Run id to total up.")
    ledger.add_argument(
        "--ledger",
        default="ledger.jsonl",
        help="Path to the append-only JSONL ledger (default: ledger.jsonl).",
    )
    ledger.set_defaults(func=cmd_ledger)

    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    """Print a RepoProfile placeholder as JSON.

    The placeholder is built through the real RepoProfile schema, so the
    printed document always matches the SPEC.md contract.
    """
    _ = args  # scan takes no options yet; the scanner is a later task.
    profile = RepoProfile(
        commit="unknown",
        language="unknown",
        interpreter="unknown",
        dependency_manager="unknown",
        install_cmd="unknown",
        test_cmd="unknown",
        framework="unknown",
        dependencies=[],
        baseline=Baseline(passed=0, failed=0, seconds=0.0),
    )
    print(profile.model_dump_json(indent=2))
    return 0


def _local_baseline(clone: str, test_path: str, timeout: float) -> dict[str, Any]:
    """Run the project's own tests with plain pytest in a child process on the host.

    The default baseline runner is the Docker sandbox, which installs only pytest and has
    no network, so it cannot import a case's dependencies. Cases that need them use this
    runner instead; it is a scrubbed child process, not an isolated container.
    """
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": clone,
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", test_path]
    try:
        proc = subprocess.run(cmd, cwd=clone, env=env, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"outcome": "timeout", "exit_code": None, "stdout": "", "stderr": "", "oracle_events": []}
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
        print("run: --case needs --replay; live providers are not wired to the CLI yet", file=sys.stderr)
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

    provider = ReplayProvider(root / settings["recording"])  # no recorder: a miss raises
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
    """Run the loop on a benchmark case, or accept the core-loop flags and report not wired."""
    if args.case:
        return _run_case(args)
    print(
        f"run: the core loop is {NOT_WIRED_YET} "
        f"(repo={args.repo!r}, diff={args.diff!r}, "
        f"replay={args.replay!r}, budget_usd={args.budget_usd!r})"
    )
    return 0


def cmd_ledger(args: argparse.Namespace) -> int:
    """Print token, cost and verdict totals for one run id as JSON."""
    try:
        totals = Ledger(Path(args.ledger)).totals(args.run_id)
    except (OSError, ValueError) as exc:
        print(f"ledger: cannot read {args.ledger}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(totals, indent=2))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``python -m exhibit_a.cli``. Returns an exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
