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
from ..loop import Roles, SandboxRunner, VerificationLoop
from ..models import CostMeter, ModelError, ModelRole, ReplayProvider, Role
from ..models.config import RoleConfig, build_roles

#: Provider and model used for live runs when the caller names none. They are
#: dev defaults (a local Ollama model); pass explicit values once the argument
#: parser exposes --provider/--model flags.
LIVE_PROVIDER_DEFAULT = "ollama"
LIVE_MODEL_DEFAULT = "llama3.1:8b"


def _live_roles(args: argparse.Namespace, meter: CostMeter | None) -> Roles:
    """Build one role per model backend through the provider registry.

    The provider/model pair comes from the parsed args when present and falls
    back to the dev defaults otherwise, so this keeps working before and after
    the parser gains explicit flags. Every role shares one cost meter, which
    enforces the --budget-usd hard stop.
    """
    provider_name = getattr(args, "provider", None) or LIVE_PROVIDER_DEFAULT
    model = getattr(args, "model", None) or LIVE_MODEL_DEFAULT
    config = {
        role: RoleConfig(provider=provider_name, model=model) for role in Role
    }
    by_role = build_roles(config, meter)
    return Roles(
        by_role[Role.ADVERSARY],
        by_role[Role.TEST_WRITER],
        by_role[Role.FIXER],
        by_role[Role.DEFENDER],
    )


def _cost_meter(args: argparse.Namespace) -> CostMeter | None:
    """Wrap --budget-usd in a CostMeter; None means spending is unbounded."""
    if args.budget_usd is None:
        return None
    return CostMeter(args.budget_usd)


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
    """Run the verification loop on one benchmark case.

    With --replay the roles answer from the case recording; without it they
    call real providers (built through the provider registry) and every test
    runs in the sandbox-backed runner.
    """
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

    ledger = Ledger(out / "ledger.jsonl")
    if args.replay:
        provider = ReplayProvider(root / settings["recording"])
        roles = Roles(*(ModelRole(r, provider) for r in (
            Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
        loop = VerificationLoop(
            clone, out, ledger, roles, "test_baseline.py",
            run_id=case_id, baseline_runner=_local_baseline,
        )
    else:
        try:
            meter = _cost_meter(args)
        except ValueError as exc:
            print(f"run: invalid --budget-usd: {exc}", file=sys.stderr)
            return 1
        try:
            roles = _live_roles(args, meter)
        except ValueError as exc:
            print(f"run: cannot build live roles: {exc}", file=sys.stderr)
            return 1
        loop = VerificationLoop(
            clone, out, ledger, roles, "test_baseline.py",
            run_id=case_id,
            runner=SandboxRunner(
                requirements=tuple(settings.get("requirements", ()))
            ),
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
