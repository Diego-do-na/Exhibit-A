"""Implementation of the ``audit`` CLI subcommand (extension module).

``exhibit-a audit`` builds the static call graph of a whole repository, ranks
every entry-point-to-sink path the graph finds, and runs the normal
verification loop (the same code path ``exhibit-a run --slice`` uses) on the
top targets until ``--budget-usd`` or ``--max-targets`` is reached. Then it
writes ``audit.json`` and ``audit.md``: targets tried, proven findings with
packages, and untried paths listed honestly.

``--list-only`` ranks and prints the targets without calling any model, so it
needs no provider, no key, and no budget.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import get_args

from exhibit_a.audit.audit import collect_targets, run_audit


def _print_targets(repo: str | Path, out: str | Path | None = None) -> int:
    from exhibit_a.graph import render

    graph, targets = collect_targets(repo)
    _ = graph
    for i, target in enumerate(targets, 1):
        best = target.paths[0]
        print(f"{i}. {target.sink_key} [{target.effect}/{target.vuln_class}]")
        print(f"   file: {target.source_file} paths: {len(target.paths)}")
        print(f"   best: {render(best)}")
    if out is not None:
        out_path = Path(out)
        out_path.mkdir(parents=True, exist_ok=True)
        (out_path / "audit.json").write_text(
            json.dumps(
                {
                    "repo": str(repo),
                    "stopped": "list-only",
                    "targets_ranked": len(targets),
                    "targets": [t.to_json() for t in targets],
                    "tried": [],
                    "findings": [],
                    "untried": [t.to_json() for t in targets],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    print(f"ranked {len(targets)} target(s)")
    return 0


def _build_roles(args: argparse.Namespace, meter):  # noqa: ANN001, ANN202
    from exhibit_a.cli.run import _live_roles

    return _live_roles(args, meter)


def cmd_audit(args: argparse.Namespace) -> int:
    """Rank the repository's reach paths and prove the top ones."""
    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"audit: repository does not exist: {repo}", file=sys.stderr)
        return 2
    if getattr(args, "list_only", False):
        return _print_targets(repo, getattr(args, "out", None))
    budget = getattr(args, "budget_usd", None)
    if budget is not None and budget <= 0:
        print("audit: --budget-usd must be positive", file=sys.stderr)
        return 2
    max_targets = int(getattr(args, "max_targets", 10) or 10)
    if max_targets < 1:
        print("audit: --max-targets must be at least 1", file=sys.stderr)
        return 2
    out = Path(getattr(args, "out", None) or "audit-out")
    if getattr(args, "replay", None):
        print("audit: --replay is not supported; audit runs live or --list-only",
              file=sys.stderr)
        return 2

    from exhibit_a.loop import SandboxRunner

    def roles_factory(meter):  # noqa: ANN001, ANN202
        return _build_roles(args, meter)

    def runner_factory():  # noqa: ANN202
        return SandboxRunner()

    try:
        outcome = run_audit(
            repo,
            out,
            budget_usd=budget,
            max_targets=max_targets,
            roles_factory=roles_factory,
            runner_factory=runner_factory,
            profile=getattr(args, "profile", None) or "standard",
        )
    except ValueError as exc:
        print(f"audit: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": outcome.stopped,
                "targets_ranked": len(outcome.targets),
                "targets_tried": len(outcome.tried),
                "proven": len(outcome.findings),
                "spent_usd": outcome.spent_usd,
            },
            sort_keys=True,
        )
    )
    return 0


def register(sub: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Add the ``audit`` subcommand to the CLI."""
    from exhibit_a.oracle.oracle import Effect

    parser = sub.add_parser(
        "audit",
        help="Audit a whole repository: rank graph reach paths and prove the top targets.",
    )
    parser.add_argument("--repo", required=True, help="Repository directory to audit.")
    parser.add_argument(
        "--out", default="audit-out", help="Output directory for audit.json/audit.md."
    )
    parser.add_argument(
        "--budget-usd", type=float, default=None, help="Hard cost limit in USD."
    )
    parser.add_argument(
        "--max-targets", type=int, default=10, help="Most sink targets to attempt."
    )
    parser.add_argument(
        "--list-only",
        action="store_true",
        help="Only rank and print targets; call no model and spend nothing.",
    )
    parser.add_argument(
        "--profile",
        choices=("standard", "compact"),
        default="standard",
        help="Prompt profile for the verification loop.",
    )
    parser.add_argument("--provider", default=None, help="Model provider for every role.")
    parser.add_argument("--model", default=None, help="Model name for every role.")
    parser.add_argument(
        "--effect",
        choices=get_args(Effect),
        default=None,
        help="Reserved: audit already covers every provable effect; ignored.",
    )
    parser.set_defaults(func=cmd_audit)
