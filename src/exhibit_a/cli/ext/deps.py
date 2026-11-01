"""Implementation of the ``deps`` CLI subcommand (extension module).

``exhibit-a deps --repo DIR`` looks up the pinned dependencies of a repository in OSV, asks
the static call graph whether an entry point of the application reaches each advisory's
affected symbols, prints a table (advisory | package version | severity | reachable? |
proven? | fixed by) and writes ``deps.json`` (docs/reference/dependency-proofs.md).

Without ``--prove`` no model is called and nothing is executed: the graph reads the code
with ``ast`` only. With ``--prove`` every reachable advisory whose class maps to an oracle
effect runs through the proof loop in the sandbox, against the installed vulnerable version,
and the fix it verifies is the upgrade to the first fixed version.

Exit codes: 0 nothing proven, 10 at least one advisory proven, 1 lookup or run failure,
2 bad arguments.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _backend(args: argparse.Namespace):  # noqa: ANN202
    from exhibit_a.advisory import HttpOsvBackend, RecordedOsvBackend

    return RecordedOsvBackend.from_file(args.offline) if args.offline else HttpOsvBackend()


def _build_roles(args: argparse.Namespace, meter):  # noqa: ANN001, ANN202
    from exhibit_a.cli.run import _live_roles

    return _live_roles(args, meter)


def cmd_deps(args: argparse.Namespace) -> int:
    """Advisories for pinned dependencies, reachability through the graph, optional proof."""
    from exhibit_a.advisory import AdvisoryDataError
    from exhibit_a.advisory.deps_report import prove_reachable, relative_label, render_table, scan, write_report

    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"deps: repository does not exist: {repo}", file=sys.stderr)
        return 2
    if args.prove and args.budget_usd is None:
        print("deps: --prove needs --budget-usd (a hard cost limit for the model calls)", file=sys.stderr)
        return 2
    if args.budget_usd is not None and args.budget_usd <= 0:
        print("deps: --budget-usd must be positive", file=sys.stderr)
        return 2
    try:
        backend = _backend(args)
        result = scan(repo, backend, requirements=args.requirements, include_tests=args.include_tests,
                      repo_label=relative_label(args.repo))
    except (OSError, UnicodeError, ValueError, AdvisoryDataError) as exc:
        print(f"deps: lookup failed: {exc}", file=sys.stderr)
        return 1
    if not result.inputs.dependencies and not result.inputs.unsupported:
        print("deps: no dependencies found: give --requirements FILE, or add requirements.txt or "
              "pyproject.toml to the repository", file=sys.stderr)
        return 2
    report = result.report
    out = Path(args.out)
    if args.prove:
        try:
            report = prove_reachable(
                result, repo, out, lambda meter: _build_roles(args, meter),
                budget_usd=args.budget_usd, profile=args.profile, provider=args.provider, model=args.model,
                baseline=args.baseline,
            )
        except ValueError as exc:
            print(f"deps: cannot build the model roles: {exc}", file=sys.stderr)
            return 1
    path = write_report(report, out)
    print(render_table(report))
    print(f"deps.json {path}")
    return 10 if report.counts.proven else 0


def register(sub: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Add the ``deps`` subcommand to the CLI."""
    parser = sub.add_parser(
        "deps",
        help="Dependency advisories: reachable through the app's call graph? proven in the sandbox?",
    )
    parser.add_argument("--repo", required=True, help="Repository directory to analyse.")
    parser.add_argument("--requirements", default=None,
                        help="Requirements file (or pyproject.toml) with the pinned dependencies; default: "
                             "requirements.txt, pyproject.toml or case.json in the repository.")
    parser.add_argument("--offline", default=None, metavar="FIXTURE",
                        help="Answer from a recorded OSV fixture ({'vulns': [...]}) instead of api.osv.dev.")
    parser.add_argument("--out", default="deps-out", help="Output directory for deps.json (and proofs).")
    parser.add_argument("--include-tests", action="store_true",
                        help="Count pytest test functions as entry points (off: test-only uses are not reachable).")
    parser.add_argument("--prove", action="store_true",
                        help="Run the proof loop on reachable advisories (calls models; needs --budget-usd).")
    parser.add_argument("--budget-usd", type=float, default=None, help="Hard cost limit in USD for --prove.")
    parser.add_argument("--provider", default=None, help="Model provider for every role (--prove).")
    parser.add_argument("--model", default=None, help="Model name for every role (--prove).")
    parser.add_argument("--profile", choices=("standard", "compact"), default="compact",
                        help="Prompt profile for the proof loop; compact carries the advisory in the test contract.")
    parser.add_argument("--baseline", default=None,
                        help="Repository-relative test that must pass before and after the upgrade "
                             "(default: a generated check that the application module imports).")
    parser.set_defaults(func=cmd_deps)
