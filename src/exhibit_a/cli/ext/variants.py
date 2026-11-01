"""Implementation of the ``variants`` CLI subcommand (extension module).

``exhibit-a variants --run-dir RUN --repo CLONE`` reads the proven findings of a finished run
(``RUN/packages/*/evidence.json``: effect, entry point and the oracle's admitted frame chain),
builds the static call graph of the clone and lists candidate variants with
:mod:`exhibit_a.graph.variants`: other entry points into the same sink function, other
non-constant call sites of the same sink rule, and structurally similar callers. That listing
needs no model and no key (``--list-only``).

Without ``--list-only`` every runnable candidate, best first and at most ``--max`` of them,
goes through the normal verification loop with the graph's entry point and slice, the same
code path ``exhibit-a run --slice`` uses: :func:`exhibit_a.graph.slicer.make_plan` and
:class:`exhibit_a.loop.pipeline.VerificationLoop`, with roles from
:func:`exhibit_a.cli.run._live_roles` and the sandbox runner from
:func:`exhibit_a.cli.run._sandbox_runner_cls`; nothing of it is copied here. Results land in
``RUN/variants/<n>/`` and ``RUN/variants.json`` links every proven variant to the original
finding id. A variant whose proof shows the same effect through the same frames as an original
finding is reported as that finding again, not as a new one.

A candidate is a proposal from the graph. Only a proven variant is a finding, and no proven
variant means nothing could be proven, never that the code is safe.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from exhibit_a.findings.dedupe import proof_key
from exhibit_a.graph import build_graph
from exhibit_a.graph.variants import ProvenFinding, Variant, VariantList, hunt, load_findings

VARIANTS_SCHEMA_VERSION = "1"
DEFAULT_MAX = 5
NOTE = ("A candidate is a proposal from the static call graph: reachability is not exploitability. "
        "Only a proven variant is a finding; no proven variant means nothing could be proven, "
        "never that the code is safe.")

RolesFactory = Callable[[Any], Any]
RunnerFactory = Callable[[], Any]


def _build_roles(args: argparse.Namespace, meter: Any) -> Any:
    """Live roles exactly as ``exhibit-a run`` builds them (imported lazily: list-only needs none)."""
    from exhibit_a.cli.run import _live_roles

    return _live_roles(args, meter)


def _default_runner(requirements: tuple[str, ...], sql_db: str | None) -> Any:
    from exhibit_a.cli.run import _sandbox_runner_cls

    return _sandbox_runner_cls()(requirements=requirements, sql_db=sql_db)


def _default_baseline(repo: Path) -> str:
    """The baseline test ``run --case`` stages in its clone, else the repository's own tests."""
    return "test_baseline.py" if (repo / "test_baseline.py").is_file() else "."


def collect(
    run_dir: str | Path, repo: str | Path, *, max_count: int = DEFAULT_MAX,
    declared_entries: list[str] | tuple[str, ...] = (),
) -> tuple[Any, list[ProvenFinding], list[dict[str, str]], list[VariantList]]:
    """Read the run's proven findings and list each one's candidates on the clone's graph."""
    findings, skipped = load_findings(run_dir)
    graph = build_graph(Path(repo))
    lists = hunt(graph, findings, root=repo, max_count=max_count, declared_entries=declared_entries)
    return graph, findings, skipped, lists


def _numbered(lists: list[VariantList]) -> list[tuple[int, VariantList, Variant]]:
    """Every listed candidate with its number (1-based, finding order, then rank)."""
    out: list[tuple[int, VariantList, Variant]] = []
    for vlist in lists:
        for variant in vlist.variants:
            out.append((len(out) + 1, vlist, variant))
    return out


def _document(
    run_dir: Path, repo: Path, mode: str, max_count: int, graph: Any, skipped: list[dict[str, str]],
    lists: list[VariantList], statuses: dict[int, str],
) -> dict[str, Any]:
    numbers = {id(v): n for n, _, v in _numbered(lists)}
    findings = []
    for vlist in lists:
        item = vlist.to_json()
        for cand, variant in zip(item["candidates"], vlist.variants):
            n = numbers[id(variant)]
            cand["n"] = n
            cand["status"] = statuses.get(n, "listed")
        findings.append(item)
    return {
        "schema_version": VARIANTS_SCHEMA_VERSION,
        "generated": datetime.now(timezone.utc).isoformat(),
        "run_dir": str(run_dir),
        "repo": str(repo),
        "mode": mode,
        "max": max_count,
        "graph": graph.stats.model_dump(),
        "findings": findings,
        "skipped_packages": skipped,
        "variants": [],
        "proven_variants": [],
        "budget_usd": None,
        "spent_usd": 0.0,
        "stopped": "list-only" if mode == "list-only" else "completed",
        "note": NOTE,
    }


def _write(path: Path, doc: dict[str, Any]) -> None:
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def list_variants(
    run_dir: str | Path, repo: str | Path, *, max_count: int = DEFAULT_MAX,
    declared_entries: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    """List candidates and write ``RUN/variants.json`` (mode ``list-only``); no model is called."""
    run_path, repo_path = Path(run_dir), Path(repo)
    graph, _, skipped, lists = collect(run_path, repo_path, max_count=max_count,
                                       declared_entries=declared_entries)
    doc = _document(run_path, repo_path, "list-only", max_count, graph, skipped, lists, {})
    _write(run_path / "variants.json", doc)
    return doc


def _same_as(facts: Any, originals: list[ProvenFinding]) -> str | None:
    """The original finding a variant's proof repeats (same effect and frames), if any."""
    key = proof_key(facts)
    if key is None:
        return None
    for finding in originals:
        if proof_key(finding.facts()) == key:
            return finding.finding_id
    return None


def run_variants(
    run_dir: str | Path,
    repo: str | Path,
    *,
    roles_factory: RolesFactory,
    runner_factory: RunnerFactory,
    max_count: int = DEFAULT_MAX,
    budget_usd: float | None = None,
    baseline: str | None = None,
    profile: str = "standard",
    requirements: tuple[str, ...] = (),
    sql_db: str | None = None,
    declared_entries: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    """List candidates, then prove at most ``max_count`` runnable ones with the normal loop.

    One :class:`CostMeter` is shared by every candidate and checked before each one starts, so
    the budget is passed by at most the model call that crossed it (as in ``exhibit-a audit``).
    Writes ``RUN/variants/<n>/`` per candidate tried and ``RUN/variants.json``; returns the latter.
    """
    from exhibit_a.graph.slicer import make_plan
    from exhibit_a.ledger import Ledger
    from exhibit_a.loop.pipeline import VerificationLoop
    from exhibit_a.models import BudgetExceeded
    from exhibit_a.models.cost import CostMeter

    if max_count < 1:
        raise ValueError("max must be at least 1")
    run_path, repo_path = Path(run_dir).resolve(), Path(repo).resolve()
    graph, findings, skipped, lists = collect(run_path, repo_path, max_count=max_count,
                                              declared_entries=declared_entries)
    baseline = baseline or _default_baseline(repo_path)
    meter = CostMeter(budget_usd) if budget_usd is not None else None
    statuses: dict[int, str] = {}
    tried: list[dict[str, Any]] = []
    proven: list[dict[str, Any]] = []
    stopped = "completed"
    attempts = 0
    for n, vlist, variant in _numbered(lists):
        if not variant.runnable:
            statuses[n] = "not_run: no entry point reaches the call site"
            continue
        if stopped != "completed":
            statuses[n] = f"not_run: {stopped}"
            continue
        if attempts >= max_count:
            stopped = "max"
            statuses[n] = "not_run: max"
            continue
        if meter is not None:
            try:
                meter.check()
            except BudgetExceeded:
                stopped = "budget"
                statuses[n] = "not_run: budget"
                continue
        attempts += 1
        out = run_path / "variants" / str(n)
        out.mkdir(parents=True, exist_ok=True)
        assert variant.path is not None
        plan = make_plan(graph, repo_path, [variant.path])
        run_id = f"variant-{n}"
        entry: dict[str, Any] = {
            "n": n, "variant_of": vlist.finding.finding_id, "original_package": vlist.finding.package,
            "run_id": run_id, "dir": f"variants/{n}", "entry_point": variant.entry_point,
            "sink": f"{variant.sink_node} -> {variant.sink_target} (line {variant.sink_line})",
            "kinds": list(variant.kinds), "proven": [],
        }
        try:
            loop = VerificationLoop(
                repo_path, out, Ledger(out / "ledger.jsonl"), roles_factory(meter), baseline,
                run_id=run_id, runner=runner_factory(), effect=variant.effect,
                prompt_profile=profile, slice_plan=plan, requirements=requirements, sql_db=sql_db,
            )
            result = loop.run(variant.source_file)
        except BudgetExceeded:
            entry["status"] = "budget_exceeded"
            stopped = "budget"
        except Exception as exc:  # noqa: BLE001 - a model or runner failure ends this candidate only
            entry["status"] = f"error: {type(exc).__name__}: {str(exc)[:300]}"
        else:
            if result.aborted:
                entry["status"] = f"aborted: {result.aborted}"
            else:
                entry["status"] = "nothing_proven"
                for r in result.findings:
                    again = _same_as(r.facts, findings)
                    package = (f"variants/{n}/{r.package_dir.relative_to(out).as_posix()}"
                               if r.package_dir is not None else None)
                    item = {
                        "n": n,
                        "variant_of": vlist.finding.finding_id,
                        "original_package": vlist.finding.package,
                        "suspicion_id": r.suspicion.id,
                        "package": package,
                        "effect": variant.effect,
                        "entry_point": (r.facts or {}).get("entry_point", variant.entry_point),
                        "sink_function": (r.facts or {}).get("sink_function"),
                        "observed_location": (r.facts or {}).get("observed_location"),
                        "fix_verified": r.fix_verified,
                        "fix_incomplete": r.fix_incomplete,
                        "distinct_from_original": None if r.facts is None else again is None,
                    }
                    entry["proven"].append(item)
                    if again is not None:
                        item["same_as_finding"] = again
                    else:
                        proven.append(item)
                if any(p.get("same_as_finding") is None for p in entry["proven"]):
                    entry["status"] = "proven_variant"
                elif entry["proven"]:
                    entry["status"] = "same_as_original"
        statuses[n] = entry["status"]
        tried.append(entry)
        (out / "variant.json").write_text(
            json.dumps({"candidate": variant.to_json() | {"n": n}, "outcome": entry}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    doc = _document(run_path, repo_path, "run", max_count, graph, skipped, lists, statuses)
    doc.update({
        "variants": tried,
        "proven_variants": proven,
        "budget_usd": budget_usd,
        "spent_usd": round(meter.total_usd, 6) if meter is not None else 0.0,
        "stopped": stopped,
        "baseline": baseline,
        "profile": profile,
    })
    _write(run_path / "variants.json", doc)
    return doc


# -- CLI --------------------------------------------------------------------------------------


def _print_listing(doc: dict[str, Any]) -> None:
    for finding in doc["findings"]:
        print(f"finding {finding['finding_id']} [{finding['effect']}] {finding['entry_point']} -> "
              f"{finding['sink_function']} ({finding['sink_file']}:{finding['sink_line']}"
              + (f", {finding['sink_call']}" if finding["sink_call"] else "") + ")")
        if finding["note"]:
            print(f"  {finding['note']}")
        if not finding["candidates"]:
            print("  no candidate variant on the graph")
        for cand in finding["candidates"]:
            where = cand["path"] or f"{cand['sink_node']} -> {cand['sink_target']} (line {cand['sink_line']}); " \
                                    "no entry point reaches it"
            extra = f" similarity={cand['similarity']}" if cand["similarity"] is not None else ""
            print(f"  {cand['n']}. [{', '.join(cand['kinds'])}] {where}")
            print(f"     entry point: {cand['entry_point']}  file: {cand['source_file']}{extra}  "
                  f"status: {cand['status']}")
        if finding["considered"] > finding["listed"]:
            print(f"  ... {finding['considered'] - finding['listed']} more below the --max cut")
        if finding["constant_sites_skipped"]:
            print(f"  {finding['constant_sites_skipped']} same-rule call(s) with only constant arguments not listed")
    for skip in doc["skipped_packages"]:
        print(f"skipped {skip['package']}: {skip['reason']}")
    listed = sum(len(f["candidates"]) for f in doc["findings"])
    print(f"listed {listed} candidate variant(s) for {len(doc['findings'])} proven finding(s); "
          "a candidate is not a finding until the loop proves it")


def cmd_variants(args: argparse.Namespace) -> int:
    """List (and unless --list-only, prove) variants of a run's proven findings."""
    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        print(f"variants: run directory does not exist: {run_dir}", file=sys.stderr)
        return 2
    repo = Path(args.repo) if args.repo else run_dir / "clone"
    if not repo.is_dir():
        print(f"variants: repository does not exist: {repo} (pass --repo)", file=sys.stderr)
        return 2
    if args.max < 1:
        print("variants: --max must be at least 1", file=sys.stderr)
        return 2
    declared = list(args.entry_point or [])
    if args.list_only:
        doc = list_variants(run_dir, repo, max_count=args.max, declared_entries=declared)
        _print_listing(doc)
        print(f"wrote {run_dir / 'variants.json'}")
        return 0
    if args.budget_usd is not None and args.budget_usd <= 0:
        print("variants: --budget-usd must be positive", file=sys.stderr)
        return 2
    requirements = tuple(args.requirement or ())
    try:
        doc = run_variants(
            run_dir, repo,
            roles_factory=lambda meter: _build_roles(args, meter),
            runner_factory=lambda: _default_runner(requirements, args.sql_db),
            max_count=args.max, budget_usd=args.budget_usd, baseline=args.baseline,
            profile=args.profile, requirements=requirements, sql_db=args.sql_db,
            declared_entries=declared,
        )
    except ValueError as exc:
        print(f"variants: {exc}", file=sys.stderr)
        return 2
    _print_listing(doc)
    for item in doc["proven_variants"]:
        print(f"PROVEN VARIANT {item['n']} of {item['variant_of']}: {item['entry_point']} -> "
              f"{item['sink_function']} package={item['package']} fix_verified={item['fix_verified']}")
    print(json.dumps({"status": doc["stopped"], "tried": len(doc["variants"]),
                      "proven_variants": len(doc["proven_variants"]), "spent_usd": doc["spent_usd"]},
                     sort_keys=True))
    print(f"wrote {run_dir / 'variants.json'}")
    return 0


def register(sub: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Add the ``variants`` subcommand to the CLI."""
    parser = sub.add_parser(
        "variants",
        help="After a proof, list (and prove) the same bug on other graph paths.",
    )
    parser.add_argument("--run-dir", required=True, help="A finished run's output directory (with packages/).")
    parser.add_argument("--repo", default=None,
                        help="The clone the run proved against (default: RUN_DIR/clone).")
    parser.add_argument("--max", type=int, default=DEFAULT_MAX,
                        help="Most candidates listed per finding and most loop runs in total.")
    parser.add_argument("--budget-usd", type=float, default=None, help="Hard cost limit in USD.")
    parser.add_argument("--list-only", action="store_true",
                        help="Only list candidates; call no model, need no key, spend nothing.")
    parser.add_argument("--provider", default=None, help="Model provider for every role.")
    parser.add_argument("--model", default=None, help="Model name for every role.")
    parser.add_argument("--profile", choices=("standard", "compact"), default="standard",
                        help="Prompt profile for the verification loop.")
    parser.add_argument("--baseline", default=None,
                        help="Baseline test in the clone (default: test_baseline.py if present, else '.').")
    parser.add_argument("--requirement", action="append", default=None,
                        help="A pinned package the sandbox installs (repeatable).")
    parser.add_argument("--sql-db", default=None, help="The app's SQLite database (canary_sql findings).")
    parser.add_argument("--entry-point", action="append", default=None,
                        help="Declared entry point (repeatable); replaces detection, the proven one is kept.")
    parser.set_defaults(func=cmd_variants)
