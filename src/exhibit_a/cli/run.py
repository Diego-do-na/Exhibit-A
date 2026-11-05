"""Implementation of the ``run`` CLI subcommand."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
import io
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..ci.summary import build_result
from ..graph import build_graph, find_paths, functions_in, reach_from_diff
from ..graph.catalog import _constant_string
from ..graph.slicer import SlicePlan, make_plan
from ..ledger import Ledger, append_run
from ..loop import Roles, SandboxRunner, VerificationLoop
from ..loop import pipeline as _loop_pipeline
from ..loop import runner as _loop_runner
from ..models import BudgetExceeded, CostMeter, ModelError, ModelRole, ReplayProvider, Role
from ..models.config import RoleConfig, build_roles
from ..oracle.js import JS_SUFFIXES
from ..schemas import Event, EventType, RunRecord, VerdictCounts
from ..schemas.graph import CodeGraph, ReachReport

#: Provider and model used for live runs when the caller names none. They are
#: dev defaults (a local Ollama model); pass explicit values once the argument
#: parser exposes --provider/--model flags.
LIVE_PROVIDER_DEFAULT = "ollama"
LIVE_MODEL_DEFAULT = "llama3.1:8b"

PR_MAX_FILES = 100
PR_MAX_FILE_BYTES = 1_000_000
PR_MAX_TOTAL_BYTES = 10_000_000
PR_MAX_DIFF_BYTES = 20_000_000


@dataclass(frozen=True)
class DiffEntry:
    status: str
    path: str
    old_path: str | None = None
    binary: bool = False


#: Source suffixes a PR-diff run ever opens (Python, JavaScript, TypeScript).
PR_SUFFIXES = frozenset({".py", *JS_SUFFIXES})


def _validate_changed_path(raw: str, repo: Path, language: str = "python") -> Path:
    """Validate a Git path before it is opened as untrusted PR data."""
    path = Path(raw)
    if not raw or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe changed path: {raw!r}")
    candidate = (repo / path)
    resolved_repo = repo.resolve()
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(resolved_repo):
        raise ValueError(f"changed path escapes repository: {raw!r}")
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"changed path is not a regular file: {raw!r}")
    if language in JS_LANGUAGES:
        if path.suffix.lower() not in JS_SUFFIXES:
            raise ValueError(f"changed path is not JavaScript/TypeScript: {raw!r}")
    elif path.suffix.lower() != ".py":
        raise ValueError(f"changed path is not Python: {raw!r}")
    if candidate.stat().st_size > PR_MAX_FILE_BYTES:
        raise ValueError(f"changed file is too large: {raw!r}")
    try:
        data = candidate.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read changed file {raw!r}: {exc}") from exc
    if b"\x00" in data:
        raise ValueError(f"changed file is binary: {raw!r}")
    return resolved


def _validate_path_shape(raw: str) -> None:
    path = Path(raw)
    if not raw or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe changed path: {raw!r}")


def parse_name_status(data: bytes, *, max_bytes: int = PR_MAX_DIFF_BYTES) -> list[DiffEntry]:
    """Parse `git diff --name-status -z` without interpreting PR-controlled text."""
    if len(data) > max_bytes:
        raise ValueError("git diff is too large")
    fields = data.split(b"\0")
    entries: list[DiffEntry] = []
    i = 0
    while i < len(fields) and fields[i]:
        try:
            status = fields[i].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ValueError("git diff contains a non-UTF-8 status") from exc
        i += 1
        if not status or status[0] not in "AMCDRTUXB":
            raise ValueError(f"unsupported git diff status: {status!r}")
        count = 2 if status[0] == "R" or status[0] == "C" else 1
        names: list[str] = []
        for _ in range(count):
            if i >= len(fields) or not fields[i]:
                raise ValueError("truncated git diff name-status record")
            try:
                names.append(fields[i].decode("utf-8", "strict"))
            except UnicodeDecodeError as exc:
                raise ValueError("git diff contains a non-UTF-8 path") from exc
            i += 1
        entries.append(DiffEntry(status[0], names[-1], names[0] if count == 2 else None))
    return entries


def _git_diff(repo: Path, spec: str) -> list[DiffEntry]:
    if spec.count("..") != 1:
        raise ValueError("--pr-diff must be BASE..HEAD")
    base, head = spec.split("..")
    if not base or not head or any(c.isspace() for c in (base + head)):
        raise ValueError("--pr-diff must contain non-empty commit names")
    cmd = [
        "git", "-C", str(repo), "diff", "--name-status", "-z",
        "--no-ext-diff", "--no-textconv", f"{base}..{head}", "--",
    ]
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"could not compute PR diff: {exc}") from exc
    if proc.returncode:
        detail = proc.stderr.decode("utf-8", "replace")[-500:]
        raise ValueError(f"could not compute PR diff: {detail}")
    return parse_name_status(proc.stdout)


def _stage_head(repo: Path, head: str, out: Path) -> Path:
    """Materialize exactly HEAD from Git, never the caller's mutable worktree."""
    clone = out / "clone"
    if clone.exists():
        shutil.rmtree(clone)
    clone.mkdir(parents=True)
    proc = subprocess.run(
        ["git", "-C", str(repo), "archive", "--format=tar", head],
        check=False, capture_output=True, timeout=60,
    )
    if proc.returncode:
        raise ValueError(f"could not stage head commit: {proc.stderr.decode('utf-8', 'replace')[-500:]}")
    with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r:") as archive:
        root = clone.resolve()
        for member in archive.getmembers():
            target = (clone / member.name).resolve()
            if not target.is_relative_to(root):
                raise ValueError("Git archive contains a path outside the repository")
            archive.extract(member, clone)
    return clone


def _pr_roles(args: argparse.Namespace) -> Roles:
    recording = getattr(args, "recording", None) or os.environ.get("EXHIBIT_A_REPLAY_RECORDING")
    if not recording:
        raise ValueError("PR-diff runs require --recording or EXHIBIT_A_REPLAY_RECORDING")
    provider = ReplayProvider(recording)
    return Roles(*(ModelRole(role, provider) for role in (
        Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))


def _run_meta(args: argparse.Namespace, *, base: str = "", head: str = "") -> dict[str, Any]:
    """Provider, model, budget and SHAs the dashboard should persist, never invent."""
    budget = getattr(args, "budget_usd", None)
    return {
        "base_sha": str(base or ""),
        "head_sha": str(head or ""),
        "provider": str(getattr(args, "provider", None) or ""),
        "model": str(getattr(args, "model", None) or ""),
        "budget_usd": float(budget) if budget is not None else None,
    }


def _write_result(
    out: Path,
    ledger: Ledger,
    run_id: str,
    code: int,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = build_result(ledger.read_all(), run_id=run_id, engine_exit=code)
    if extra:
        result.update(extra)
    (out / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _append_run_index(
    out: Path,
    result: dict[str, Any],
    repo: Path,
    head: str,
    started: float,
    *,
    base: str = "",
    provider: str = "",
    model: str = "",
    budget_usd: float | None = None,
) -> None:
    verdicts = result["verdicts"]
    status = "completed" if result["status"] == "completed" else "aborted"
    record = RunRecord(
        run_id=result["run_id"], repo=str(repo), commit=head,
        base_sha=base, provider=provider, model=model, budget_usd=budget_usd,
        ts=datetime.now(timezone.utc),
        status=status,
        proven_raw=int(result.get("proven_raw", verdicts.get("proven", 0))),
        verdict_counts=VerdictCounts(
            proven=int(result["proven"]),  # unique findings: duplicate proofs of one effect grouped
            discarded_unproven=int(verdicts.get("discarded_unproven", 0)),
            invalid_test=int(verdicts.get("invalid_test", 0)),
            flaky=int(verdicts.get("flaky", 0)),
            env_failure=int(verdicts.get("env_failure", 0)),
        ),
        severity="high" if result["proven"] else None,
        discarded_suspicions=int(result["dropped"]),
        tokens_in=int(result["tokens_in"]), tokens_out=int(result["tokens_out"]),
        cost_usd=float(result["cost_usd"]), duration_s=max(0.0, time.monotonic() - started),
        ledger_path="ledger.jsonl",
    )
    append_run(out / "runs.jsonl", record)


# -- SLICE (on by default with --profile compact) ----------------------------------------


def _slice(args: argparse.Namespace) -> bool:
    """Whether to slice: --slice / --no-slice win; otherwise on exactly for the compact profile."""
    explicit = getattr(args, "slice", None)
    if explicit is not None:
        return bool(explicit)
    return _profile(args) == "compact"


#: Source languages verified through the Node sandbox and oracle.
JS_LANGUAGES = ("javascript", "typescript")


def _resolve_language(flag: str | None, declared: str = "", clone: Path | None = None) -> str:
    """The loop language: an explicit --lang wins, then the case's own declaration.

    Otherwise the staged clone is auto-detected (package.json, tsconfig.json, case.json
    language, file extensions). Anything the loop cannot verify falls back to python,
    the historical behaviour for every repository.
    """
    if flag and flag != "auto":
        return flag
    if declared in ("python", *JS_LANGUAGES):
        return declared
    if clone is not None:
        try:
            from ..scan import detect as _detect

            seen = _detect(str(clone)).profile.language
        except (OSError, ValueError):
            seen = ""
        if seen in ("python", *JS_LANGUAGES):
            return seen
    return "python"


def _baseline_name(case_baseline: str, language: str) -> str:
    """The staged baseline file name: the historical test_baseline.py for Python."""
    if language in JS_LANGUAGES:
        return "test_baseline.ts" if language == "typescript" else "test_baseline.js"
    return "test_baseline.py"


NOTHING_REACHABLE = "nothing_reachable"

#: Oracle effects a sliced PR run may derive when ``--effect`` is omitted.
#: ``canary_access`` (IDOR) is not in this list: the graph has no sink call for it
#: (docs/reference/code-graph.md). ``canary_redirect`` is not derived here either.
PR_DERIVED_EFFECTS: tuple[str, ...] = (
    "canary_exec",
    "canary_sql",
    "canary_write",
    "canary_connect",
    "canary_read",
    "canary_dos",
)

_SKIP_DB_DIRS = frozenset({".git", ".venv", "venv", "node_modules", "__pycache__", ".tox"})
_DB_SUFFIXES = frozenset({".db", ".sqlite", ".sqlite3"})


def pr_derived_effects(report: ReachReport, language: str = "python") -> list[str]:
    """Effects the oracle can prove on paths the diff actually reaches, in budget order."""
    allowed = {"canary_read", "canary_exec"} if language in JS_LANGUAGES else set(PR_DERIVED_EFFECTS)
    seen = {p.sink.effect for p in report.paths if p.sink.effect in allowed}
    return [effect for effect in PR_DERIVED_EFFECTS if effect in seen]


def discover_sql_db(clone: Path, graph: CodeGraph) -> str | None:
    """One relative sqlite file to seed for ``canary_sql``, or None (fail closed).

    Prefers a unique constant path passed to ``sqlite3.connect`` in the graph; otherwise
    a unique regular ``.db`` / ``.sqlite`` / ``.sqlite3`` file in the clone. Zero or
    several matches return None so the SQL effect is skipped rather than guessed.
    """
    from exhibit_a.oracle.oracle import sql_db_problem

    named: list[str] = []
    for edge in graph.edges:
        if edge.kind != "external" or edge.dst != "sqlite3.connect" or not edge.args:
            continue
        constant = _constant_string(edge.args[0])
        if not constant or sql_db_problem(clone, constant) is not None:
            continue
        if constant not in named:
            named.append(constant)
    if len(named) == 1:
        return named[0]
    found: list[str] = []
    for path in sorted(clone.rglob("*")):
        if path.suffix.lower() not in _DB_SUFFIXES or not path.is_file() or path.is_symlink():
            continue
        if any(part in _SKIP_DB_DIRS for part in path.relative_to(clone).parts):
            continue
        rel = path.relative_to(clone).as_posix()
        if sql_db_problem(clone, rel) is None and rel not in found:
            found.append(rel)
    if len(found) == 1:
        return found[0]
    return None


def sql_skip_reason(graph: CodeGraph) -> str:
    """Why ``canary_sql`` is not run on this clone (fail closed, no model call)."""
    for edge in graph.edges:
        if edge.kind != "external" or edge.dst != "sqlite3.connect" or not edge.args:
            continue
        if _constant_string(edge.args[0]) == ":memory:":
            return (
                "canary_sql seeds a file database; this clone opens sqlite as :memory: "
                "so the effect cannot be judged; no model call was made"
            )
    return (
        "canary_sql needs one sqlite database in the clone to seed; "
        "none or more than one was found; no model call was made"
    )


def _reach_report(
    clone: Path, sources: list[str], *, diff: str | None = None,
    declared: list[str] | tuple[str, ...] = (),
    language: str = "python",
) -> tuple[CodeGraph, ReachReport, float]:
    """Build the graph of the staged clone and the reach report for ``sources``."""
    started = time.perf_counter()
    if language in JS_LANGUAGES:
        from ..graph.js_graph import build_js_graph, find_paths as js_paths
        from ..graph.js_graph import functions_in as js_functions
        from ..graph.js_graph import reach_from_diff as js_reach

        graph = build_js_graph(clone)
        seconds = round(time.perf_counter() - started, 3)
        if diff is None:
            changed = [node for source in sources for node in js_functions(graph, source)]
            report = js_paths(graph, changed, declared_entries=declared)
        else:
            report = js_reach(graph, diff, declared_entries=declared)
    else:
        graph = build_graph(clone)
        seconds = round(time.perf_counter() - started, 3)
        if diff is None:
            changed = [node for source in sources for node in functions_in(graph, source)]
            report = find_paths(graph, changed, declared_entries=declared)
        else:
            report = reach_from_diff(graph, diff, declared_entries=declared)
    return graph, report, seconds


def _outside_lines(source: str, report: ReachReport) -> list[tuple[str, int]]:
    """Changed module-level (file, line) pairs in ``source``."""
    out: list[tuple[str, int]] = []
    for loc in report.changed_outside_functions:
        file, sep, raw = loc.rpartition(":")
        if not sep or file != source:
            continue
        try:
            line = int(raw)
        except ValueError:
            continue
        out.append((file, line))
    return out


def _plans_for_effect(
    graph: CodeGraph, clone: Path, sources: list[str], report: ReachReport, effect: str,
) -> dict[str, SlicePlan]:
    """One slice plan per source file that has a path to a ``effect`` sink."""
    files = {node.id: node.file for node in graph.nodes}
    plans: dict[str, SlicePlan] = {}
    for source in sources:
        paths = [p for p in report.paths if p.sink.effect == effect and files.get(p.changed) == source]
        plan = make_plan(graph, clone, paths, extra_lines=_outside_lines(source, report))
        if plan is not None:
            plans[source] = plan
    return plans


def _slice_plans(
    clone: Path, sources: list[str], effect: str, *, diff: str | None = None,
    declared: list[str] | tuple[str, ...] = (),
    language: str = "python",
) -> tuple[CodeGraph, ReachReport, dict[str, SlicePlan], float]:
    """Build the graph of the staged clone and one slice plan per source file with a path.

    The changed functions are those the diff touches, or every function of the source
    files when there is no diff (a benchmark case names a file, not a change). Only paths
    to a sink the oracle can prove with ``effect`` count: a path to any other sink could
    never end in a proof, so it is not worth a model call. Node repositories use the
    JavaScript graph (``--slice`` on a Node repository needs Docker for its builder).
    """
    graph, report, seconds = _reach_report(
        clone, sources, diff=diff, declared=declared, language=language)
    return graph, report, _plans_for_effect(graph, clone, sources, report, effect), seconds


def _emit_nothing_reachable(
    ledger: Ledger, run_id: str, graph: CodeGraph, report: ReachReport, seconds: float, effect: str,
    *, derived: bool = False,
) -> None:
    """Record that the graph found no path, so no model was called."""
    if derived:
        reason = (
            "no changed function is on a path from an entry point to a sink the oracle can "
            "prove with read, write, exec, SQL, connect or dos; canary_access (IDOR) has no "
            "sink call and is not derived; no model call was made"
        )
        other = len([p for p in report.paths if p.sink.effect not in PR_DERIVED_EFFECTS])
    else:
        reason = (
            "no changed function is on a path from an entry point to a sink the "
            f"oracle can prove with {effect}; no model call was made"
        )
        other = len(report.paths)
    ledger.append(Event(
        ts=datetime.now(timezone.utc).isoformat(), run_id=run_id, type=EventType.SCAN_DONE,
        payload={
            "status": NOTHING_REACHABLE,
            "reason": reason,
            "effect": effect,
            "changed": report.changed,
            "changed_outside_functions": report.changed_outside_functions,
            "unreached": [u.model_dump() for u in report.unreached],
            "entries": [e.oracle_name for e in report.entries],
            "paths_to_other_sinks": other,
            "graph": graph.stats.model_dump(),
            "build_seconds": seconds,
        },
    ))


def _run_pr_diff(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if not repo.is_dir():
        print(f"run: repository does not exist: {repo}", file=sys.stderr)
        return 2
    pr_number = getattr(args, "pr", None)
    if pr_number is not None and (not str(pr_number).isdigit() or len(str(pr_number)) > 10):
        print("run: --pr must be a pull request number", file=sys.stderr)
        return 2
    started = time.monotonic()
    try:
        spec = str(args.pr_diff)
        head = spec.rsplit("..", 1)[1]
        entries = _git_diff(repo, spec)
        candidates: list[str] = []
        for entry in entries:
            # Deletions have no head file to verify; renames use the new path.
            if entry.status == "D":
                continue
            if entry.status in {"R", "C"}:
                old = entry.old_path or ""
                if old == entry.path:
                    continue
            if entry.path not in candidates:
                candidates.append(entry.path)
        if len(candidates) > PR_MAX_FILES:
            raise ValueError("PR changes too many files")
        changed: list[str] = []
        total = 0
        for path in candidates:
            _validate_path_shape(path)
            if Path(path).suffix.lower() not in PR_SUFFIXES:
                continue
            changed.append(path)
        if len(changed) > PR_MAX_FILES:
            raise ValueError("PR changes too many source files")
        clone = _stage_head(repo, head, out)
        language = _resolve_language(getattr(args, "lang", None), clone=clone)
        wanted = JS_SUFFIXES if language in JS_LANGUAGES else frozenset({".py"})
        safe_changed: list[str] = []
        total = 0
        for path in changed:
            if Path(path).suffix.lower() not in wanted:
                continue
            resolved = _validate_changed_path(path, clone, language)
            total += resolved.stat().st_size
            if total > PR_MAX_TOTAL_BYTES:
                raise ValueError("changed source files exceed the total size cap")
            safe_changed.append(path)
        changed = safe_changed
        ledger = Ledger(out / "ledger.jsonl")
        run_id = f"pr-{head[:12]}"
        base = spec.split("..", 1)[0] if ".." in spec else ""
        pr_number = getattr(args, "pr", None)
        meta = _run_meta(args, base=base, head=head)
        ledger.append(Event(
            ts=datetime.now(timezone.utc).isoformat(),
            run_id=run_id,
            type=EventType.PR_OPENED,
            payload={
                "base": base,
                "base_sha": base,
                "head": head,
                "commit": head,
                "head_sha": head,
                "provider": meta["provider"],
                "model": meta["model"],
                "budget_usd": meta["budget_usd"],
                "language": language,
                **({"pr": str(pr_number)} if pr_number is not None else {}),
            },
        ))
        if not changed:
            kind = "JavaScript/TypeScript" if language in JS_LANGUAGES else "Python"
            ledger.append(Event(
                ts=datetime.now(timezone.utc).isoformat(),
                run_id=run_id, type=EventType.SCAN_DONE,
                payload={"status": "not_applicable", "reason": f"no changed regular {kind} files",
                         "entries": len(entries), "language": language},
            ))
            result = _write_result(out, ledger, run_id, 0, extra=meta)
            _append_run_index(
                out, result, repo, head, started,
                base=meta["base_sha"], provider=meta["provider"],
                model=meta["model"], budget_usd=meta["budget_usd"],
            )
            return 0
        plans_by_effect: dict[str, dict[str, SlicePlan]] = {}
        graph: CodeGraph | None = None
        report: ReachReport | None = None
        if _slice(args):
            from .scan import git_unified_diff

            graph, report, seconds = _reach_report(
                clone, changed, diff=git_unified_diff(repo, spec), language=language)
            derived = args.effect is None
            effects = [args.effect] if args.effect else pr_derived_effects(report, language)
            for effect in effects:
                plans = _plans_for_effect(graph, clone, changed, report, effect)
                if plans:
                    plans_by_effect[effect] = plans
            if not plans_by_effect:
                shown = args.effect or ",".join(PR_DERIVED_EFFECTS)
                _emit_nothing_reachable(
                    ledger, run_id, graph, report, seconds, shown, derived=derived)
                result = _write_result(out, ledger, run_id, 0, extra=meta)
                _append_run_index(
                    out, result, repo, head, started,
                    base=meta["base_sha"], provider=meta["provider"],
                    model=meta["model"], budget_usd=meta["budget_usd"],
                )
                print(json.dumps({"status": result["status"], "proven": result["proven"],
                                  "slice": NOTHING_REACHABLE}, sort_keys=True))
                return 0
            if derived:
                ledger.append(Event(
                    ts=datetime.now(timezone.utc).isoformat(), run_id=run_id,
                    type=EventType.SCAN_DONE,
                    payload={
                        "status": "derived_effects",
                        "effects": list(plans_by_effect),
                        "changed": report.changed,
                        "changed_outside_functions": report.changed_outside_functions,
                        "graph": graph.stats.model_dump(),
                        "build_seconds": seconds,
                    },
                ))
        else:
            effects = [args.effect or "canary_read"]
        try:
            meter = None if args.replay else _cost_meter(args)
        except ValueError as exc:
            print(f"run: invalid --budget-usd: {exc}", file=sys.stderr)
            return 1
        sql_db = discover_sql_db(clone, graph) if graph is not None and "canary_sql" in plans_by_effect else None
        baseline = "."
        any_proven = False
        incomplete = False
        roles = None
        for effect in effects:
            if _slice(args) and effect not in plans_by_effect:
                continue
            if meter is not None:
                try:
                    meter.check()
                except BudgetExceeded as exc:
                    print(f"run: PR-diff incomplete: {exc}", file=sys.stderr)
                    incomplete = True
                    break
            if effect == "canary_sql" and not sql_db:
                ledger.append(Event(
                    ts=datetime.now(timezone.utc).isoformat(), run_id=run_id,
                    type=EventType.SCAN_DONE,
                    payload={
                        "status": "effect_skipped",
                        "effect": effect,
                        "reason": (
                            sql_skip_reason(graph) if graph is not None
                            else "canary_sql needs one sqlite database in the clone to seed; "
                                 "none or more than one was found; no model call was made"
                        ),
                    },
                ))
                continue
            if roles is None:
                if args.replay:
                    roles = _pr_roles(args)
                else:
                    try:
                        roles = _live_roles(args, meter)
                    except ValueError as exc:
                        print(f"run: cannot build live roles: {exc}", file=sys.stderr)
                        return 1
            runner = _sandbox_runner_cls()(
                language=language,
                sql_db=sql_db if effect == "canary_sql" else None,
            )
            sources = list(plans_by_effect[effect]) if _slice(args) else changed
            for source in sources:
                loop = VerificationLoop(
                    clone, out, ledger, roles, baseline, run_id=run_id,
                    runner=runner, prompt_profile=_profile(args), effect=effect,
                    language=language,
                    **({"slice_plan": plans_by_effect[effect][source]} if _slice(args) else {}),
                )
                try:
                    result_loop = loop.run(source)
                except (BudgetExceeded, ModelError, OSError) as exc:
                    print(f"run: PR-diff incomplete: {exc}", file=sys.stderr)
                    incomplete = True
                    break
                any_proven = any_proven or bool(result_loop.proven)
                incomplete = incomplete or bool(result_loop.aborted)
            if incomplete:
                break
        code = 20 if incomplete else (10 if any_proven else 0)
        result = _write_result(out, ledger, run_id, code, extra=meta)
        _append_run_index(
            out, result, repo, head, started,
            base=meta["base_sha"], provider=meta["provider"],
            model=meta["model"], budget_usd=meta["budget_usd"],
        )
        if not getattr(args, "quiet", False):
            print(json.dumps({"status": result["status"], "proven": result["proven"]}, sort_keys=True))
        if getattr(args, "verbose", 0):
            _print_phases(ledger, run_id)
        return code
    except ValueError as exc:
        print(f"run: invalid PR diff: {exc}", file=sys.stderr)
        return 2


def _live_roles(args: argparse.Namespace, meter: CostMeter | None) -> Roles:
    """Build one role per model backend through the provider registry.

    The provider/model pair comes from the parsed args when present and falls
    back to the dev defaults otherwise, so this keeps working before and after
    the parser gains explicit flags. Every role shares one cost meter, which
    enforces the --budget-usd hard stop.
    """
    # Precedence: explicit CLI flags > environment variables > built-in defaults.
    # The dev default model applies to ollama only: silently sending it to a
    # hosted provider once produced 404s for a model id that does not exist
    # there, so any other provider without an explicit model fails closed.
    provider_name = getattr(args, "provider", None)
    if not provider_name:
        provider_name = os.environ.get("EXHIBIT_A_PROVIDER") or LIVE_PROVIDER_DEFAULT
    model = getattr(args, "model", None)
    if not model:
        model = os.environ.get("EXHIBIT_A_MODEL")
    if not model:
        if provider_name == "ollama":
            model = LIVE_MODEL_DEFAULT
        else:
            raise ValueError(
                f"run: live {provider_name} runs need --model (no default model for this provider)"
            )
    config = {
        role: RoleConfig(provider=provider_name, model=model, **_generation(args, role))
        for role in Role
    }
    by_role = build_roles(config, meter)
    return Roles(
        by_role[Role.ADVERSARY],
        by_role[Role.TEST_WRITER],
        by_role[Role.FIXER],
        by_role[Role.DEFENDER],
    )


#: Output-token ceilings per role for --profile compact. They are ceilings, not targets:
#: reasoning tokens count against them, so they stay well above a normal answer.
COMPACT_MAX_OUTPUT_TOKENS: dict[Role, int] = {
    Role.ADVERSARY: 6000,
    Role.TEST_WRITER: 8000,
    Role.FIXER: 6000,
    Role.DEFENDER: 10000,
}


def _profile(args: argparse.Namespace) -> str:
    return getattr(args, "profile", None) or "standard"


def _generation(args: argparse.Namespace, role: Role) -> dict[str, object]:
    """Reasoning effort and output cap for one role (explicit flags win over the profile)."""
    compact = _profile(args) == "compact"
    effort = getattr(args, "reasoning_effort", None) or ("minimal" if compact else "")
    cap = getattr(args, "max_output_tokens", None)
    if cap is None:
        cap = COMPACT_MAX_OUTPUT_TOKENS[role] if compact else 0
    if cap < 0:
        raise ValueError("--max-output-tokens must be >= 0")
    return {"reasoning_effort": effort, "max_output_tokens": cap}


def _cost_meter(args: argparse.Namespace) -> CostMeter | None:
    """Wrap --budget-usd in a CostMeter; None means spending is unbounded."""
    if args.budget_usd is None:
        return None
    return CostMeter(args.budget_usd)


def _sandbox_runner_cls() -> Any:
    """Return ``SandboxRunner``, honouring test monkeypatches on ``cli.run`` or ``loop.pipeline``."""
    if SandboxRunner is not _loop_runner.SandboxRunner:
        return SandboxRunner
    if _loop_pipeline.SandboxRunner is not _loop_runner.SandboxRunner:
        return _loop_pipeline.SandboxRunner
    return SandboxRunner


def _install_requirements(target: Path, requirements: list[str]) -> None:
    """Install the case's pinned dependencies into a local app root for the host and sandbox."""
    # This helper is kept for backwards-compatibility but must not leak host secrets.
    # Prefer installing inside the sandbox (SandboxRunner) instead of running pip on the host.
    if not requirements:
        return
    from ..install import safe_pip_install

    safe_pip_install(target=str(target), requirements=requirements)


def _run_case(args: argparse.Namespace) -> int:
    """Run the verification loop on one benchmark case.

    With --replay the roles answer from the case recording; without it they
    call real providers (built through the provider registry) and every test
    runs in the sandbox-backed runner.
    """
    if os.environ.get("GITHUB_ACTIONS") and not args.replay:
        print("run: --case requires --replay; live case execution is disabled", file=sys.stderr)
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
    clone.mkdir(parents=True, exist_ok=True)
    # Support either a single "tree" key or the newer "trees" mapping.
    if "trees" in settings and isinstance(settings["trees"], dict):
        tree_name = settings["trees"].get("vulnerable") or next(iter(settings["trees"].values()))
        source_tree = root / tree_name
    else:
        source_tree = root / settings.get("tree", ".")
    if source_tree.exists():
        shutil.copytree(source_tree, clone, dirs_exist_ok=True)
    # --lang wins; otherwise the case's own declaration, else the staged clone.
    declared_language = str(settings.get("language") or spec.get("language") or "")
    language = _resolve_language(getattr(args, "lang", None), declared_language, clone)
    requirements = [str(item) for item in settings.get("requirements", [])]
    if requirements and language == "python":
        # Pip pins install on the host only for Python cases: Node pins
        # (express@4.18.2 and friends) belong to the Node sandbox image, which
        # the runner builds once with the network and reuses across runs.
        try:
            _install_requirements(clone, requirements)
        except RuntimeError as exc:
            print(f"run: cannot install case requirements: {exc}", file=sys.stderr)
            return 1
    staged_baseline = _baseline_name(str(settings.get("baseline_test", "test_baseline.py")), language)
    shutil.copyfile(root / settings["baseline_test"], clone / staged_baseline)

    ledger = Ledger(out / "ledger.jsonl")
    slice_plan: SlicePlan | None = None
    if _slice(args):
        effect = settings.get("effect", "canary_read")
        source_file = settings["source_file"]
        graph, report, plans, seconds = _slice_plans(
            clone, [source_file], effect, declared=list(settings.get("entry_points") or []),
            language=language)
        slice_plan = plans.get(source_file)
        if slice_plan is None:
            _emit_nothing_reachable(ledger, case_id, graph, report, seconds, effect)
            print(f"run {case_id}: nothing reachable: no function of {source_file} is on a path "
                  f"from an entry point to a {effect} sink; no model call was made")
            print(f"ledger {out / 'ledger.jsonl'}")
            return 0
        best = slice_plan.paths[0]
        print(f"run {case_id}: slice: {len(slice_plan.paths)} path(s), best [{best.vuln_class}] "
              f"from {best.oracle_entry_point}; {len(slice_plan.slice.text)} chars instead of {source_file}")
    if args.replay:
        if "recording" in settings:
            provider = ReplayProvider(root / settings["recording"])
        else:
            # A case without a recording (archive extraction) answers from its own labelled
            # materials, the same deterministic provider the benchmark uses for it.
            try:
                from bench.corpus import load_corpus
                from bench.loop_pipeline import CaseMaterialsProvider

                provider = CaseMaterialsProvider(load_corpus(case_file)[0])
            except (ImportError, ValueError, OSError, IndexError) as exc:
                print(f"run: case {case_file} has no replay recording and its materials "
                      f"cannot be used: {exc}", file=sys.stderr)
                return 1
        roles = Roles(*(ModelRole(r, provider) for r in (
            Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
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
    req_tuple = tuple(requirements)
    sql_db = settings.get("sql_db") or None
    access_db = settings.get("access_db") or None
    access = settings.get("access") or None
    redirect_meta = bool(settings.get("redirect_meta", False))
    runner_cls = _sandbox_runner_cls()
    loop = VerificationLoop(
        clone, out, ledger, roles, staged_baseline,
        run_id=case_id,
        runner=runner_cls(
            requirements=req_tuple,
            sql_db=sql_db,
            access_db=access_db,
            access=access,
            redirect_meta=redirect_meta,
            language=language,
        ),
        requirements=req_tuple,
        sql_db=sql_db,
        access_db=access_db,
        access=access,
        redirect_meta=redirect_meta,
        effect=settings.get("effect", "canary_read"),
        prompt_profile=_profile(args),
        slice_plan=slice_plan,
        language=language,
    )
    try:
        result = loop.run(settings["source_file"])
    except BudgetExceeded as exc:
        # The ledger appends every event with fsync, so events emitted
        # before the abort are already on disk; report and exit non-zero.
        print(f"run: budget exceeded: {exc}", file=sys.stderr)
        return 1
    except ModelError as exc:
        print(f"run: model step failed: {exc}", file=sys.stderr)
        return 1
    if result.aborted:
        print(f"run: aborted: {result.aborted}", file=sys.stderr)
        return 1

    quiet = getattr(args, "quiet", False)
    if not quiet:
        print(f"run {result.run_id}: {json.dumps(result.counts())} dropped={result.dropped}")
    if result.duplicate_proofs and not quiet:
        print(f"run {result.run_id}: {len(result.proven)} proofs are {len(result.findings)} unique "
              f"finding(s); {result.duplicate_proofs} duplicate(s) of an effect already proven")
    totals = ledger.totals(result.run_id)
    if not quiet:
        print(f"run {result.run_id} totals: {json.dumps(totals, sort_keys=True)}")
    if getattr(args, "verbose", 0):
        _print_phases(ledger, result.run_id)
    packaged = [r for r in result.proven if r.package_dir is not None]
    for r in packaged:
        print(f"PACKAGE {r.package_dir} fix_verified={r.fix_verified}"
              + (f" duplicate_of={r.duplicate_of}" if r.duplicate_of else ""))
    print(f"ledger {out / 'ledger.jsonl'}")
    return 0 if any(r.fix_verified for r in packaged) else 1


LOOP_STAGES = ("BASELINE", "SUSPECT", "EXPLOIT", "RUN", "VERDICT", "FIX", "VERIFY", "PACKAGE")


def _print_phases(ledger: Ledger, run_id: str) -> None:
    """Verbose detail: how many ledger events each loop phase recorded.

    Progress is tty-only so piped ``run -v`` output stays a parseable log.
    """
    from ..ledger.trace import trace_events
    from .style import progress, progress_enabled

    if not progress_enabled():
        return
    counts: dict[str, int] = {}
    for step in trace_events(list(ledger.replay(run_id))):
        counts[step.stage] = counts.get(step.stage, 0) + 1
    for stage in LOOP_STAGES:
        progress(f"phase {stage}: {counts.get(stage, 0)} event(s)")
    for stage in sorted(set(counts) - set(LOOP_STAGES)):
        progress(f"phase {stage}: {counts[stage]} event(s)")


def cmd_run(args: argparse.Namespace) -> int:
    """Run a benchmark case or a bounded PR-diff verification."""
    if _profile(args) == "compact" and getattr(args, "replay", False):
        # Replay keys hash the prompt and schema (models/replay.py); every recording was
        # made with the standard profile, so compact prompts can never hit them.
        print("run: --profile compact cannot be combined with --replay "
              "(the recordings were made with the standard profile)", file=sys.stderr)
        return 2
    if _slice(args) and getattr(args, "replay", False):
        # Same reason: the adversary prompt carries the slice, so no recorded key matches.
        print("run: --slice cannot be combined with --replay "
              "(the recordings were made without slicing)", file=sys.stderr)
        return 2
    if args.case:
        return _run_case(args)
    if getattr(args, "pr_diff", None):
        return _run_pr_diff(args)
    print("run: one of --case or --pr-diff is required", file=sys.stderr)
    return 2
