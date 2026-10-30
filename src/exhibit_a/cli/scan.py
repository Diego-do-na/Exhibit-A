"""Implementation of the ``scan`` CLI subcommand.

``exhibit-a scan`` with no repository prints the RepoProfile placeholder, as it always did.
``exhibit-a scan REPO`` prints the RepoProfile the rule-based scanner detects. ``--graph``
adds a summary of the static call graph, and ``--pr-diff BASE..HEAD`` the reach paths of the
functions the diff changes (built on HEAD as committed, not on the worktree). The graph only
proposes where to look: reachability is not exploitability, only the sandboxed proof decides.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from ..graph import build_graph, find_entries, reach_from_diff, render, sink_hits
from ..scan import detect
from ..schemas import Baseline, RepoProfile
from ..schemas.graph import CodeGraph

#: Bytes of `git diff` output a scan reads at most.
MAX_DIFF_BYTES = 20_000_000


def _placeholder() -> RepoProfile:
    return RepoProfile(
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


def graph_summary(graph: CodeGraph, seconds: float, declared: list[str] | None = None) -> dict[str, Any]:
    """Counts, entry points and sinks of a graph, for people and for the ledger."""
    entries, missing = find_entries(graph, declared or [])
    hits = [hit for found in sink_hits(graph).values() for hit in found]
    by_class: dict[str, int] = {}
    for hit in hits:
        by_class[hit.vuln_class] = by_class.get(hit.vuln_class, 0) + 1
    return {
        "schema_version": graph.schema_version,
        "stats": graph.stats.model_dump(),
        "build_seconds": round(seconds, 3),
        "truncated": graph.truncated,
        "skipped": len(graph.skipped),
        "entries": [{"name": e.oracle_name, "kind": e.kind, "node": e.node} for e in entries],
        "undeclared_entries": missing,
        "sinks": dict(sorted(by_class.items())),
    }


def git_unified_diff(repo: Path, spec: str) -> str:
    """``git diff -U0 BASE..HEAD`` as text; the diff is untrusted data, only ever parsed."""
    if spec.count("..") != 1:
        raise ValueError("--pr-diff must be BASE..HEAD")
    base, head = spec.split("..")
    if not base or not head or any(c.isspace() for c in base + head) or (base + head).startswith("-"):
        raise ValueError("--pr-diff must contain non-empty commit names")
    cmd = ["git", "-C", str(repo), "diff", "-U0", "--no-color", "--no-ext-diff", "--no-textconv",
           f"{base}..{head}", "--"]
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"could not compute PR diff: {exc}") from exc
    if proc.returncode:
        raise ValueError(f"could not compute PR diff: {proc.stderr.decode('utf-8', 'replace')[-500:]}")
    if len(proc.stdout) > MAX_DIFF_BYTES:
        raise ValueError("git diff is too large")
    return proc.stdout.decode("utf-8", "replace")


def _scan_pr_diff(repo: Path, spec: str, declared: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    from .run import _stage_head

    diff = git_unified_diff(repo, spec)
    head = spec.split("..")[1]
    with tempfile.TemporaryDirectory(prefix="exhibit-a-scan-") as tmp:
        clone = _stage_head(repo, head, Path(tmp))
        started = time.perf_counter()
        graph = build_graph(clone)
        summary = graph_summary(graph, time.perf_counter() - started, declared)
    report = reach_from_diff(graph, diff, declared_entries=declared)
    reach = report.model_dump(mode="json")
    reach["rendered"] = [render(p) for p in report.paths]
    return summary, reach


def cmd_scan(args: argparse.Namespace) -> int:
    """Print the RepoProfile (a placeholder without a repository), plus graph and reach."""
    repo_arg = getattr(args, "repo", None)
    if not repo_arg:
        print(_placeholder().model_dump_json(indent=2))
        return 0
    repo = Path(repo_arg)
    if not repo.is_dir():
        print(f"scan: repository does not exist: {repo}", file=sys.stderr)
        return 2
    result = detect(str(repo))
    want_graph = bool(getattr(args, "graph", False))
    spec = getattr(args, "pr_diff", None)
    if not want_graph and not spec:
        print(result.profile.model_dump_json(indent=2))
        return 0
    declared = list(getattr(args, "entry_point", None) or [])
    out: dict[str, Any] = {
        "profile": result.profile.model_dump(mode="json"),
        "supported": result.supported,
        "reasons": result.reasons,
        "languages": result.languages,
    }
    try:
        if spec:
            out["graph"], out["reach"] = _scan_pr_diff(repo.resolve(), str(spec), declared)
        else:
            started = time.perf_counter()
            graph = build_graph(repo)
            out["graph"] = graph_summary(graph, time.perf_counter() - started, declared)
            graph_out = getattr(args, "graph_out", None)
            if graph_out:
                Path(graph_out).write_text(graph.model_dump_json(indent=1) + "\n", encoding="utf-8")
    except ValueError as exc:
        print(f"scan: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0
