"""Compare installed static analyzers with Exhibit A on the benchmark corpus.

The analyzers are deliberately treated as external tools. Their reports are parsed into
the same ``Finding`` shape used by ``bench.baseline`` and scored by its exact matching
rules. Missing tools are represented as unmeasured, never as zero findings.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .baseline import (
    FIXED,
    INCOMPLETE,
    Finding,
    Score,
    canonical_class,
    canonical_file,
    combine,
    score_findings,
)
from .corpus import Case, load_corpus

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "bench" / "corpus"
RESULTS = REPO / "bench" / "results"
DOC = REPO / "docs" / "bench" / "tools.md"
BEGIN_MARKER = "<!-- BEGIN GENERATED: python -m bench.tools_compare -->"
END_MARKER = "<!-- END GENERATED -->"

# These are installation pins, not copied rules. CodeQL is distributed as a CLI rather
# than a pip package and is therefore reported at the installed CLI version.
PINNED_TOOLS = {"bandit": "1.8.6", "semgrep": "1.141.0"}


@dataclass(frozen=True)
class ToolFinding:
    finding: Finding
    rule: str = ""
    cwe: str = ""


@dataclass(frozen=True)
class Tree:
    case: Case
    role: str
    name: str
    path: Path
    truth_tree: str = ""


@dataclass
class ToolRun:
    tool: str
    version: str | None
    status: str
    error: str = ""
    findings: list[ToolFinding] | None = None


def _cwe_class(value: Any) -> str:
    text = str(value or "").lower()
    if "22" in text or "path traversal" in text or "zip slip" in text:
        return "path_traversal"
    if "78" in text or "command injection" in text or "shell injection" in text:
        return "command_injection"
    if "502" in text or "deserialization" in text or "pickle" in text:
        return "insecure_deserialization"
    return canonical_class(text)


def _class_for(rule: Any, cwe: Any, message: Any = "") -> str:
    candidate = _cwe_class(cwe)
    if candidate and candidate != canonical_class(""):
        return candidate
    return canonical_class(f"{rule} {message}")


def _relative(path: str, root: Path | None) -> str:
    value = path.replace("\\", "/")
    if root:
        try:
            value = Path(path).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            value = path.replace("\\", "/")
    return canonical_file(value)


def parse_bandit(data: str | bytes | dict[str, Any], root: Path | None = None) -> list[ToolFinding]:
    """Parse Bandit's JSON report."""
    raw = json.loads(data) if isinstance(data, (str, bytes)) else data
    findings: list[ToolFinding] = []
    for item in raw.get("results", []):
        cwe = (item.get("issue_cwe") or {}).get("id", "")
        rule = item.get("test_id", "")
        message = item.get("issue_text", "")
        findings.append(ToolFinding(
            Finding(_class_for(rule, cwe, message), _relative(item.get("filename", ""), root),
                    int(item.get("line_number") or 0)),
            rule, str(cwe),
        ))
    return findings


def _semgrep_cwes(metadata: dict[str, Any]) -> str:
    cwe = metadata.get("cwe", "")
    if isinstance(cwe, list):
        return " ".join(str(item) for item in cwe)
    return str(cwe)


def parse_semgrep(data: str | bytes | dict[str, Any], root: Path | None = None) -> list[ToolFinding]:
    """Parse Semgrep's JSON report."""
    raw = json.loads(data) if isinstance(data, (str, bytes)) else data
    findings: list[ToolFinding] = []
    for item in raw.get("results", []):
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        rule = item.get("check_id", "")
        cwe = _semgrep_cwes(metadata)
        message = extra.get("message", "")
        start = item.get("start") or {}
        findings.append(ToolFinding(
            Finding(_class_for(rule, cwe, message), _relative(item.get("path", ""), root),
                    int(start.get("line") or 0)),
            rule, cwe,
        ))
    return findings


def parse_codeql(data: str | bytes | dict[str, Any], root: Path | None = None) -> list[ToolFinding]:
    """Parse CodeQL SARIF (the CLI's standard machine-readable output)."""
    raw = json.loads(data) if isinstance(data, (str, bytes)) else data
    findings: list[ToolFinding] = []
    for run in raw.get("runs", []):
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        rule_meta = {r.get("id", ""): r for r in rules}
        for item in run.get("results", []):
            rule = item.get("ruleId", "")
            descriptor = rule_meta.get(rule, {})
            props = descriptor.get("properties") or {}
            tags = props.get("tags") or []
            cwe = " ".join(str(tag) for tag in tags)
            message = (item.get("message") or {}).get("text", "")
            locations = item.get("locations") or [{}]
            physical = (locations[0].get("physicalLocation") or {})
            artifact = (physical.get("artifactLocation") or {}).get("uri", "")
            region = physical.get("region") or {}
            findings.append(ToolFinding(
                Finding(_class_for(rule, cwe, message), _relative(artifact, root),
                        int(region.get("startLine") or 0)),
                rule, cwe,
            ))
    return findings


PARSERS: dict[str, Callable[[str | bytes | dict[str, Any], Path | None], list[ToolFinding]]] = {
    "Bandit": parse_bandit,
    "Semgrep": parse_semgrep,
    "CodeQL": parse_codeql,
}


def score_tool(findings: Iterable[ToolFinding], tree: Tree) -> Score:
    return score_findings([item.finding for item in findings], tree.case.ground_truth,
                          tree.role, tree.truth_tree)


def _tree(case: Case, role: str, name: str, path: Path) -> Tree:
    truth_tree = case.tree if case.tree else ""
    return Tree(case, role, name, path, truth_tree)


def discover_trees(corpus: Iterable[Case]) -> list[Tree]:
    """Return each shipped vulnerable, fixed, and incomplete source tree."""
    trees: list[Tree] = []
    tools_available = any(shutil.which(name) for name in ("bandit", "semgrep", "codeql"))
    staging = Path(tempfile.mkdtemp(prefix="exhibit_a_static_tools_")) if tools_available else None
    for case in corpus:
        case_dir = Path(case.case_dir)
        raw = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
        run = raw.get("run") or {}
        declared = run.get("trees") or {}
        if declared:
            for role, dirname in declared.items():
                path = case_dir / dirname
                if not path.is_dir() and staging and role == "vulnerable" and case.tree:
                    path = _stage_case(case, staging / case.id / role)
                if not path.is_dir() and staging and role == "fixed":
                    fixed_case = Case(case.id, FIXED, case.repo, case.commit,
                                      case.ground_truth, case.synthetic, case.case_dir, "fixed",
                                      case.baseline_test, case.recording, case.requirements,
                                      case.effect, case.source_file, case.sql_db)
                    path = _stage_case(fixed_case, staging / case.id / role)
                if path.is_dir() or not tools_available:
                    trees.append(_tree(case, role if role != "fixed_incomplete" else INCOMPLETE,
                                       f"{case.id}/{role}", path))
        elif case.tree and (case_dir / case.tree).is_dir():
            trees.append(_tree(case, case.kind, case.id, case_dir / case.tree))
        elif case.tree:
            path = _stage_case(case, staging / case.id / case.kind) if staging else case_dir / case.tree
            trees.append(_tree(case, case.kind, case.id, path))
    return trees


def _version(executable: str) -> str | None:
    try:
        result = subprocess.run([executable, "--version"], capture_output=True, text=True,
                                check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (result.stdout or result.stderr).strip().splitlines()[0] or None


def _run_json(tool: str, tree: Tree, executable: str) -> ToolRun:
    commands = {
        "Bandit": [executable, "-r", str(tree.path), "-f", "json", "-q"],
        "Semgrep": [executable, "--config", "p/python", "--json", "--quiet", str(tree.path)],
    }
    try:
        result = subprocess.run(commands[tool], capture_output=True, text=True, check=False,
                                timeout=300, env={**os.environ, "SEMGREP_SEND_METRICS": "off"})
        if result.returncode not in (0, 1):
            return ToolRun(tool, _version(executable), "not run",
                           (result.stderr or result.stdout).strip()[:300])
        parser = PARSERS[tool]
        return ToolRun(tool, _version(executable), "measured",
                       findings=parser(result.stdout, tree.path))
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return ToolRun(tool, _version(executable), "not run", str(exc))


def run_tool(tool: str, tree: Tree) -> ToolRun:
    executable = shutil.which({"Bandit": "bandit", "Semgrep": "semgrep", "CodeQL": "codeql"}[tool])
    if not executable:
        return ToolRun(tool, None, "not run", "executable not found")
    if tool in ("Bandit", "Semgrep"):
        return _run_json(tool, tree, executable)
    version = _version(executable)
    with tempfile.TemporaryDirectory(prefix="exhibit_a_codeql_") as work:
        database = Path(work) / "db"
        sarif = Path(work) / "results.sarif"
        create = subprocess.run(
            [executable, "database", "create", str(database), "--language=python",
             "--source-root", str(tree.path), "--overwrite"],
            capture_output=True, text=True, check=False, timeout=300,
        )
        if create.returncode:
            return ToolRun("CodeQL", version, "not run", create.stderr.strip()[:300])
        analyze = subprocess.run(
            [executable, "database", "analyze", str(database),
             "codeql/python-queries:codeql-suites/python-security-extended.qls",
             "--format=sarif-latest", f"--output={sarif}", "--download", "none"],
            capture_output=True, text=True, check=False, timeout=600,
        )
        if analyze.returncode:
            return ToolRun("CodeQL", version, "not run", analyze.stderr.strip()[:300])
        try:
            return ToolRun("CodeQL", version, "measured",
                           findings=parse_codeql(sarif.read_text(encoding="utf-8"), tree.path))
        except (OSError, json.JSONDecodeError) as exc:
            return ToolRun("CodeQL", version, "not run", str(exc))


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def _score_cells(score: Score) -> str:
    return f"{score.reported} | {score.true_positives} | {score.false_positives} | {score.false_accusations} | {_fmt(score.precision)} | {_fmt(score.recall)}"


def compare(corpus: Iterable[Case]) -> dict[str, Any]:
    trees = discover_trees(corpus)
    rows: list[dict[str, Any]] = []
    systems: dict[str, list[Score]] = {"Bandit": [], "Semgrep": [], "CodeQL": []}
    for tree in trees:
        for tool in PARSERS:
            run = run_tool(tool, tree)
            score = score_tool(run.findings or [], tree) if run.status == "measured" else None
            row = {"tool": tool, "target": tree.name, "role": tree.role, "status": run.status,
                   "version": run.version, "error": run.error}
            if score is not None:
                row.update({"reported": score.reported, "true_positives": score.true_positives,
                            "false_positives": score.false_positives,
                            "false_accusations": score.false_accusations,
                            "precision": score.precision, "recall": score.recall})
                systems[tool].append(score)
            rows.append(row)
    return {"rows": rows, "systems": {tool: _score_dict(combine(parts)) for tool, parts in systems.items()}}


def _score_dict(score: Score) -> dict[str, Any]:
    return {"reported": score.reported, "true_positives": score.true_positives,
            "false_positives": score.false_positives, "false_accusations": score.false_accusations,
            "precision": score.precision, "recall": score.recall}


def exhibit_rows() -> list[dict[str, Any]]:
    """Read the latest replayed Exhibit A aggregate from bench/results, if present."""
    files = sorted(f for f in RESULTS.glob("*.json") if not f.name.startswith("tools-"))
    if not files:
        return []
    data = json.loads(files[-1].read_text(encoding="utf-8"))
    return [{"tool": key, "status": "measured", **value}
            for key, value in data.get("systems", {}).items()]


def render_document(result: dict[str, Any]) -> str:
    lines = [
        "Static tools are run as installed, with Bandit 1.8.6 and Semgrep 1.141.0 pinned for reproducibility. "
        "A missing CLI is **not run**, never zero findings.",
        "",
        "| tool | target tree | role | status | reported | TP | FP | false accusations | precision | recall |",
        "|---|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in result["rows"]:
        if row["status"] == "measured":
            cells = f"{row['reported']} | {row['true_positives']} | {row['false_positives']} | {row['false_accusations']} | {_fmt(row['precision'])} | {_fmt(row['recall'])}"
        else:
            cells = "- | - | - | - | - | -"
        lines.append(f"| {row['tool']} | {row['target']} | {row['role']} | {row['status']} | {cells} |")
    lines += ["", "Headline totals (measured rows only):", "",
              "| tool | reported | TP | FP | false accusations | precision | recall |",
              "|---|---:|---:|---:|---:|---:|---:|"]
    for tool, score in result["systems"].items():
        status = "not run" if not any(row["tool"] == tool and row["status"] == "measured"
                                      for row in result["rows"]) else "measured"
        if status == "not run":
            lines.append(f"| {tool} | not run | - | - | - | - | - |")
        else:
            lines.append(f"| {tool} | {score['reported']} | {score['true_positives']} | "
                         f"{score['false_positives']} | {score['false_accusations']} | "
                         f"{_fmt(score['precision'])} | {_fmt(score['recall'])} |")
    lines += ["", "Exhibit A aggregate rows (from existing replayed recordings/results):", "",
              "| system | reported | TP | FP | false accusations | precision | recall |",
              "|---|---:|---:|---:|---:|---:|---:|"]
    for row in result.get("exhibit_a", []):
        lines.append(f"| {row['tool']} | {row.get('reported', 0)} | {row.get('true_positives', 0)} | "
                     f"{row.get('false_positives', 0)} | {row.get('false_accusations', 0)} | "
                     f"{_fmt(row.get('precision'))} | {_fmt(row.get('recall'))} |")
    lines += ["", "Exhibit A rows come from the existing replayed recordings and benchmark results; "
              "they are not rerun as a static tool. Static tools are fast and free and cover classes "
              "Exhibit A cannot prove. Exhibit A reports less and proves what it reports."]
    return "\n".join(lines) + "\n"


def update_doc(path: Path, generated: str) -> None:
    text = path.read_text(encoding="utf-8") if path.exists() else (
        "# Benchmark: static tools versus Exhibit A\n\n"
        "## Results\n\n" + BEGIN_MARKER + "\n" + END_MARKER + "\n"
    )
    before, marker, rest = text.partition(BEGIN_MARKER)
    _, end, after = rest.partition(END_MARKER)
    if not marker or not end:
        raise ValueError(f"{path} lacks generated-section markers")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{before}{BEGIN_MARKER}\n{generated}{END_MARKER}{after}", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--out", type=Path, default=RESULTS)
    parser.add_argument("--doc", type=Path, default=DOC)
    args = parser.parse_args(argv)
    try:
        result = compare(load_corpus(args.corpus))
        result["exhibit_a"] = exhibit_rows()
        args.out.mkdir(parents=True, exist_ok=True)
        output = args.out / f"tools-{datetime.now(timezone.utc):%Y-%m-%d}.json"
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        update_doc(args.doc, render_document(result))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"tools_compare: {exc}", file=sys.stderr)
        return 1
    print(f"results: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
