"""Benchmark: a naive "LLM reports everything" baseline versus the proof loop (SPEC section 11).

The naive reporter sends one case's source to the same Meta model, at the same reasoning
effort as the compact recordings, with a plain "list the vulnerabilities" prompt, and every
finding it returns counts as reported. Its live answers are recorded once with
RecordingProvider and replayed offline from then on:

    PYTHONPATH=src:. python -m bench.baseline --record
    PYTHONPATH=src:. python -m bench --compare baseline

Exhibit A's numbers are never read from recording metadata. Every verdict comes from replaying
the recording through the current oracle (``bench.record_meta.replay_case``), so a proof the
oracle has since learned to reject does not count. Scoring is one function for both systems.
The replay is ``replay_case`` with the provider wrapped to count calls.

Everything written to the table is a pure function of the recordings. Measured replay time
varies per run, so it stays in the ``volatile`` block of the results file, out of the table.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from exhibit_a.ledger import Ledger
from exhibit_a.models import BudgetExceeded, Completion, CostMeter, ModelError, ModelRole, ReplayProvider, Role
from exhibit_a.models.meta import DEFAULT_API_KEY_ENV, MetaProvider
from exhibit_a.models.record import RecordingProvider
from exhibit_a.schemas import EventType

from .corpus import Case
from .loop_pipeline import _pick_source_file, _stage_case
from .record_meta import (
    COMPACT_MAX_OUTPUT_TOKENS,
    COMPACT_REASONING_EFFORT,
    DEFAULT_MODEL,
    PROVIDER_TIMEOUT_S,
    _git_commit,
    _usage,
    case_dir,
    load_case,
    recording_paths,
    replay_meter,
    run_case,
)

REPO = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO / "bench" / "results"
DOC_PATH = REPO / "docs" / "bench.md"
BEGIN_MARKER = "<!-- BEGIN GENERATED: python -m bench --compare baseline -->"
END_MARKER = "<!-- END GENERATED -->"
#: Same hard cap as T070's rule for this task.
RECORD_BUDGET_USD = 3.0

NAIVE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["findings"],
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["class", "file", "line", "description"],
                "properties": {
                    "class": {"type": "string"},
                    "file": {"type": "string"},
                    "line": {"type": "integer", "minimum": 0},
                    "description": {"type": "string"},
                },
            },
        }
    },
}


def naive_prompt(source: str, file: str) -> str:
    return f'List the vulnerabilities in this code. Reply with JSON {{"findings": [...]}}.\nFILE: {file}\n{source}'


# -- ground truth ----------------------------------------------------------------------------

#: How a target's findings are scored. ``fixed`` has no vulnerability, so every finding on it is
#: a false accusation. ``incomplete`` keeps the case's ground truth: its fix is a decoy that an
#: absolute member path still defeats, so reporting traversal there is correct, not an accusation.
VULNERABLE, FIXED, INCOMPLETE = "vulnerable", "fixed", "incomplete"


@dataclass(frozen=True)
class Target:
    case_id: str
    role: str  # VULNERABLE, FIXED or INCOMPLETE
    tree: str = ""  # tree of a case that ships several; "" keeps the case's own source
    paired: bool = True  # False: no Exhibit A recording exists, so it stays out of the headline


TARGETS = (
    Target("starlette-cve-2023-29159", VULNERABLE),
    Target("starlette-cve-2023-29159-fixed", FIXED),
    Target("archive-extraction-pathtraversal", VULNERABLE),
    Target("archive-extraction-pathtraversal", FIXED, "fixed", paired=False),
    Target("archive-extraction-pathtraversal", INCOMPLETE, "fixed_incomplete", paired=False),
)

#: Ground-truth classes, each with the wordings that mean it. Matching stays literal on purpose:
#: symlink or TOCTOU findings are other claims, even when they sit near a traversal bug.
_TRAVERSAL = "path_traversal"
_CLASS_MEMBERS = {
    _TRAVERSAL: ("traversal", "zip_slip", "zipslip", "tar_slip"),
}


def canonical_class(name: str) -> str:
    """Normalize a class name: 'Path Traversal' and 'archive_extraction_path_traversal' match."""
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    for canonical, members in _CLASS_MEMBERS.items():
        if any(member in slug for member in members):
            return canonical
    return slug


def canonical_file(path: str, tree: str = "") -> str:
    """Normalize a path to tree-relative. case.json roots paths at the case, models at the tree."""
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if tree and path.startswith(tree + "/"):
        path = path[len(tree) + 1:]
    return path


def truth_keys(ground_truth: Sequence[dict[str, str]], tree: str = "") -> set[tuple[str, str]]:
    return {(canonical_class(t["class"]), canonical_file(t["file"], tree)) for t in ground_truth}


# -- metric math -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    vuln_class: str
    file: str
    line: int = 0


@dataclass
class Score:
    """One system on one or more targets. False accusations are a subset of false positives."""

    reported: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_accusations: int = 0
    truth_total: int = 0
    truth_found: int = 0
    calls: int = 0
    cost_usd: float = 0.0
    live_usd: float = 0.0  # every recorded call, including any today's oracle no longer reaches
    model_wall_s: float = 0.0
    discarded: int = 0  # suspicions raised but not reported (always 0 for the naive reporter)

    @property
    def precision(self) -> float | None:
        return self.true_positives / self.reported if self.reported else None

    @property
    def recall(self) -> float | None:
        return self.truth_found / self.truth_total if self.truth_total else None


def score_findings(
    findings: Sequence[Finding], ground_truth: Sequence[dict[str, str]], role: str, tree: str = ""
) -> Score:
    """Score findings by file + class.

    Every finding that matches a ground-truth entry is a true positive, duplicates included.
    That favours whichever system repeats itself, which here is the baseline, so it cannot
    flatter Exhibit A. Recall counts each ground-truth entry once. A fixed target has no
    vulnerability, whatever the case it was derived from declares.
    """
    truth = set() if role == FIXED else truth_keys(ground_truth, tree)
    keys = [(canonical_class(f.vuln_class), canonical_file(f.file, tree)) for f in findings]
    true_positives = sum(1 for key in keys if key in truth)
    false_positives = len(keys) - true_positives
    return Score(
        reported=len(keys),
        true_positives=true_positives,
        false_positives=false_positives,
        false_accusations=false_positives if role == FIXED else 0,
        truth_total=len(truth),
        truth_found=len(truth & set(keys)),
    )


def combine(parts: Sequence[Score]) -> Score:
    total = Score()
    for part in parts:
        for name in ("reported", "true_positives", "false_positives", "false_accusations",
                     "truth_total", "truth_found", "calls", "cost_usd", "live_usd", "model_wall_s", "discarded"):
            setattr(total, name, getattr(total, name) + getattr(part, name))
    return total


# -- the naive reporter ----------------------------------------------------------------------


def naive_paths(target: Target, model: str = DEFAULT_MODEL) -> tuple[Path, Path]:
    suffix = f"-{target.tree}" if target.tree else ""
    base = case_dir(target.case_id) / "recordings"
    return base / f"naive-{model}{suffix}.jsonl", base / f"naive-{model}{suffix}.json"


def target_case(target: Target) -> Case:
    case = load_case(target.case_id)
    return replace(case, tree=target.tree) if target.tree else case


def target_source(target: Target, out_dir: Path) -> tuple[str, str]:
    """Return (file, source) as the adversary would see it, with the tree name out of the path."""
    case = target_case(target)
    clone = _stage_case(case, out_dir / target.case_id / (target.tree or "case"))
    file = _pick_source_file(clone, case)
    return file, (clone / file).read_text(encoding="utf-8")


def run_naive(target: Target, provider: Any, out_dir: Path, meter: CostMeter | None = None) -> tuple[list[Finding], Any]:
    file, source = target_source(target, out_dir)
    result = ModelRole(Role.ADVERSARY, provider, meter).run(naive_prompt(source, file), NAIVE_SCHEMA)
    findings = [Finding(item["class"], item["file"], item["line"]) for item in result.output["findings"]]
    return findings, result


def replay_naive(target: Target, out_dir: Path, model: str = DEFAULT_MODEL) -> Score:
    recording, _ = naive_paths(target, model)
    if not recording.is_file():
        raise FileNotFoundError(f"no naive recording {recording}; record it with python -m bench.baseline --record")
    findings, result = run_naive(target, ReplayProvider(recording), out_dir)
    score = score_findings(findings, load_case(target.case_id).ground_truth, target.role, _truth_tree(target))
    score.calls = 1
    score.cost_usd = score.live_usd = result.cost_usd
    score.model_wall_s = result.latency_ms / 1000
    return score


def _truth_tree(target: Target) -> str:
    """The tree that case.json's ground-truth paths are rooted at."""
    return load_case(target.case_id).tree


def record_naive(target: Target, meter: CostMeter, out_dir: Path, overwrite: bool, model: str = DEFAULT_MODEL) -> dict[str, Any]:
    """Make the one live call for a target. A failed call is recorded as what happened."""
    recording, metadata_path = naive_paths(target, model)
    if recording.exists():
        if not overwrite:
            raise FileExistsError(f"{recording} exists; pass --overwrite to record again")
        recording.unlink()
    meta = MetaProvider(model, timeout=PROVIDER_TIMEOUT_S)
    meta.configure_generation(COMPACT_REASONING_EFFORT, COMPACT_MAX_OUTPUT_TOKENS)
    started = datetime.now(timezone.utc)
    commit = _git_commit()
    findings: list[Finding] = []
    error = ""
    try:
        findings, _ = run_naive(target, RecordingProvider(recording, meta), out_dir, meter)
    except ModelError as exc:
        error = f"{type(exc).__name__}: {exc}"
    metadata = {
        "case": target.case_id,
        "tree": target.tree,
        "role": target.role,
        "system": "naive",
        "provider": "meta",
        "model": model,
        "reasoning_effort": meta.reasoning_effort,
        "max_output_tokens": meta.max_output_tokens,
        "base_url": meta.base_url,
        "date_utc": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "exhibit_a": commit,
        "pricing_usd_per_mtok": {"input": meta.pricing.input_per_mtok, "output": meta.pricing.output_per_mtok},
        "budget_usd": meter.limit_usd,
        **_usage(recording),
        "findings": len(findings),
        "error": error,
        "recording": recording.name,
        "hand_authored": False,
    }
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metadata


# -- Exhibit A, always through the current oracle --------------------------------------------


class _Tally:
    """Counts the model calls of a replay.

    Costs come from here and not from the ledger: the loop stamps the adversary's one call on
    every suspicion_raised event, so ledger totals charge it once per suspicion.
    """

    def __init__(self, provider: Any) -> None:
        self.provider = provider
        self.name = provider.name
        self.pricing = provider.pricing
        self.calls = 0
        self.cost_usd = 0.0
        self.latency_ms = 0

    def complete(self, role: Role, prompt: str, schema: dict[str, Any]) -> Completion:
        completion = self.provider.complete(role, prompt, schema)
        self.calls += 1
        self.cost_usd += completion.cost_usd
        self.latency_ms += completion.latency_ms
        return completion


class ComparisonError(RuntimeError):
    """The replay could not produce trustworthy numbers, so no table is written."""


#: A replay that stopped this way reproduces what the live run did. Anything else is a broken run.
_EXPECTED_STOPS = {"compact": ("",), "standard": ("", "budget_exceeded", "replay_miss")}


def replay_exhibit_a(target: Target, profile: str, out_dir: Path, model: str = DEFAULT_MODEL) -> Score:
    """Score one case from the verdicts its recording obtains under today's oracle."""
    work = out_dir / target.case_id
    recording, _ = recording_paths(target.case_id, model, profile)
    tally = _Tally(ReplayProvider(recording))
    # What replay_case does, with the provider wrapped: the caps are the ones the recording had.
    outcome = run_case(load_case(target.case_id), tally, work, replay_meter(target.case_id, model, profile), profile)
    if not outcome.baseline_ok or outcome.aborted or outcome.stopped not in _EXPECTED_STOPS[profile]:
        raise ComparisonError(
            f"{target.case_id} [{profile}]: baseline_ok={outcome.baseline_ok} aborted={outcome.aborted!r} "
            f"stopped={outcome.stopped!r}: {outcome.stop_detail}"
        )
    suspicions: dict[str, Finding] = {}
    for event in Ledger(work / "ledger.jsonl").replay(target.case_id):
        if event.type == EventType.SUSPICION_RAISED:
            payload = event.payload.get("suspicion", event.payload)
            location = payload.get("location", {})
            suspicions[payload["id"]] = Finding(payload["class"], location.get("file", ""), location.get("line", 0))
    proven = [row["suspicion_id"] for row in outcome.verdicts if row["verdict"] == "proven"]
    findings = [suspicions[sid] for sid in proven]
    score = score_findings(findings, load_case(target.case_id).ground_truth, target.role, _truth_tree(target))
    score.discarded = len(suspicions) - len(findings)
    score.calls = tally.calls
    score.cost_usd = tally.cost_usd
    score.live_usd = _usage(recording)["cost_usd"]
    score.model_wall_s = tally.latency_ms / 1000
    return score


# -- the comparison --------------------------------------------------------------------------


@dataclass
class Comparison:
    per_target: list[dict[str, Any]] = field(default_factory=list)
    systems: dict[str, Score] = field(default_factory=dict)
    volatile: dict[str, Any] = field(default_factory=dict)


NAIVE_LABEL = "Naive LLM (reports everything)"
COMPACT_LABEL = "Exhibit A, compact profile"
STANDARD_LABEL = "Exhibit A, standard profile (nothing proven live)"


def _target_name(target: Target) -> str:
    return f"{target.case_id}/{target.tree}" if target.tree else target.case_id


def _row(system: str, target: Target, score: Score | None) -> dict[str, Any]:
    """One per-target row; ``score`` None means the system was not measured there."""
    return {"system": system, "target": _target_name(target), "role": target.role,
            "measured": score is not None, **(_score_dict(score) if score else {})}


def _score_dict(score: Score) -> dict[str, Any]:
    return {**asdict(score), "cost_usd": round(score.cost_usd, 6), "live_usd": round(score.live_usd, 6),
            "model_wall_s": round(score.model_wall_s, 3),
            "precision": score.precision, "recall": score.recall}


def compare(work_dir: Path, targets: Sequence[Target] = TARGETS, profiles: Sequence[str] = ("compact", "standard")) -> Comparison:
    """Replay both systems offline. Raises ComparisonError instead of reporting a broken run."""
    result = Comparison()
    naive_parts: list[Score] = []
    for target in targets:
        score = replay_naive(target, work_dir / "naive")
        result.per_target.append(_row(NAIVE_LABEL, target, score))
        if target.paired:
            naive_parts.append(score)
    result.systems[NAIVE_LABEL] = combine(naive_parts)
    labels = {"compact": COMPACT_LABEL, "standard": STANDARD_LABEL}
    for profile in profiles:
        started = time.monotonic()
        parts: list[Score] = []
        for target in targets:
            if not target.paired:
                result.per_target.append(_row(labels[profile], target, None))
                continue
            score = replay_exhibit_a(target, profile, work_dir / profile)
            parts.append(score)
            result.per_target.append(_row(labels[profile], target, score))
        result.systems[labels[profile]] = combine(parts)
        result.volatile[f"replay_wall_s_{profile}"] = round(time.monotonic() - started, 3)
    return result


def _fmt(value: float | None, spec: str = ".2f") -> str:
    return "n/a" if value is None else format(value, spec)


_COLUMNS = ("reported", "TP", "FP", "false accusations", "precision", "recall", "discarded", "calls",
            "cost (US$)", "live spend (US$)", "model wall time (s)")


def _cells(score: dict[str, Any]) -> str:
    return (
        f"{score['reported']} | {score['true_positives']} | {score['false_positives']} "
        f"| {score['false_accusations']} | {_fmt(score['precision'])} | {_fmt(score['recall'])} "
        f"| {score['discarded']} | {score['calls']} | {score['cost_usd']:.4f} | {score['live_usd']:.4f} | {score['model_wall_s']:.1f}"
    )


def render_section(result: Comparison) -> str:
    """The generated part of docs/bench.md. A pure function of the replayed recordings."""
    header = " | ".join(_COLUMNS)
    lines = [
        "Same three targets for every row: the two vulnerable cases and the fixed Starlette tree.",
        "",
        f"| system | {header} |",
        "|---|" + "---|" * len(_COLUMNS),
    ]
    for label, score in result.systems.items():
        lines.append(f"| {label} | {_cells(_score_dict(score))} |")
    lines += ["", "Per target (`-` means not measured: no recording exists for that system there):", "",
              f"| system | target | role | {header} |", "|---|---|---|" + "---|" * len(_COLUMNS)]
    blank = " | ".join("-" for _ in _COLUMNS)
    for row in result.per_target:
        cells = _cells(row) if row["measured"] else blank
        lines.append(f"| {row['system']} | {row['target']} | {row['role']} | {cells} |")
    return "\n".join(lines) + "\n"


def update_doc(doc: Path, section: str) -> None:
    """Replace only what sits between the markers, so the prose around the table stays."""
    text = doc.read_text(encoding="utf-8")
    before, begin, rest = text.partition(BEGIN_MARKER)
    _, end, after = rest.partition(END_MARKER)
    if not begin or not end:
        raise ComparisonError(f"{doc} lacks the generated-section markers")
    doc.write_text(f"{before}{BEGIN_MARKER}\n{section}{END_MARKER}{after}", encoding="utf-8")


def write_results(result: Comparison, results_dir: Path, today: str | None = None) -> Path:
    today = today or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    results_dir.mkdir(parents=True, exist_ok=True)
    path = results_dir / f"{today}.json"
    payload = {
        "model": DEFAULT_MODEL,
        "reasoning_effort_naive": COMPACT_REASONING_EFFORT,
        "systems": {label: _score_dict(score) for label, score in result.systems.items()},
        "per_target": result.per_target,
        "volatile": result.volatile,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def run_comparison(results_dir: Path = RESULTS_DIR, doc: Path = DOC_PATH, work_dir: Path | None = None) -> tuple[Comparison, Path]:
    work = work_dir or Path(tempfile.mkdtemp(prefix="exhibit_a_compare_"))
    result = compare(work)
    path = write_results(result, results_dir)
    update_doc(doc, render_section(result))
    return result, path


# -- CLI (recording only; the comparison is python -m bench --compare baseline) ---------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m bench.baseline", description=__doc__.split("\n")[0])
    parser.add_argument("--record", action="store_true", required=True, help="make the live calls once")
    parser.add_argument("--budget-usd", type=float, default=RECORD_BUDGET_USD, help="hard cap for the run")
    parser.add_argument("--overwrite", action="store_true", help="replace an existing recording")
    args = parser.parse_args(argv)
    if not os.environ.get(DEFAULT_API_KEY_ENV):
        print(f"baseline: {DEFAULT_API_KEY_ENV} is not set; export it first", file=sys.stderr)
        return 2
    if not 0 < args.budget_usd <= RECORD_BUDGET_USD:
        print(f"baseline: --budget-usd must be positive and at most {RECORD_BUDGET_USD}", file=sys.stderr)
        return 2
    meter = CostMeter(args.budget_usd)
    work = Path(tempfile.mkdtemp(prefix="exhibit_a_naive_"))
    code = 0
    for target in TARGETS:
        try:
            meta = record_naive(target, meter, work, args.overwrite)
        except FileExistsError as exc:
            print(f"baseline: {exc}", file=sys.stderr)
            code = 1
            continue
        except BudgetExceeded as exc:
            print(f"baseline: stopping before {_target_name(target)}: {exc}", file=sys.stderr)
            return 3
        print(f"{_target_name(target)}: calls={meta['calls']} tokens={meta['tokens_in']}+{meta['tokens_out']} "
              f"cost=${meta['cost_usd']:.4f} (run total ${meter.total_usd:.4f}) findings={meta['findings']} "
              f"error={meta['error'] or '-'}")
        if meta["error"]:
            code = 1
    return code


if __name__ == "__main__":
    raise SystemExit(main())
