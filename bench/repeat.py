"""Repeatability runs for the real case runner.

The execution adapter deliberately calls ``exhibit_a.cli.run._run_case`` rather
than reimplementing the verification loop.  The pure aggregation and document
helpers are usable with offline fake runs.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from exhibit_a.cli.run import _run_case
from exhibit_a.ledger import Ledger
from exhibit_a.schemas import EventType

from .corpus import Case, load_corpus

MARKER_START = "<!-- BEGIN REPEATABILITY -->"
MARKER_END = "<!-- END REPEATABILITY -->"
DEFAULT_CORPUS = Path(__file__).with_name("corpus")
DEFAULT_DOC = Path(__file__).parents[1] / "docs" / "bench" / "repeatability.md"


def _mode(mode: str) -> tuple[str, bool]:
    if not mode:
        raise ValueError("mode must not be empty")
    sliced = mode.endswith("-slice")
    profile = mode[:-6] if sliced else mode
    if not profile:
        raise ValueError(f"invalid mode {mode!r}")
    return profile, sliced


def _case_path(case: Case) -> str:
    if not case.case_dir:
        raise ValueError(f"case {case.id!r} is not a real case directory")
    return case.case_dir


def _ledger_run(out: Path, case: Case, run_id: str) -> dict[str, Any]:
    ledger = Ledger(out / "ledger.jsonl")
    events = list(ledger.replay(run_id))
    counts = {value: 0 for value in (
        "proven", "discarded_unproven", "invalid_test", "flaky", "env_failure",
    )}
    proven_ids: list[str] = []
    fix_verified = 0
    for event in events:
        if event.type != EventType.VERDICT:
            continue
        verdict = str(event.payload.get("verdict", ""))
        if verdict in counts:
            counts[verdict] += 1
        if verdict == "proven":
            proven_ids.append(str(event.payload.get("suspicion_id", "")))
        if event.payload.get("fix_verified") is True:
            fix_verified += 1
    totals = ledger.totals(run_id)
    return {
        "case": case.id,
        "mode": "",
        "verdict_counts": counts,
        "proven": counts["proven"],
        "fix_verified": fix_verified,
        "input_tokens": int(totals["tokens_in"]),
        "tokens": int(totals["tokens_in"]) + int(totals["tokens_out"]),
        "cost": float(totals["cost_usd"]),
        "wall_time": 0.0,
        "unique_findings": sorted({item for item in proven_ids if item}),
    }


def run_case(case: Case, mode: str, out: Path, budget_usd: float) -> dict[str, Any]:
    """Run one case through the production CLI case path."""
    profile, sliced = _mode(mode)
    started = time.perf_counter()
    args = argparse.Namespace(
        case=_case_path(case), out=str(out), replay=False, provider=None, model=None,
        profile=profile, slice=sliced, budget_usd=budget_usd, effect=None,
        pr_diff=None, repo=None, diff=None, recording=None, reasoning_effort=None,
        max_output_tokens=None,
    )
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        code = _run_case(args)
    row = _ledger_run(out, case, case.id)
    row["mode"] = mode
    row["wall_time"] = round(time.perf_counter() - started, 6)
    row["exit_code"] = code
    row["budget_exceeded"] = "budget exceeded:" in stderr.getvalue()
    return row


def _normalise_run(raw: Mapping[str, Any]) -> dict[str, Any]:
    counts = {str(k): int(v) for k, v in dict(raw.get("verdict_counts", {})).items()}
    for key in ("proven", "discarded_unproven", "invalid_test", "flaky", "env_failure"):
        counts.setdefault(key, 0)
    row = dict(raw)
    row["verdict_counts"] = counts
    row["proven"] = int(row.get("proven", counts["proven"]))
    row["fix_verified"] = int(row.get("fix_verified", 0))
    row["tokens"] = int(row.get("tokens", 0))
    row["cost"] = float(row.get("cost", 0.0))
    row["wall_time"] = float(row.get("wall_time", 0.0))
    row["unique_findings"] = sorted(set(str(x) for x in row.get("unique_findings", [])))
    return row


def aggregate(runs: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return one table row per case and mode."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for raw in runs:
        row = _normalise_run(raw)
        groups.setdefault((str(row["case"]), str(row["mode"])), []).append(row)
    result: list[dict[str, Any]] = []
    for (case, mode), items in sorted(groups.items()):
        costs = [item["cost"] for item in items]
        invalid = [item["verdict_counts"]["invalid_test"] for item in items]
        result.append({
            "case": case,
            "mode": mode,
            "runs": len(items),
            "runs_proven": sum(item["proven"] > 0 for item in items),
            "runs_fix_verified": sum(item["fix_verified"] > 0 for item in items),
            "false_proofs": sum(item["proven"] > 0 for item in items
                                if item.get("negative_control", False)),
            "invalid_test": invalid,
            "mean_input_tokens": round(sum(item.get("input_tokens", item["tokens"]) for item in items)
                                       / len(items)),
            "mean_cost": sum(costs) / len(costs),
            "cost_range": [min(costs), max(costs)],
        })
    return result


def render_table(runs: Iterable[Mapping[str, Any]]) -> str:
    """Render the marked repeatability table from run records."""
    rows = aggregate(runs)
    lines = [
        "| Case | Mode | Runs proven | False proofs | `invalid_test` per run | "
        "Mean input tokens | Mean cost (US$) | Cost range (US$) |",
        "|---|---|---|---|---|---:|---:|---|",
    ]
    for row in rows:
        false = "-" if not row["false_proofs"] else f"**{row['false_proofs']} / {row['runs']}**"
        invalid = ", ".join(str(value) for value in row["invalid_test"])
        lines.append(
            f"| {row['case']} | {row['mode']} | "
            f"{row['runs_proven']} / {row['runs']}, fix verified "
            f"{row['runs_fix_verified']} / {row['runs']} | {false} | {invalid} | "
            f"{row['mean_input_tokens']:,} | {row['mean_cost']:.4f} | "
            f"{row['cost_range'][0]:.4f}-{row['cost_range'][1]:.4f} |"
        )
    return "\n".join(lines)


def regenerate_document(path: str | Path, payload: Mapping[str, Any]) -> None:
    """Replace only the marked generated section in a repeatability document."""
    target = Path(path)
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    section = f"{MARKER_START}\n\n{render_table(payload.get('runs', []))}\n\n{MARKER_END}"
    if MARKER_START in existing and MARKER_END in existing:
        before = existing.split(MARKER_START, 1)[0].rstrip()
        after = existing.split(MARKER_END, 1)[1].lstrip()
        text = f"{before}\n\n{section}"
        if after:
            text += f"\n\n{after}"
    else:
        text = (existing.rstrip() + "\n\n" if existing.strip() else "") + section + "\n"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def execute(
    cases: Iterable[Case],
    modes: Iterable[str],
    runs: int,
    total_usd: float,
    out: Path,
    runner: Callable[[Case, str, Path, float], dict[str, Any]] = run_case,
) -> dict[str, Any]:
    if runs < 1 or total_usd <= 0:
        raise ValueError("runs must be at least one and total_usd must be positive")
    selected = list(cases)
    records: list[dict[str, Any]] = []
    spent = 0.0
    stopped = False
    for case in selected:
        for mode in modes:
            _mode(mode)
            for number in range(runs):
                if stopped:
                    break
                remaining = total_usd - spent
                if remaining <= 0:
                    stopped = True
                    break
                run_out = out / f"{case.id}-{mode}-{number + 1}"
                raw = runner(case, mode, run_out, remaining)
                row = _normalise_run(raw)
                row["case"] = case.id
                row["mode"] = mode
                row["run"] = number + 1
                row["negative_control"] = not bool(case.ground_truth)
                spent += row["cost"]
                records.append(row)
                # The production meter stops before the next call. A single
                # in-flight provider call may be the only budget overshoot.
                if raw.get("budget_exceeded") or spent > total_usd:
                    stopped = True
            if stopped:
                break
        if stopped:
            break
    payload = {
        "runs": records,
        "total_usd": spent,
        "budget_usd": total_usd,
        "stopped": stopped,
        "table": aggregate(records),
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "repeat.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    regenerate_document(DEFAULT_DOC, payload)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", required=True, help="comma-separated case ids or all")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--modes", default="compact,compact-slice")
    parser.add_argument("--provider", default="meta")
    parser.add_argument("--model", default="muse-wonder-1.0")
    parser.add_argument("--total-usd", type=float, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    args = parser.parse_args(argv)
    # Provider/model are consumed by the production runner through its normal
    # argument path; retain them on the namespace for compatibility with callers.
    cases = load_corpus(args.corpus)
    wanted = {case.id for case in cases} if args.cases == "all" else set(args.cases.split(","))
    selected = [case for case in cases if case.id in wanted]
    missing = wanted - {case.id for case in selected}
    if missing:
        parser.error(f"unknown case id(s): {', '.join(sorted(missing))}")
    def configured(case: Case, mode: str, target: Path, budget: float) -> dict[str, Any]:
        profile, sliced = _mode(mode)
        started = time.perf_counter()
        args_ns = argparse.Namespace(
            case=_case_path(case), out=str(target), replay=False, provider=args.provider,
            model=args.model, profile=profile, slice=sliced, budget_usd=budget,
            effect=None, pr_diff=None, repo=None, diff=None, recording=None,
            reasoning_effort=None, max_output_tokens=None,
        )
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = _run_case(args_ns)
        row = _ledger_run(target, case, case.id)
        row.update(mode=mode, wall_time=round(time.perf_counter() - started, 6), exit_code=code)
        row["budget_exceeded"] = "budget exceeded:" in stderr.getvalue()
        return row

    payload = execute(
        selected, args.modes.split(","), args.runs, args.total_usd, args.out,
        runner=configured,
    )
    regenerate_document(args.doc, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
