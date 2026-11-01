"""Budgeted, resumable scale benchmark runner and offline aggregation."""
from __future__ import annotations

import argparse
import json
import statistics
import time
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from datetime import date
from pathlib import Path
from typing import Any

from exhibit_a.models.cost import Pricing
from exhibit_a.models.meta import META_PRICING
from exhibit_a.models.meta import MetaProvider
from exhibit_a.models.record import RecordingProvider
from exhibit_a.models.replay import ReplayProvider
from exhibit_a.models import Completion, Role, CostMeter

from .corpus import Case, load_corpus

BEGIN_MARKER = "<!-- BEGIN GENERATED: bench.scale -->"
END_MARKER = "<!-- END GENERATED: bench.scale -->"
DEFAULT_DOC = Path(__file__).parents[1] / "docs" / "bench" / "benchmark.md"
PROFILE_TOKENS = {
    "standard": (100_000, 40_000),
    "compact": (50_000, 10_000),
}


def wilson(successes: int, trials: int, z: float = 1.959963984540054) -> dict[str, float | None]:
    """Return a two-sided 95% Wilson interval (or n/a for no observations)."""
    if trials <= 0:
        return {"rate": None, "low": None, "high": None}
    p = successes / trials
    denominator = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    margin = z * ((p * (1 - p) / trials + z * z / (4 * trials * trials)) ** 0.5) / denominator
    return {"rate": p, "low": max(0.0, centre - margin), "high": min(1.0, centre + margin)}


def run_key(case: str, system: str, model: str, repetition: int) -> str:
    return f"{case}|{system}|{model}|{repetition}"


def pricing_for(model: str) -> Pricing:
    return META_PRICING.get(model, META_PRICING["default"])


def recording_provider(path: str | Path, provider: Any) -> ReplayProvider:
    """Build the live-once/offline-afterwards provider used by scale runs."""
    return ReplayProvider(path, recorder=RecordingProvider(path, provider))


class _Tally:
    def __init__(self, provider: Any) -> None:
        self.provider = provider
        self.name = provider.name
        self.pricing = provider.pricing
        self.cost_usd = 0.0
        self.latency_ms = 0

    def complete(self, role: Role, prompt: str, schema: dict[str, Any]) -> Completion:
        result = self.provider.complete(role, prompt, schema)
        self.cost_usd += result.cost_usd or self.pricing.cost(result.tokens_in, result.tokens_out)
        self.latency_ms += result.latency_ms
        return result


def live_runner(model: str | None = None, provider_name: str = "meta") -> Runner:
    """Return the production adapter; calls are recorded and then replayed by key."""
    if provider_name != "meta":
        raise ValueError(f"unsupported scale provider {provider_name!r}")
    from .baseline import Finding, Target, run_naive, score_findings
    from .record_meta import run_case as run_loop_case

    def runner(case: Case, system: str, selected_model: str, repetition: int,
               out: Path, cap: float) -> Mapping[str, Any]:
        if model is not None and selected_model != model:
            raise ValueError("runner was configured for a different model")
        base = MetaProvider(selected_model)
        replay = recording_provider(out / "recording.jsonl", base)
        tally = _Tally(replay)
        meter = CostMeter(cap)
        started = time.perf_counter()
        if system == "loop":
            outcome = run_loop_case(case, tally, out, meter, "standard")
            proven = sum(item.get("verdict") == "proven" for item in outcome.verdicts)
            valid = any(item.get("verdict") == "proven" and item.get("fix_verified", True)
                        for item in outcome.verdicts)
            return {"proven": bool(proven), "valid_proof": valid,
                    "cost_usd": meter.total_usd, "latency_ms": tally.latency_ms or
                    (time.perf_counter() - started) * 1000}
        if system == "naive":
            target = Target(case.id, "vulnerable" if case.kind == "vulnerable" else "fixed")
            findings, _ = run_naive(target, tally, out, meter)
            score = score_findings(findings, case.ground_truth, target.role, case.tree)
            return {"proven": bool(score.reported), "reported": score.reported,
                    "false_accusation": bool(score.false_accusations),
                    "cost_usd": meter.total_usd, "latency_ms": tally.latency_ms or
                    (time.perf_counter() - started) * 1000}
        raise ValueError(f"unknown scale system {system!r}")

    return runner


def worst_case_cost(model: str, runs: int, profile: str = "standard") -> float:
    """Estimate the provider-priced maximum for all role calls in each run."""
    input_cap, output_cap = PROFILE_TOKENS[profile]
    pricing = pricing_for(model)
    return runs * pricing.cost(input_cap, output_cap)


def _normalise(raw: Mapping[str, Any], *, key: str, case: Case, system: str,
               model: str, repetition: int) -> dict[str, Any]:
    row = dict(raw)
    row.update({
        "run_key": key, "case": case.id, "system": system, "model": model,
        "repetition": repetition, "effect": row.get("effect", case.effect),
        "held_out": bool(row.get("held_out", case.held_out)),
        "measured": bool(row.get("measured", True)),
        "true_vulnerability": bool(row.get("true_vulnerability", case.kind == "vulnerable")),
        "proven": bool(row.get("proven", False)),
        "valid_proof": bool(row.get("valid_proof", row.get("proven", False))),
        "false_accusation": bool(row.get("false_accusation", False)),
        "cost_usd": float(row.get("cost_usd", row.get("cost", 0.0))),
        "latency_ms": float(row.get("latency_ms", row.get("latency", 0.0))),
    })
    return row


def aggregate(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate measured records by system and effect, with held-out results separate."""
    groups: dict[tuple[str, str, bool], list[Mapping[str, Any]]] = defaultdict(list)
    for row in records:
        if row.get("measured", True):
            groups[(str(row["system"]), str(row.get("effect", "")), bool(row.get("held_out", False)))].append(row)

    def metric(rows: list[Mapping[str, Any]]) -> dict[str, Any]:
        n = len(rows)
        proven = sum(bool(r.get("proven")) for r in rows)
        false = sum(
            bool(r.get("false_accusation"))
            or (not bool(r.get("true_vulnerability", False)) and bool(r.get("proven")))
            or (bool(r.get("true_vulnerability", False))
                and bool(r.get("proven")) and not bool(r.get("valid_proof", True)))
            for r in rows
        )
        true = sum(bool(r.get("true_vulnerability", False)) for r in rows)
        recalled = sum(bool(r.get("proven")) and bool(r.get("valid_proof", r.get("proven"))) for r in rows
                       if r.get("true_vulnerability", False))
        costs = [float(r.get("cost_usd", 0.0)) for r in rows]
        latencies = [float(r.get("latency_ms", 0.0)) for r in rows]
        return {
            "runs": n,
            "proven_rate": wilson(proven, n),
            "false_accusation_rate": wilson(false, n),
            "recall": wilson(recalled, true),
            "flaky_rate": wilson(sum(_flips(rows)), len(_case_groups(rows))) if _case_groups(rows) else wilson(0, 0),
            "cost_per_proven": sum(costs) / proven if proven else None,
            "median_latency_ms": statistics.median(latencies) if latencies else None,
        }

    grouped = {
        f"{system}:{effect}": metric(rows)
        for (system, effect, held_out), rows in sorted(groups.items())
        if not held_out
    }
    held_out = {
        f"{system}:{effect}": metric(rows)
        for (system, effect, held), rows in sorted(groups.items())
        if held
    }
    return {"groups": grouped, "held_out": held_out}


def _case_groups(rows: list[Mapping[str, Any]]) -> dict[tuple[str, str, str], list[Mapping[str, Any]]]:
    result: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        result[(str(row["case"]), str(row["system"]), str(row.get("model", "")))].append(row)
    return result


def _flips(rows: list[Mapping[str, Any]]) -> list[int]:
    return [int(len({bool(r.get("proven")) for r in values}) > 1)
            for values in _case_groups(rows).values() if len(values) > 1]


def render_block(records: Iterable[Mapping[str, Any]]) -> str:
    data = aggregate(records)
    lines = ["| System / effect | Runs | Proven rate (95% CI) | False accusation rate (95% CI) | "
             "Recall (95% CI) | Flaky rate (95% CI) | Cost/proven (USD) | Median latency (ms) |",
             "|---|---:|---|---|---|---|---:|---:|"]
    for name, row in sorted(data["groups"].items()):
        def ci(key: str) -> str:
            value = row[key]
            return "unmeasured" if value["rate"] is None else f"{value['rate']:.3f} [{value['low']:.3f}, {value['high']:.3f}]"
        cost = "unmeasured" if row["cost_per_proven"] is None else f"{row['cost_per_proven']:.4f}"
        latency = "unmeasured" if row["median_latency_ms"] is None else f"{row['median_latency_ms']:.1f}"
        lines.append(f"| {name} | {row['runs']} | {ci('proven_rate')} | {ci('false_accusation_rate')} | "
                     f"{ci('recall')} | {ci('flaky_rate')} | {cost} | {latency} |")
    if data["held_out"]:
        lines += ["", "**Held-out cases**", "", "```json", json.dumps(data["held_out"], sort_keys=True, indent=2), "```"]
    return "\n".join(lines)


def regenerate_document(path: str | Path, records: Iterable[Mapping[str, Any]]) -> None:
    target = Path(path)
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    section = f"{BEGIN_MARKER}\n\n{render_block(records)}\n\n{END_MARKER}"
    if BEGIN_MARKER in existing and END_MARKER in existing:
        before = existing.split(BEGIN_MARKER, 1)[0].rstrip()
        after = existing.split(END_MARKER, 1)[1].lstrip()
        text = section if not before else f"{before}\n\n{section}"
        if after:
            text += f"\n\n{after}"
    else:
        text = (existing.rstrip() + "\n\n" if existing.strip() else "") + section + "\n"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text.rstrip() + "\n", encoding="utf-8")


Runner = Callable[[Case, str, str, int, Path, float], Mapping[str, Any]]


def execute(cases: Iterable[Case], systems: Iterable[str], models: Iterable[str], k: int,
            total_usd: float, per_run_usd: float, out: str | Path,
            runner: Runner, resume: bool = True, dry_run: bool = False,
            profile: str = "standard", doc: str | Path = DEFAULT_DOC) -> dict[str, Any]:
    if k < 1 or total_usd <= 0 or per_run_usd <= 0:
        raise ValueError("k, total_usd and per_run_usd must be positive")
    if profile not in PROFILE_TOKENS:
        raise ValueError(f"unknown profile {profile!r}")
    target = Path(out)
    target.mkdir(parents=True, exist_ok=True)
    lines_path = target / "runs.jsonl"
    existing: dict[str, dict[str, Any]] = {}
    if resume and lines_path.exists():
        for line in lines_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                item = json.loads(line)
                existing[item["run_key"]] = item
    selected = list(cases)
    systems, models = list(systems), list(models)
    planned = len(selected) * len(systems) * len(models) * k
    estimate = sum(worst_case_cost(model, len(selected) * len(systems) * k, profile) for model in models)
    if dry_run:
        return {"planned_runs": planned, "worst_case_cost_usd": estimate, "records": list(existing.values())}
    records = dict(existing)
    spent = sum(float(item.get("cost_usd", 0.0)) for item in records.values())
    stopped = False
    with lines_path.open("a", encoding="utf-8") as handle:
        for case in sorted(selected, key=lambda x: x.id):
            for system in systems:
                for model in models:
                    for repetition in range(1, k + 1):
                        key = run_key(case.id, system, model, repetition)
                        if key in records:
                            continue
                        if spent + per_run_usd > total_usd:
                            stopped = True
                            break
                        started = time.perf_counter()
                        raw = runner(case, system, model, repetition, target / key.replace("|", "_"), per_run_usd)
                        row = _normalise(raw, key=key, case=case, system=system, model=model, repetition=repetition)
                        row.setdefault("latency_ms", (time.perf_counter() - started) * 1000)
                        if row["cost_usd"] > per_run_usd:
                            raise ValueError(f"run {key} exceeded per-run cap")
                        spent += row["cost_usd"]
                        records[key] = row
                        handle.write(json.dumps(row, sort_keys=True) + "\n")
                        handle.flush()
                    if stopped:
                        break
                if stopped:
                    break
            if stopped:
                break
    all_records = list(records.values())
    regenerate_document(doc, all_records)
    return {"planned_runs": planned, "completed_runs": len(all_records), "spent_usd": spent,
            "stopped": stopped, "records": all_records, "aggregate": aggregate(all_records)}


def _glob_cases(value: str) -> list[Case]:
    if value == "all":
        return load_corpus(Path(__file__).with_name("corpus"))
    paths = sorted(Path(".").glob(value))
    cases: list[Case] = []
    for path in paths:
        if path.is_dir() and (path / "case.json").is_file():
            cases.extend(load_corpus(path))
        elif path.is_file():
            cases.extend(load_corpus(path))
    if not cases:
        raise ValueError(f"no cases matched {value!r}")
    return cases


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m bench.scale")
    parser.add_argument("--cases", required=True)
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--systems", default="loop,naive")
    parser.add_argument("--model", action="append", required=True)
    parser.add_argument("--total-usd", type=float, required=True)
    parser.add_argument("--per-run-usd", type=float, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--profile", choices=tuple(PROFILE_TOKENS), default="standard")
    parser.add_argument("--resume", action="store_true", default=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    cases = _glob_cases(args.cases)
    result = execute(cases, args.systems.split(","), args.model, args.k, args.total_usd,
                     args.per_run_usd, args.out, live_runner(), dry_run=args.dry_run,
                     profile=args.profile)
    if args.dry_run:
        print(f"planned runs: {result['planned_runs']}")
        print(f"worst-case cost: ${result['worst_case_cost_usd']:.4f}")
    else:
        print(json.dumps({k: result[k] for k in ("planned_runs", "completed_runs", "spent_usd", "stopped")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
