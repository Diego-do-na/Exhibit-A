"""Record real Meta-model runs of the corpus cases, and replay them offline (SPEC section 15).

For each case in ``bench/corpus`` this runs the real verification loop (sandbox-backed
baseline and exploit runs, full proof standard) with all four roles answered by the Meta
Model API, wrapped in :class:`~exhibit_a.models.record.RecordingProvider`. It writes

* ``bench/corpus/<case>/recordings/meta-<model>.jsonl``: every completion, keyed exactly as
  :class:`~exhibit_a.models.replay.ReplayProvider` looks it up;
* ``bench/corpus/<case>/recordings/meta-<model>.json``: metadata (model id, date UTC,
  tokens, cost, the verdicts actually obtained, the Exhibit A commit).

It does not go through the CLI. Spend is capped twice with the real cost meter: per case
(``--budget-usd``, default US$2) and across the whole invocation (``--total-usd``, default
US$5). The meter checks the cap before every call, so one call can overshoot it by at most
its own cost. Recordings are never edited: a failed proof is recorded as it happened.

The API key is read from the environment by the provider and is never printed, logged or
written. ``--scan`` checks files for the key and for any other environment value before
they are committed.

    PYTHONPATH=src:. python -m bench.record_meta --model muse-wonder-1.0
    PYTHONPATH=src:. python -m bench.record_meta --scan bench/corpus/*/recordings/*
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from exhibit_a.ledger import Ledger
from exhibit_a.loop import Roles, SandboxRunner, VerificationLoop
from exhibit_a.models import BudgetExceeded, CostMeter, ModelError, ModelRole, ReplayProvider, Role
from exhibit_a.models.errors import ReplayMiss
from exhibit_a.models.meta import DEFAULT_API_KEY_ENV, DEFAULT_BASE_URL, MetaProvider
from exhibit_a.models.record import RecordingProvider
from exhibit_a.schemas import EventType

from .corpus import Case, load_corpus
from .loop_pipeline import STAGED_BASELINE, _pick_source_file, _stage_case

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "bench" / "corpus"
CASES = (
    "starlette-cve-2023-29159",
    "starlette-cve-2023-29159-fixed",
    "archive-extraction-pathtraversal",
)
DEFAULT_MODEL = "muse-wonder-1.0"
CASE_BUDGET_USD = 2.0
TOTAL_BUDGET_USD = 5.0
#: Reasoning models can think for minutes before answering a full-file fix.
PROVIDER_TIMEOUT_S = 600.0

#: Verdict fields that must replay identically. The free-text reason is left out: on a
#: non-proof it can name per-run temporary paths.
VERDICT_KEYS = ("suspicion_id", "verdict", "reason_code", "fix_verified", "fix_incomplete")

#: Environment values shorter than this are too generic to scan for ("1", "zsh", ...);
#: values of secret-looking variables and the API key are scanned whatever their length.
MIN_ENV_VALUE_LEN = 16
_SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASS|AUTH|CRED", re.I)


class SplitMeter:
    """Charges one case meter and the run-wide meter; either one stops the next call."""

    def __init__(self, case: CostMeter, total: CostMeter) -> None:
        self.case = case
        self.total = total

    @property
    def total_usd(self) -> float:
        return self.case.total_usd

    def check(self) -> None:
        self.total.check()
        self.case.check()

    def charge(self, cost_usd: float) -> None:
        # Charge both before raising, so the run-wide total never misses a spend.
        errors = []
        for meter in (self.total, self.case):
            try:
                meter.charge(cost_usd)
            except BudgetExceeded as exc:
                errors.append(exc)
        if errors:
            raise errors[0]


@dataclass
class CaseOutcome:
    case_id: str
    baseline_ok: bool = False
    aborted: str = ""
    stopped: str = ""  # "", "budget_exceeded", "provider_error", "replay_miss"
    stop_detail: str = ""
    verdicts: list[dict[str, Any]] = field(default_factory=list)
    suspicions_raised: int = 0


def case_dir(case_id: str) -> Path:
    return CORPUS / case_id


def recording_paths(case_id: str, model: str) -> tuple[Path, Path]:
    stem = f"meta-{model}"
    base = case_dir(case_id) / "recordings"
    return base / f"{stem}.jsonl", base / f"{stem}.json"


def load_case(case_id: str) -> Case:
    return load_corpus(case_dir(case_id))[0]


def run_case(case: Case, provider: Any, out_dir: Path, meter: Any = None) -> CaseOutcome:
    """Run the full loop on one case with every role answered by ``provider``.

    The same staging, runner and loop settings serve recording and replay, so every
    prompt (and therefore every replay key) is rebuilt identically offline.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    clone = _stage_case(case, out_dir)
    ledger = Ledger(out_dir / "ledger.jsonl")
    roles = Roles(*(ModelRole(role, provider, meter) for role in (
        Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
    loop = VerificationLoop(
        clone, out_dir, ledger, roles, STAGED_BASELINE,
        run_id=case.id,
        runner=SandboxRunner(requirements=tuple(case.requirements)),
        effect=case.effect,
    )
    outcome = CaseOutcome(case.id)
    try:
        result = loop.run(_pick_source_file(clone, case))
    except BudgetExceeded as exc:
        outcome.stopped, outcome.stop_detail = "budget_exceeded", str(exc)
    except ReplayMiss as exc:
        outcome.stopped, outcome.stop_detail = "replay_miss", str(exc)
    except ModelError as exc:
        outcome.stopped, outcome.stop_detail = "provider_error", str(exc)
    else:
        outcome.baseline_ok = result.baseline_ok
        outcome.aborted = result.aborted
    events = ledger.replay(case.id)
    for event in events:
        if event.type == EventType.BASELINE_DONE and "suspicion_id" not in event.payload:
            outcome.baseline_ok = bool(event.payload.get("ok"))
        elif event.type == EventType.SUSPICION_RAISED:
            outcome.suspicions_raised += 1
        elif event.type == EventType.VERDICT:
            row = {key: event.payload.get(key) for key in VERDICT_KEYS}
            row["reason"] = event.payload.get("reason", "")
            outcome.verdicts.append(row)
    return outcome


def comparable(verdicts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The part of each verdict row that an offline replay must reproduce exactly."""
    return [{key: row.get(key) for key in VERDICT_KEYS} for row in verdicts]


def replay_case(case_id: str, model: str, out_dir: Path) -> CaseOutcome:
    """Replay a recorded Meta run offline (no network); the sandbox still runs every test."""
    recording, _ = recording_paths(case_id, model)
    return run_case(load_case(case_id), ReplayProvider(recording), out_dir)


def _usage(recording: Path) -> dict[str, Any]:
    calls = tokens_in = tokens_out = 0
    cost = 0.0
    by_role: dict[str, int] = {}
    if recording.exists():
        for line in recording.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            calls += 1
            tokens_in += int(record["tokens_in"])
            tokens_out += int(record["tokens_out"])
            cost += float(record.get("cost_usd", 0.0))
            by_role[record["role"]] = by_role.get(record["role"], 0) + 1
    return {"calls": calls, "calls_by_role": by_role, "tokens_in": tokens_in,
            "tokens_out": tokens_out, "cost_usd": round(cost, 6)}


def _git_commit() -> dict[str, Any]:
    def git(*args: str) -> str:
        proc = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True)
        return proc.stdout.strip() if proc.returncode == 0 else ""

    return {"commit": git("rev-parse", "HEAD"), "dirty": bool(git("status", "--porcelain"))}


def record_case(
    case_id: str, model: str, total: CostMeter, budget_usd: float, out_dir: Path, overwrite: bool
) -> dict[str, Any]:
    recording, metadata_path = recording_paths(case_id, model)
    if recording.exists():
        if not overwrite:
            raise FileExistsError(f"{recording} exists; pass --overwrite to record again")
        recording.unlink()
    meta = MetaProvider(model, timeout=PROVIDER_TIMEOUT_S)
    provider = RecordingProvider(recording, meta)
    meter = SplitMeter(CostMeter(budget_usd), total)
    started = datetime.now(timezone.utc)
    commit = _git_commit()
    outcome = run_case(load_case(case_id), provider, out_dir, meter)
    metadata = {
        "case": case_id,
        "provider": "meta",
        "model": model,
        "base_url": meta.base_url,
        "date_utc": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "exhibit_a": commit,
        "pricing_usd_per_mtok": {
            "input": meta.pricing.input_per_mtok, "output": meta.pricing.output_per_mtok,
        },
        "budget_usd": {"case": budget_usd, "run_total": total.limit_usd},
        **_usage(recording),
        "baseline_ok": outcome.baseline_ok,
        "aborted": outcome.aborted,
        "stopped": outcome.stopped,
        "stop_detail": outcome.stop_detail,
        "suspicions_raised": outcome.suspicions_raised,
        "verdicts": outcome.verdicts,
        "recording": recording.name,
        "hand_authored": False,
    }
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metadata


# -- secret scan --------------------------------------------------------------------------


def scan_values(env: dict[str, str] | None = None, key_env: str = DEFAULT_API_KEY_ENV) -> dict[str, str]:
    """Environment values worth scanning for, keyed by variable name (values never shown)."""
    env = dict(os.environ if env is None else env)
    values: dict[str, str] = {}
    for name, value in env.items():
        if not value:
            continue
        if name == key_env or (_SECRET_NAME.search(name) and len(value) >= 8):
            values[name] = value
        elif len(value) >= MIN_ENV_VALUE_LEN:
            values[name] = value
    return values


def scan_files(paths: list[Path], values: dict[str, str]) -> list[tuple[str, str]]:
    """Return (file, variable name) for every file that contains an environment value."""
    hits: list[tuple[str, str]] = []
    for path in paths:
        data = path.read_bytes()
        for name, value in values.items():
            if value.encode() in data:
                hits.append((str(path), name))
    return hits


def _scan_command(paths: list[str]) -> int:
    files = sorted({Path(p) for p in paths if Path(p).is_file()})
    values = scan_values()
    key_set = DEFAULT_API_KEY_ENV in values
    hits = scan_files(files, values)
    print(f"secret scan: {len(files)} file(s), {len(values)} environment value(s) "
          f"({DEFAULT_API_KEY_ENV} {'included' if key_set else 'NOT SET'}); hits: {len(hits)}")
    for path, name in hits:
        print(f"  LEAK: {path} contains the value of ${name}")
    if not key_set:
        print(f"secret scan: refusing to pass without {DEFAULT_API_KEY_ENV} to scan for")
        return 2
    return 1 if hits else 0


# -- CLI ----------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m bench.record_meta", description=__doc__.split("\n")[0])
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--case", action="append", choices=CASES, help="repeatable; default: every case")
    parser.add_argument("--budget-usd", type=float, default=CASE_BUDGET_USD, help="hard cap per case")
    parser.add_argument("--total-usd", type=float, default=TOTAL_BUDGET_USD, help="hard cap for the run")
    parser.add_argument("--spent-usd", type=float, default=0.0,
                        help="already spent by earlier invocations; counts against --total-usd")
    parser.add_argument("--out", default="", help="work directory (default: a new temporary one)")
    parser.add_argument("--overwrite", action="store_true", help="replace an existing recording")
    parser.add_argument("--scan", nargs="+", metavar="FILE", help="only scan files for secrets")
    args = parser.parse_args(argv)

    if args.scan:
        return _scan_command(args.scan)
    if not os.environ.get(DEFAULT_API_KEY_ENV):
        print(f"record_meta: {DEFAULT_API_KEY_ENV} is not set; export it first", file=sys.stderr)
        return 2
    if args.budget_usd <= 0 or args.total_usd <= 0 or not 0 <= args.spent_usd < args.total_usd:
        print("record_meta: budgets must be positive and --spent-usd below --total-usd", file=sys.stderr)
        return 2
    total = CostMeter(args.total_usd)
    if args.spent_usd:
        total.charge(args.spent_usd)
    out_root = Path(args.out) if args.out else Path(tempfile.mkdtemp(prefix="exhibit_a_meta_"))
    print(f"record_meta: model {args.model} at {os.environ.get('META_BASE_URL') or DEFAULT_BASE_URL}; "
          f"cap ${args.budget_usd:.2f}/case, ${args.total_usd:.2f} total; work dir {out_root}")
    code = 0
    for case_id in args.case or CASES:
        try:
            total.check()
        except BudgetExceeded as exc:
            print(f"record_meta: stopping before {case_id}: {exc}")
            return 3
        try:
            meta = record_case(case_id, args.model, total, args.budget_usd, out_root / case_id, args.overwrite)
        except (FileExistsError, FileNotFoundError, RuntimeError) as exc:
            print(f"record_meta: {case_id}: {exc}", file=sys.stderr)
            code = 1
            continue
        verdicts = ", ".join(f"{v['suspicion_id']}={v['verdict']}" for v in meta["verdicts"]) or "none"
        print(f"{case_id}: calls={meta['calls']} tokens={meta['tokens_in']}+{meta['tokens_out']} "
              f"cost=${meta['cost_usd']:.4f} (run total ${total.total_usd:.4f}) baseline_ok={meta['baseline_ok']} "
              f"stopped={meta['stopped'] or '-'} aborted={meta['aborted'] or '-'} verdicts: {verdicts}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
