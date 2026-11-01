"""CLI: ``python -m spikes.redteam.auto`` (live generation) or ``--replay`` (CI).

Live mode asks a model for cheating tests, runs each through the real sandbox
and oracle, classifies the result, and saves NEW false proofs as attack files.
``--total-usd`` is a hard budget: the cost meter stops the campaign once it is
reached (about 20% of the overall budget is reserved for the owner's live Meta
run; pass this tool its share). Every model call is recorded with
``RecordingProvider`` so the run replays offline.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import get_args

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "src"))

from exhibit_a.models.base import Role  # noqa: E402
from exhibit_a.models.config import PROVIDER_REGISTRY, RoleConfig  # noqa: E402
from exhibit_a.models.cost import CostMeter  # noqa: E402
from exhibit_a.models.record import RecordingProvider  # noqa: E402
from exhibit_a.models.replay import ReplayProvider  # noqa: E402
from exhibit_a.oracle.oracle import Effect  # noqa: E402
from spikes.redteam.auto.cases import discover  # noqa: E402
from spikes.redteam.auto.engine import replay_run, run_campaign  # noqa: E402
from spikes.redteam.auto.report import counts_table, write_doc  # noqa: E402

EFFECT_CHOICES = ["all", *sorted(get_args(Effect))]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m spikes.redteam.auto",
        description="Model-generated cheating tests against the oracle (fixed trees only).",
    )
    parser.add_argument("--effect", choices=EFFECT_CHOICES, default="all")
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--per-round", type=int, default=5)
    parser.add_argument("--provider", default="meta")
    parser.add_argument("--model", default="")
    parser.add_argument("--base-url", default="")
    parser.add_argument("--api-key-env", default="")
    parser.add_argument("--total-usd", type=float, default=10.0)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--out", default="out/auto-redteam")
    parser.add_argument("--recording", default="")
    parser.add_argument("--replay", default="", help="run dir to replay offline (no model, no sandbox)")
    parser.add_argument("--write-docs", action="store_true",
                        help="regenerate docs/oracle/auto-redteam.md from the run counts")
    parser.add_argument("--lang", choices=("py", "js"), default="py",
                        help="'js' is a documented hook for the T125 Node-oracle task")
    return parser


def _build_provider(args):
    if args.provider == "replay":
        if not args.recording:
            raise ValueError("replay provider needs --recording")
        return ReplayProvider(args.recording)
    factory = PROVIDER_REGISTRY.get(args.provider)
    if factory is None:
        raise ValueError(f"unknown provider {args.provider!r}; known: {sorted(PROVIDER_REGISTRY)}")
    return factory(RoleConfig(provider=args.provider, model=args.model, base_url=args.base_url,
                              api_key_env=args.api_key_env))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.replay:
        result = replay_run(Path(args.replay))
        print(counts_table(result["counts"]), end="")
        print(f"samples={result['samples']} match={result['match']}")
        return 0 if result["match"] else 10
    if args.rounds < 1 or args.per_round < 1:
        print("rounds and per-round must be >= 1", file=sys.stderr)
        return 2
    if args.total_usd <= 0:
        print("total-usd must be positive", file=sys.stderr)
        return 2
    # Documented hook for the T125 Node-oracle task: until it registers JS
    # targets and wires its own run_fn, --lang js has nothing to attack.
    targets, skipped = discover(args.effect, REPO_ROOT / "bench" / "corpus", lang=args.lang)
    if args.lang == "js":
        print("lang=js hook: no Node-oracle targets registered yet (T125 wires "
              "register_js_target() and its own run_fn); nothing to do.",
              file=sys.stderr)
        return 2 if not targets else 0
    if not targets:
        print(f"no fixed-tree targets for effect={args.effect} (skipped: {skipped})",
              file=sys.stderr)
        return 2
    try:
        inner = _build_provider(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    out_dir = Path(args.out)
    recording_path = Path(args.recording) if args.recording else out_dir / "recording.jsonl"
    provider = RecordingProvider(recording_path, inner)

    from exhibit_a.models.base import ModelRole
    meter = CostMeter(args.total_usd)
    role = ModelRole(Role.TEST_WRITER, provider, meter)
    print(f"targets={len(targets)} rounds={args.rounds} per_round={args.per_round} "
          f"budget=${args.total_usd:.2f} out={out_dir}")
    report = run_campaign(targets, role, rounds=args.rounds, per_round=args.per_round,
                          out_dir=out_dir, timeout=args.timeout)
    print(counts_table(report.counts), end="")
    print(f"samples={report.samples} findings={len(report.findings)} "
          f"spent=${meter.total_usd:.4f} budget_exhausted={report.budget_exhausted}")
    if report.findings:
        print("new findings:")
        for name in report.findings:
            print(f"  {out_dir / 'findings' / name}")
    if args.write_docs:
        note = (f"\nLatest run: {report.samples} samples, "
                f"{len(report.findings)} NEW findings, spent ${meter.total_usd:.4f} "
                f"of ${args.total_usd:.2f} (budget_exhausted={report.budget_exhausted}).\n")
        write_doc(REPO_ROOT / "docs" / "oracle" / "auto-redteam.md",
                  report.counts, note=note)
        print("docs/oracle/auto-redteam.md regenerated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
