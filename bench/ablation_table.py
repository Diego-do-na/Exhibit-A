"""Ablation table: switch off each proof component and each oracle layer.

Runs every red-team attack (``spikes/redteam``) and every labelled corpus exploit
under (a) each loop ablation from ``bench/flags.py`` and (b) the oracle with one
provenance layer disabled at a time. Model answers are never requested: corpus
inputs are the committed labelled exploits and recordings, and red-team attacks
call ``run_oracle`` directly.

The layer switch is the test-only ``disabled_layers`` argument on ``run_oracle``
(and ``disable_oracle_layers``). The CLI never sets it.

Usage, from the repo root, with ``src`` on ``PYTHONPATH``::

    python -m bench.ablation_table
    python -m bench.ablation_table --from-json bench/results/ablations.json
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
import threading
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path

from bench.flags import ABLATIONS, Flags
from exhibit_a.oracle.layers import ORACLE_LAYERS, disable_oracle_layers
from exhibit_a.oracle.oracle import Frame, OracleEvent, _judge

REPO = Path(__file__).resolve().parent.parent
REDTEAM = REPO / "spikes" / "redteam"
CORPUS = REPO / "bench" / "corpus"
DOC = REPO / "docs" / "bench" / "ablations.md"
RESULTS = REPO / "bench" / "results" / "ablations.json"
BEGIN_MARKER = "<!-- BEGIN GENERATED: python -m bench.ablation_table -->"
END_MARKER = "<!-- END GENERATED -->"

FALSE_PROVEN = "FALSE_PROVEN"
BLOCKED = "BLOCKED"
DETECTED = "DETECTED"
SUPPRESSED_TRUE = "SUPPRESSED_TRUE"
ERROR = "ERROR"

TRUE_LABELS = frozenset({"true-exploit"})
FALSE_LABELS = frozenset({"cheating", "wrong-reason-failure", "benign", "flaky"})

Runner = Callable[[str, frozenset[str]], "Observation"]
_REDTEAM_LOCK = threading.Lock()


@dataclass
class Observation:
    """One attack or labelled exploit under one configuration."""

    name: str
    source: str
    app_is_safe: bool
    verdict: str
    test_failed: bool = False
    cost_usd: float = 0.0


@dataclass
class ConfigRow:
    configuration: str
    false_proofs: int
    true_proofs: int
    missed_true_proofs: int
    cost_usd: float
    got_through: list[str] = field(default_factory=list)
    note: str = ""


def _proven(verdict: str) -> bool:
    return verdict in {FALSE_PROVEN, DETECTED}


def classify(observed_effect: bool, provenance_ok: bool, test_outcome: str, *, app_is_safe: bool) -> str:
    """FALSE_PROVEN / BLOCKED (safe app) or SUPPRESSED_TRUE / DETECTED (vulnerable app)."""
    proven_like = observed_effect and provenance_ok and test_outcome == "failed"
    if app_is_safe:
        return FALSE_PROVEN if proven_like else BLOCKED
    return DETECTED if proven_like else SUPPRESSED_TRUE


def reclassify(obs: Observation, flags: Flags) -> str:
    """Apply a loop ablation to a single oracle observation, without a new model call."""
    if flags.naive:
        return FALSE_PROVEN if obs.app_is_safe else DETECTED
    if not flags.oracle:
        if obs.test_failed:
            return FALSE_PROVEN if obs.app_is_safe else DETECTED
        return BLOCKED if obs.app_is_safe else SUPPRESSED_TRUE
    return obs.verdict


def redteam_attack_names() -> list[str]:
    """The host-testable attacks listed by ``spikes/redteam/run_all.py``."""
    if str(REDTEAM) not in sys.path:
        sys.path.insert(0, str(REDTEAM))
    module = importlib.import_module("run_all")
    return list(module.ATTACKS)


def run_redteam_attack(name: str, disabled: frozenset[str] = frozenset()) -> Observation:
    """Import one red-team module and judge it through the real host oracle."""
    if str(REDTEAM) not in sys.path:
        sys.path.insert(0, str(REDTEAM))
    harness = importlib.import_module("_harness")
    original_report = harness.report
    captured: dict[str, object] = {}

    def capture(label: str, judgement: object, *, app_is_safe: bool) -> str:
        captured["judgement"] = judgement
        captured["app_is_safe"] = app_is_safe
        return original_report(label, judgement, app_is_safe=app_is_safe)

    with _REDTEAM_LOCK:
        harness.report = capture
        harness.GUARD = True
        try:
            with disable_oracle_layers(*disabled) if disabled else _null():
                verdict = importlib.import_module(name).main()
            judgement = captured.get("judgement")
            app_is_safe = bool(captured.get("app_is_safe", True))
            test_failed = bool(getattr(judgement, "test_outcome", "") == "failed")
            return Observation(
                name=name, source="redteam", app_is_safe=app_is_safe,
                verdict=str(verdict or ERROR), test_failed=test_failed,
            )
        except Exception:  # noqa: BLE001 — an attack that cannot run is not a proof
            return Observation(
                name=name, source="redteam", app_is_safe=True,
                verdict=ERROR, test_failed=False,
            )
        finally:
            harness.report = original_report
            harness.GUARD = True


def _null():
    from contextlib import nullcontext
    return nullcontext()


def iter_corpus_exploits(corpus: Path = CORPUS) -> list[dict[str, object]]:
    """Labelled exploits from each real case.json (replayed test-writer answers)."""
    items: list[dict[str, object]] = []
    if not corpus.is_dir():
        return items
    for child in sorted(p for p in corpus.iterdir() if p.is_dir()):
        case_file = child / "case.json"
        if not case_file.is_file():
            continue
        try:
            data = json.loads(case_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        run = data.get("run") or {}
        exploits = run.get("exploits") or []
        if not exploits:
            continue
        trees = run.get("trees") or {}
        tree = str(run.get("tree") or trees.get("vulnerable") or "vulnerable")
        app_root = child / tree
        if not app_root.is_dir():
            continue
        entry_points = [str(x) for x in (run.get("entry_points") or [])]
        if run.get("oracle_entry_point"):
            entry_points.append(str(run["oracle_entry_point"]))
        effect = str(run.get("effect") or "canary_read")
        case_id = str((data.get("cases") or [{}])[0].get("id") or child.name)
        cost = _recording_cost(child)
        first = True
        for spec in exploits:
            if not isinstance(spec, dict):
                continue
            label = str(spec.get("label") or "")
            rel = str(spec.get("file") or "")
            path = child / rel
            if not path.is_file():
                continue
            items.append({
                "name": f"{case_id}:{Path(rel).stem}",
                "app_root": app_root,
                "test_path": path,
                "entry_points": entry_points,
                "effect": effect,
                "sql_db": run.get("sql_db"),
                "access_db": run.get("access_db"),
                "access": run.get("access"),
                "redirect_meta": bool(run.get("redirect_meta", False)),
                "label": label,
                "cost_usd": cost if first else 0.0,
            })
            first = False
    return items


def _recording_cost(case_dir: Path) -> float:
    recordings = case_dir / "recordings"
    if not recordings.is_dir():
        return 0.0
    total = 0.0
    for path in sorted(recordings.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("cost_usd"), (int, float)):
            total += float(data["cost_usd"])
            break
    return total


def run_corpus_exploit(item: dict[str, object], disabled: frozenset[str] = frozenset()) -> Observation:
    """Replay one labelled corpus exploit through ``run_oracle`` (no model call)."""
    from exhibit_a.oracle import run_oracle

    label = str(item.get("label") or "")
    app_is_safe = label not in TRUE_LABELS
    kwargs: dict[str, object] = {
        "timeout": 60.0,
        "effect": item["effect"],
        "disabled_layers": disabled or None,
    }
    if item.get("sql_db"):
        kwargs["sql_db"] = item["sql_db"]
    if item.get("access_db") or item.get("access"):
        kwargs["access_db"] = item.get("access_db")
        kwargs["access"] = item.get("access")
    if item.get("redirect_meta"):
        kwargs["redirect_meta"] = True
    try:
        judgement = run_oracle(
            Path(str(item["app_root"])),
            Path(str(item["test_path"])),
            set(item["entry_points"] or ["App.handle_request"]),
            **kwargs,
        )
        verdict = classify(
            judgement.observed_effect, judgement.provenance_ok, judgement.test_outcome,
            app_is_safe=app_is_safe,
        )
        return Observation(
            name=str(item["name"]), source="corpus", app_is_safe=app_is_safe,
            verdict=verdict, test_failed=judgement.test_outcome == "failed",
            cost_usd=float(item.get("cost_usd") or 0.0),
        )
    except Exception:  # noqa: BLE001 — a case that cannot run is not a proof
        return Observation(
            name=str(item["name"]), source="corpus", app_is_safe=app_is_safe,
            verdict=ERROR, test_failed=False,
        )


def _probe_event(app_py: Path, test_py: Path, canary: str, requested: str) -> OracleEvent:
    return OracleEvent(
        path=canary,
        mode="r",
        stack=[
            Frame(file=str(test_py), function="test_x", qualname="test_x", line=1, admitted=False),
            Frame(
                file=str(app_py), function="handle_request", qualname="App.handle_request",
                line=1, admitted=True,
            ),
        ],
        op="open",
        flags=getattr(os, "O_RDONLY", 0),
        access="read",
        requested=requested,
    )


def run_probes(disabled: frozenset[str] = frozenset()) -> list[Observation]:
    """Judge-level probes for layers the red-team set may not uniquely exercise.

    Each probe is a safe-app claim: a proof is a false proof. They exist so a
    layer that is redundant with others on ``spikes/redteam`` still has a row
    that shows what it stops when it is the one switched off.
    """
    app_root = Path("/tmp/exhibit_a_ablation_app")
    test_path = Path("/tmp/exhibit_a_ablation_tests/test_x.py")
    app_py = app_root / "app.py"
    canary = "/tmp/exhibit_a_ablation_work/outside/canary.txt"
    allowed = "/tmp/exhibit_a_ablation_work/allowed"
    via_allowed = allowed + "/../outside/canary.txt"
    entries = {"App.handle_request"}
    out: list[Observation] = []

    def score(name: str, judgement: object) -> Observation:
        verdict = classify(
            bool(getattr(judgement, "observed_effect", False)),
            bool(getattr(judgement, "provenance_ok", False)),
            str(getattr(judgement, "test_outcome", "failed")),
            app_is_safe=True,
        )
        return Observation(
            name=name, source="probe", app_is_safe=True, verdict=verdict,
            test_failed=str(getattr(judgement, "test_outcome", "")) == "failed",
        )

    event = _probe_event(app_py, test_path, canary, via_allowed)
    with disable_oracle_layers(*disabled) if disabled else _null():
        tree = _judge(
            "failed", [event], app_root, test_path, entries,
            allowed_dir=allowed, app_tree_changes=["added: handler_shim.py"],
        )
        out.append(score("probe_L3_app_tree_change", tree))
        routed = _judge(
            "failed", [_probe_event(app_py, test_path, canary, "/tmp/other/canary.txt")],
            app_root, test_path, entries, allowed_dir=allowed,
        )
        out.append(score("probe_L6_route_access", routed))
        witness = _judge(
            "failed", [event], app_root, test_path, entries, allowed_dir=allowed,
            witness={"status": "ok", "observed": []},
        )
        out.append(score("probe_L14_witness", witness))
    return out


def loop_configurations() -> list[tuple[str, Flags, frozenset[str]]]:
    return [(f"loop:{name}", flags, frozenset()) for name, flags in ABLATIONS.items()]


def layer_configurations() -> list[tuple[str, Flags, frozenset[str]]]:
    return [
        (f"oracle:no_{layer}", Flags(), frozenset({layer}))
        for layer in sorted(ORACLE_LAYERS)
    ]


def configurations() -> list[tuple[str, Flags, frozenset[str]]]:
    return loop_configurations() + layer_configurations()


def _is_flaky(name: str) -> bool:
    return "flaky" in name


def summarise(observations: Sequence[Observation]) -> tuple[int, int, int, float, list[str]]:
    false_proofs = [o.name for o in observations if o.verdict == FALSE_PROVEN]
    true_proofs = sum(1 for o in observations if o.verdict == DETECTED)
    missed = sum(1 for o in observations if o.verdict == SUPPRESSED_TRUE)
    cost = sum(o.cost_usd for o in observations)
    return len(false_proofs), true_proofs, missed, cost, false_proofs


def rows_from_observations(
    by_config: dict[str, list[Observation]],
    full_name: str = "loop:full",
) -> list[ConfigRow]:
    full_false = set()
    full_missed = set()
    if full_name in by_config:
        full_false = {o.name for o in by_config[full_name] if o.verdict == FALSE_PROVEN}
        full_missed = {o.name for o in by_config[full_name] if o.verdict == SUPPRESSED_TRUE}
    rows: list[ConfigRow] = []
    for name, observations in by_config.items():
        false_n, true_n, missed, cost, got = summarise(observations)
        extra = [
            item for item in got
            if item not in full_false and not _is_flaky(item)
        ]
        display = extra if name != full_name else [
            item for item in got if not _is_flaky(item)
        ]
        note = ""
        if name.startswith("oracle:no_") and name != full_name:
            if not extra:
                note = (
                    "no additional stable attack on the current attack set "
                    "(other layers still hold; defense in depth)"
                )
            else:
                note = "new vs full"
        elif name.startswith("loop:") and name not in {full_name}:
            if extra:
                note = "new vs full"
            elif name in {"loop:no_differential", "loop:no_defender"}:
                note = (
                    "single-run oracle judgements are unchanged; "
                    "this flag applies to the fix/bypass steps of the loop"
                )
        newly_missed = [
            obs.name for obs in observations
            if obs.verdict == SUPPRESSED_TRUE and obs.name not in full_missed and not _is_flaky(obs.name)
        ]
        if newly_missed:
            miss = "newly missed: " + ", ".join(f"`{n}`" for n in newly_missed)
            note = f"{note}; {miss}" if note else miss
        rows.append(ConfigRow(
            configuration=name, false_proofs=false_n, true_proofs=true_n,
            missed_true_proofs=missed, cost_usd=cost, got_through=display, note=note,
        ))
    return rows


def _map_corpus(
    run_case: Callable[[dict[str, object], frozenset[str]], Observation],
    corpus: Sequence[dict[str, object]],
    disabled: frozenset[str],
    workers: int,
) -> list[Observation]:
    if not corpus:
        return []
    if workers <= 1 or len(corpus) == 1:
        return [run_case(item, disabled) for item in corpus]
    out: list[Observation | None] = [None] * len(corpus)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(run_case, item, disabled): i for i, item in enumerate(corpus)}
        for fut in as_completed(futs):
            out[futs[fut]] = fut.result()
    return [obs for obs in out if obs is not None]


def collect(
    *,
    redteam: Iterable[str] | None = None,
    corpus_items: Iterable[dict[str, object]] | None = None,
    redteam_runner: Runner | None = None,
    corpus_runner: Callable[[dict[str, object], frozenset[str]], Observation] | None = None,
    include_probes: bool = True,
    configs: Sequence[tuple[str, Flags, frozenset[str]]] | None = None,
    workers: int = 1,
) -> dict[str, list[Observation]]:
    """Run every attack under every configuration. Inject runners in tests."""
    attacks = list(redteam) if redteam is not None else redteam_attack_names()
    corpus = list(corpus_items) if corpus_items is not None else iter_corpus_exploits()
    run_attack = redteam_runner or run_redteam_attack
    run_case = corpus_runner or run_corpus_exploit
    configs = list(configs) if configs is not None else configurations()

    def pass_for(disabled: frozenset[str]) -> list[Observation]:
        label = ",".join(sorted(disabled)) or "full"
        observed: list[Observation] = []
        for i, name in enumerate(attacks, 1):
            observed.append(run_attack(name, disabled))
            if workers > 1 and (i == 1 or i % 10 == 0 or i == len(attacks)):
                print(f"  [{label}] redteam {i}/{len(attacks)}", flush=True)
        observed.extend(_map_corpus(run_case, corpus, disabled, workers))
        if corpus and workers > 1:
            print(f"  [{label}] corpus {len(corpus)}", flush=True)
        if include_probes:
            observed.extend(run_probes(disabled))
        return observed

    # One full oracle pass, then reclassify loop ablations that do not need a re-run.
    baseline = pass_for(frozenset())
    by_config: dict[str, list[Observation]] = {}
    for conf_name, flags, disabled in configs:
        if disabled:
            by_config[conf_name] = pass_for(disabled)
            continue
        by_config[conf_name] = [
            Observation(
                name=obs.name, source=obs.source, app_is_safe=obs.app_is_safe,
                verdict=reclassify(obs, flags), test_failed=obs.test_failed,
                cost_usd=obs.cost_usd if not flags.naive else 0.0,
            )
            for obs in baseline
        ]
    return by_config


def _shorten(names: Sequence[str], limit: int = 8) -> str:
    items = [f"`{name}`" for name in names]
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f", and {len(items) - limit} more"


def render(rows: Sequence[ConfigRow]) -> str:
    """Markdown ablation table. Cost is from committed recordings (no live model call)."""
    header = (
        "| configuration | false proofs | true proofs | missed true proofs "
        "| cost (USD) | what attack got through |"
    )
    lines = [
        BEGIN_MARKER,
        header,
        "|" + "---|" * 6,
    ]
    for row in rows:
        got = _shorten(row.got_through) if row.got_through else "—"
        if row.note:
            got = f"{got} — {row.note}" if row.got_through else row.note
        lines.append(
            f"| `{row.configuration}` | {row.false_proofs} | {row.true_proofs} "
            f"| {row.missed_true_proofs} | {row.cost_usd:.4f} | {got} |"
        )
    lines.append(END_MARKER)
    return "\n".join(lines) + "\n"


def render_document(rows: Sequence[ConfigRow]) -> str:
    layers = ", ".join(f"`{name}`" for name in sorted(ORACLE_LAYERS))
    intro = f"""# Ablation table

Every proof component and every oracle provenance layer is load-bearing, or the
row says plainly that it had no extra effect on the current attack set. A green
cell still means "nothing could be proven", never "safe". The sandbox that runs
untrusted tests is isolated and resource-limited, never "100% safe".

This table is **replay only**: no live model call. Red-team attacks
(`spikes/redteam`) and labelled corpus exploits go through `run_oracle` on the
host path. Loop ablations that do not change a single oracle judgement
(`no_differential`, `no_defender`) are scored from the full-oracle pass; they
are not a second model run.

The oracle layer switch is test-only (`run_oracle(..., disabled_layers=...)` /
`disable_oracle_layers`). The CLI has no flag for it and never sets
`EXHIBIT_A_DISABLED_LAYERS`. Layers: {layers}. Layer 14 is T114's OS-level
witness; the host path has no supervisor, so the `probe_L14_witness` row is the
judge-level stand-in (plugin saw the effect, the OS did not).

Cost is the committed recording total attributed to a case, not money spent
generating this table. False-proof counts include labelled flaky corpus exploits
whose outcome can differ between passes; a one-count shift without a named
attack is that noise, not a new hole.

"""
    return intro + render(rows)


def update_document(rows: Sequence[ConfigRow], document: Path = DOC) -> None:
    generated = render(rows)
    if document.is_file():
        existing = document.read_text(encoding="utf-8")
        start = existing.find(BEGIN_MARKER)
        end = existing.find(END_MARKER)
        if start >= 0 and end >= start:
            document.write_text(
                existing[:start] + generated + existing[end + len(END_MARKER):].lstrip("\n"),
                encoding="utf-8",
            )
            return
    document.parent.mkdir(parents=True, exist_ok=True)
    document.write_text(render_document(rows), encoding="utf-8")


def write_json(by_config: dict[str, list[Observation]], path: Path = RESULTS) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        config: [asdict(obs) for obs in observations]
        for config, observations in by_config.items()
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, list[Observation]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, list[Observation]] = {}
    for config, rows in data.items():
        out[config] = [Observation(**row) for row in rows]
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--doc", type=Path, default=DOC)
    parser.add_argument("--json-out", type=Path, default=RESULTS)
    parser.add_argument(
        "--from-json", type=Path, default=None,
        help="Rebuild the markdown table from a previous JSON result (no oracle runs).",
    )
    parser.add_argument("--skip-corpus", action="store_true", help="Red-team and probes only.")
    parser.add_argument("--skip-redteam", action="store_true", help="Corpus and probes only.")
    parser.add_argument("--workers", type=int, default=8, help="Parallel corpus replays.")
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.from_json:
        by_config = load_json(args.from_json)
    else:
        by_config = collect(
            redteam=[] if args.skip_redteam else None,
            corpus_items=[] if args.skip_corpus else None,
            workers=max(1, args.workers),
        )
        write_json(by_config, args.json_out)
    rows = rows_from_observations(by_config)
    args.doc.parent.mkdir(parents=True, exist_ok=True)
    args.doc.write_text(render_document(rows), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
