#!/usr/bin/env bash
# Exhibit A demo kit: a 2-3 minute red-to-green story, offline or live.
#
#   scripts/demo.sh --offline        replay the committed compact Meta
#                                    recordings (no key, no Meta network)
#   scripts/demo.sh --live           run the live loop on the archive case
#                                    with Muse Wonder (needs META_API_KEY)
#   scripts/demo.sh --offline --serve   also serve the live view afterwards
#
# Run from the repository root with Docker running. Needs the project
# environment on PATH (the same interpreter that runs the test suite).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

usage() {
    echo "usage: scripts/demo.sh --offline [--serve] | --live" >&2
    exit 2
}

MODE="${1:-}"
SERVE="${2:-}"
[[ "$MODE" == "--offline" || "$MODE" == "--live" ]] || usage
[[ -z "$SERVE" || "$SERVE" == "--serve" ]] || usage

export PYTHONPATH="$ROOT/src:$ROOT/bench${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

step() { printf '\n=== %s ===\n' "$1"; }

# -- Step 1: the code under proof ----------------------------------------------
step "1/6 the code under proof (this, and nothing else, is what gets proven)"
echo "--- archive: the confinement check whose removal is the vulnerability ---"
diff -u bench/corpus/archive-extraction-pathtraversal/fixed/archive.py \
       bench/corpus/archive-extraction-pathtraversal/vulnerable/archive.py || true
echo
echo "--- starlette: the line Starlette 0.26.1 shipped (CVE-2023-29159) ---"
python3 - <<'EOF'
import json
recording = "bench/corpus/starlette-cve-2023-29159/recordings/meta-muse-wonder-1.0-compact.jsonl"
for line in open(recording, encoding="utf-8"):
    row = json.loads(line)
    if row["role"] == "fixer":
        edit = json.loads(row["text"])["edits"][0]
        print(f"{edit['path']}:")
        print(f"-{edit['find']}")
        print(f"+{edit['replace']}")
EOF
echo "This is the code Starlette 0.26.1 shipped (CVE-2023-29159)."

if [[ "$MODE" == "--offline" ]]; then
    OUT="${DEMO_OUT:-$ROOT/runs/demo-offline}"
    rm -rf "$OUT"

    # -- Step 2: run the proof loop by replaying the Meta recordings ---------
    step "2/6 run exhibit-a (offline replay of the live Meta runs)"
    python3 - "$OUT" <<'EOF'
import json, os, sys, time
from pathlib import Path

# Prove the replay is offline: without the key no live call could be built.
os.environ.pop("META_API_KEY", None)

from bench.record_meta import replay_case

root = Path(".")
out_root = Path(sys.argv[1])
for case_id in ("archive-extraction-pathtraversal", "starlette-cve-2023-29159"):
    meta = json.loads((root / "bench" / "corpus" / case_id / "recordings"
                       / "meta-muse-wonder-1.0-compact.json").read_text())
    started = time.monotonic()
    outcome = replay_case(case_id, "muse-wonder-1.0", out_root / case_id, "compact")
    elapsed = time.monotonic() - started
    verdicts = ", ".join(
        f"{v['suspicion_id']}={v['verdict']} fix_verified={v['fix_verified']}" for v in outcome.verdicts)
    print(f"{case_id}: baseline_ok={outcome.baseline_ok} suspicions={outcome.suspicions_raised} "
          f"verdicts: {verdicts} (${meta['cost_usd']:.4f} live, {elapsed:.1f}s replay)")
    proven = [v for v in outcome.verdicts if v["verdict"] == "proven" and v["fix_verified"]]
    if not proven:
        sys.exit(f"demo: {case_id} did not end with a proven, verified finding")
print("demo: both cases proven with a verified fix")
EOF

    # -- Steps 3-5: verdict, report, runs ------------------------------------
    step "3/6 the verdicts and the steps behind them (ledger)"
    python3 - "$OUT" <<'EOF'
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
for ledger in sorted(out.glob("*/ledger.jsonl")):
    for line in ledger.read_text().splitlines():
        event = json.loads(line)
        if event["type"] == "verdict":
            p = event["payload"]
            print(f"{event['run_id']} {p.get('suspicion_id')}: {p.get('verdict')} "
                  f"(fix_verified={p.get('fix_verified')}, fix_incomplete={p.get('fix_incomplete')})")
EOF
    # The steps behind each verdict, straight from the ledger (the run id of a
    # replayed case is its directory name). A for loop over a glob: no mapfile.
    for LEDGER in "$OUT"/*/ledger.jsonl; do
        [[ -f "$LEDGER" ]] || continue
        CASE_ID="$(basename "$(dirname "$LEDGER")")"
        echo
        echo "--- trace: $CASE_ID ---"
        python3 -m exhibit_a.cli trace --ledger "$LEDGER" "$CASE_ID"
    done

    step "4/6 the report"
    # No mapfile: macOS ships bash 3.2.
    FIRST_VERDICT="$(find "$OUT" -name verdict.json -path "*packages*" | sort | head -n 1)"
    [[ -n "$FIRST_VERDICT" ]] || { echo "demo: no finding package was written" >&2; exit 1; }
    python3 -m exhibit_a.cli report "$(dirname "$FIRST_VERDICT")"

    step "5/6 past runs"
    python3 - "$OUT" <<'EOF'
import json, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

out = Path(sys.argv[1])
commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
from exhibit_a.ledger.index import append_run
from exhibit_a.schemas import RunRecord, VerdictCounts

index = out / "runs.jsonl"
if index.exists():
    index.unlink()
for ledger in sorted(out.glob("*/ledger.jsonl")):
    run_id, counts = ledger.parent.name, {"proven": 0, "discarded_unproven": 0,
                                          "invalid_test": 0, "flaky": 0, "env_failure": 0}
    raised, tokens_in, tokens_out, cost = 0, 0, 0, 0.0
    stamps = []
    for line in ledger.read_text().splitlines():
        event = json.loads(line)
        stamps.append(datetime.fromisoformat(event["ts"]))
        tokens_in += int(event.get("tokens_in", 0))
        tokens_out += int(event.get("tokens_out", 0))
        cost += float(event.get("cost_usd", 0.0))
        kind, payload = event["type"], event.get("payload", {})
        if kind == "suspicion_raised":
            raised += 1
        elif kind == "verdict" and payload.get("verdict") in counts:
            counts[payload["verdict"]] += 1
    append_run(index, RunRecord(run_id=run_id, repo="bench/corpus (compact Meta replay)",
                                commit=commit or "unknown", ts=datetime.now(timezone.utc),
                                status="completed",
                                verdict_counts=VerdictCounts(**counts),
                                severity="high" if counts["proven"] else None,
                                discarded_suspicions=max(0, raised - counts["proven"]),
                                tokens_in=tokens_in, tokens_out=tokens_out,
                                cost_usd=cost,
                                # Replay wall time, first to last ledger event.
                                duration_s=(max(stamps) - min(stamps)).total_seconds() if stamps else 0.0,
                                ledger_path=f"{run_id}/ledger.jsonl"))
EOF
    python3 -m exhibit_a.cli runs --index "$OUT/runs.jsonl"

    step "6/6 live view (ledger-backed, read-only)"
    echo "To browse this demo run:"
    echo "  PYTHONPATH=src python3 -m exhibit_a.cli dashboard --source local:$OUT --port 8765"
    echo "  open http://127.0.0.1:8765"
    if [[ "$SERVE" == "--serve" ]]; then
        exec python3 -m exhibit_a.cli dashboard --source "local:$OUT" --port 8765
    fi
    exit 0
fi

# --live: the same story, answered live by Muse Wonder -------------------------
step "live demo (Muse Wonder, compact profile, \$1 cap)"
if [[ -z "${META_API_KEY:-}" ]]; then
    echo "demo: --live needs META_API_KEY in the environment (export it first)" >&2
    exit 2
fi
OUT="${DEMO_OUT:-$ROOT/runs/demo-live}"
rm -rf "$OUT"
python3 -m exhibit_a.cli run \
    --case "$ROOT/bench/corpus/archive-extraction-pathtraversal" \
    --profile compact --budget-usd 1 \
    --provider meta --model muse-wonder-1.0 \
    --out "$OUT"
step "report"
FIRST_VERDICT="$(find "$OUT" -name verdict.json -path "*packages*" | sort | head -n 1)"
if [[ -n "$FIRST_VERDICT" ]]; then
    python3 -m exhibit_a.cli report "$(dirname "$FIRST_VERDICT")"
else
    echo "demo: no proven finding this run (the model is not deterministic;"
    echo "see docs/bench/meta-run.md). The ledger still records every step:"
    python3 -m exhibit_a.cli ledger archive-extraction-pathtraversal --ledger "$OUT/ledger.jsonl" || true
fi
step "live view"
echo "  PYTHONPATH=src python3 -m exhibit_a.cli dashboard --source local:$OUT --port 8765"
