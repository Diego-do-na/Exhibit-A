#!/usr/bin/env bash
# Manual macOS smoke test. Run from a checkout with Docker/Colima running:
#   scripts/smoke_pr_diff.sh <base-sha> <head-sha> [replay.jsonl]
set -euo pipefail

base=${1:?base commit SHA required}
head=${2:?head commit SHA required}
recording=${3:-}
out=${TMPDIR:-/tmp}/exhibit-a-pr-diff
rm -rf "$out"
args=(run --repo . --out "$out" --pr-diff "$base..$head" --replay)
[[ -n "$recording" ]] && args+=(--recording "$recording")
PYTHONPATH=src python3 -m exhibit_a.cli "${args[@]}"
echo "result: $out/result.json"
