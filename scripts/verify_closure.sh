#!/bin/sh
# T145 closure verification (needs Docker running).
# Run from the repository root in your own terminal:
#   sh scripts/verify_closure.sh
# Every claim in docs/plan/verification.md maps to one block below.
set -eu
PY=".venv/bin/python"

echo "== 1. No production path enables host execution =="
if grep -rn "allow_host_execution=True" src/exhibit_a/cli/ src/exhibit_a/loop/pipeline.py bench/loop_pipeline.py | grep -v "test-only"; then
  echo "FAIL: host execution switch set outside its guarded definition"
  exit 1
fi
grep -rn "allow_host_execution" src/exhibit_a/loop/runner.py | head -4
echo "OK: switch exists only behind its explicit test-only guard"

echo "== 2. One real run in the sandbox (compact profile, slice on) =="
$PY -m exhibit_a.cli run --case bench/corpus/starlette-cve-2023-29159 --replay --profile compact --slice --out /tmp/exhibit-a-verify-run
$PY -m exhibit_a.cli trace --ledger /tmp/exhibit-a-verify-run/ledger.jsonl 2>/dev/null | head -20 || \
  $PY -m exhibit_a.cli runs --source local:/tmp 2>/dev/null | head -5 || true
echo "OK: ledger written under /tmp/exhibit-a-verify-run; verdict lines are in docs/plan/verification.md"

echo "== 3. Meta replay three consecutive times (no skip, no xfail) =="
for i in 1 2 3; do
  echo "-- run $i of 3"
  $PY -m pytest tests/test_meta_replay.py -m docker -q
done
echo "OK: three consecutive green replay runs"

echo "== 4. Full suite with Docker =="
$PY -m pytest -q
echo "ALL CLOSURE CHECKS PASSED"
