#!/bin/sh
# Cold-clone Exhibit A at a given SHA and fail loudly if the installed
# wheel, CLI, dashboard UI, or non-Docker tests are incomplete.
#
# Usage (from anywhere):
#   sh scripts/cold_clone_check.sh <sha> [repo-url]
#
# Default repo-url is this checkout (or its origin remote). The script
# never treats a skipped sandbox test as passing: it runs
# ``pytest -q -m 'not docker'`` and requires a zero exit.

set -eu

die() {
    echo "cold_clone_check: $*" >&2
    exit 1
}

usage() {
    echo "usage: sh scripts/cold_clone_check.sh <sha> [repo-url]" >&2
    exit 2
}

SHA="${1:-}"
[ -n "$SHA" ] || usage

HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
REPO_URL="${2:-$HERE}"

command -v git >/dev/null 2>&1 || die "git is missing"
command -v python3 >/dev/null 2>&1 || die "python3 is missing"
command -v curl >/dev/null 2>&1 || die "curl is missing"

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/exhibit-a-cold-clone.XXXXXX")
DASH_PID=""
DASH_LOG="$WORKDIR/dashboard.log"

cleanup() {
    status=$?
    if [ -n "${DASH_PID:-}" ]; then
        kill "$DASH_PID" 2>/dev/null || true
        wait "$DASH_PID" 2>/dev/null || true
    fi
    if [ "$status" -ne 0 ]; then
        echo "cold_clone_check: workdir kept at $WORKDIR" >&2
        if [ -f "$DASH_LOG" ]; then
            echo "cold_clone_check: dashboard log:" >&2
            cat "$DASH_LOG" >&2 || true
        fi
    else
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT INT HUP TERM

echo "cold_clone_check: cloning $REPO_URL at $SHA into $WORKDIR"

CLONE="$WORKDIR/src"
git clone --quiet "$REPO_URL" "$CLONE" || die "git clone failed"
git -C "$CLONE" checkout --quiet --detach "$SHA" || die "cannot check out $SHA"
test -f "$CLONE/pyproject.toml" || die "pyproject.toml missing from clone"
test -d "$CLONE/web/dashboard" || die "web/dashboard missing from clone"
test -f "$CLONE/web/dashboard/index.html" || die "web/dashboard/index.html missing from clone"

VENV="$WORKDIR/venv"
python3 -m venv "$VENV" || die "python3 -m venv failed"
BIN="$VENV/bin"
"$BIN/python" -m pip install --upgrade pip >/dev/null
( cd "$CLONE" && "$BIN/python" -m pip install . ) || die "pip install . failed"

command -v "$BIN/exhibit-a" >/dev/null 2>&1 || die "exhibit-a entry point missing after pip install"

echo "cold_clone_check: exhibit-a --help"
"$BIN/exhibit-a" --help >/dev/null || die "exhibit-a --help failed"

echo "cold_clone_check: exhibit-a init in an empty repo"
EMPTY="$WORKDIR/empty-repo"
mkdir "$EMPTY"
git -C "$EMPTY" init -q
( cd "$EMPTY" && "$BIN/exhibit-a" init ) || die "exhibit-a init failed"
test -f "$EMPTY/.github/workflows/exhibit-a.yml" || die "init did not write the workflow"

echo "cold_clone_check: exhibit-a scan on a sample pytest repo"
SAMPLE="$WORKDIR/sample"
mkdir -p "$SAMPLE/tests"
printf '%s\n' '[project]' 'name = "cold-clone-sample"' 'version = "0.0.1"' >"$SAMPLE/pyproject.toml"
printf '%s\n' '[pytest]' 'addopts = -q' >"$SAMPLE/pytest.ini"
printf '%s\n' 'def ping():' '    return "ok"' >"$SAMPLE/app.py"
printf '%s\n' 'import pytest' '' 'def test_ping():' '    assert pytest is not None' >"$SAMPLE/tests/test_app.py"
SCAN_OUT=$("$BIN/exhibit-a" scan "$SAMPLE") || die "exhibit-a scan failed"
echo "$SCAN_OUT" | grep -q '"test_cmd": "pytest"' || die "scan did not detect pytest (got: $SCAN_OUT)"
echo "$SCAN_OUT" | grep -q '"framework": "pytest"' || die "scan framework was not pytest (got: $SCAN_OUT)"

echo "cold_clone_check: packaged dashboard UI"
"$BIN/python" - <<'PY' || die "installed default_web_dir has no UI"
from pathlib import Path
from exhibit_a.dashboard.server import default_web_dir, STATIC_FILES
web = default_web_dir()
missing = [name for name in STATIC_FILES if not (web / name).is_file()]
if missing:
    raise SystemExit(f"dashboard UI missing from install: {missing} (web_dir={web})")
if not (web / "views" / "index.js").is_file():
    raise SystemExit(f"dashboard views missing from install (web_dir={web})")
print(web)
PY

echo "cold_clone_check: exhibit-a dashboard --no-open"
RUNS="$WORKDIR/runs"
mkdir -p "$RUNS/cold-clone"
printf '%s\n' \
    '{"ts":"2026-01-01T00:00:00+00:00","run_id":"cold-clone","type":"scan_done","payload":{"language":"python","test_cmd":"pytest"}}' \
    >"$RUNS/cold-clone/ledger.jsonl"
PORT=$("$BIN/python" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
"$BIN/exhibit-a" dashboard --source "local:$RUNS" --no-open --port "$PORT" >"$DASH_LOG" 2>&1 &
DASH_PID=$!
i=0
while [ "$i" -lt 100 ]; do
    if grep -q "serving" "$DASH_LOG" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$DASH_PID" 2>/dev/null; then
        die "dashboard exited before serving"
    fi
    i=$((i + 1))
    sleep 0.1
done
grep -q "serving" "$DASH_LOG" || die "dashboard did not print a serving line"
grep -q "127.0.0.1" "$DASH_LOG" || die "dashboard did not bind 127.0.0.1"
HTML=$(curl -fsS -H "Host: 127.0.0.1:$PORT" "http://127.0.0.1:$PORT/") \
    || die "dashboard did not serve /"
echo "$HTML" | grep -q "Exhibit A" || die "dashboard HTML is missing the Exhibit A UI"
curl -fsS -H "Host: 127.0.0.1:$PORT" "http://127.0.0.1:$PORT/dashboard.css" >/dev/null \
    || die "dashboard did not serve dashboard.css"
curl -fsS -H "Host: 127.0.0.1:$PORT" "http://127.0.0.1:$PORT/dc-lite.js" >/dev/null \
    || die "dashboard did not serve dc-lite.js"
kill "$DASH_PID" 2>/dev/null || true
wait "$DASH_PID" 2>/dev/null || true
DASH_PID=""

echo "cold_clone_check: pip install dev extras and pytest -q -m 'not docker'"
( cd "$CLONE" && "$BIN/python" -m pip install ".[dev]" ) || die "pip install .[dev] failed"
command -v "$BIN/pytest" >/dev/null 2>&1 || die "pytest missing after pip install .[dev]"
( cd "$CLONE" && "$BIN/python" -m pytest -q -m "not docker" ) \
    || die "pytest -q -m 'not docker' failed"

echo "cold_clone_check: OK at $SHA"
