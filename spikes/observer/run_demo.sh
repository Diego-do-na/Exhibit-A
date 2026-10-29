#!/usr/bin/env bash
# Observer spike driver. Runs each scenario with pytest under the ptrace
# observer, then prints what each observer recorded. Designed to run INSIDE the
# container started by run_in_container.sh, but also runs on a bare Linux host
# with python3+gcc (no Docker) for a quick local check.
#
# Env the caller may override: PYTHON (default python3).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${PYTHON:-python3}"
WORK="$(mktemp -d)"
ALLOWED="$WORK/allowed"; OUTSIDE="$WORK/outside"
mkdir -p "$ALLOWED" "$OUTSIDE"
echo "public" > "$ALLOWED/public.txt"
echo "CANARY-TOKEN-$RANDOM$RANDOM" > "$OUTSIDE/canary.txt"
CANARY="$OUTSIDE/canary.txt"

# Use a prebuilt observer binary if given (container run), else compile here.
# NB: the binary must live on an exec-able filesystem. Docker --tmpfs mounts are
# noexec, so in the container we run the binary in place from its (bind-mounted,
# exec) location rather than copying it onto $WORK (tmpfs). A production image
# would bake the observer into an image layer for the same reason.
if [ -n "${OBSERVER_BIN:-}" ] && [ -x "${OBSERVER_BIN}" ]; then
  OBS="$OBSERVER_BIN"
else
  OBS="$WORK/ptrace_observer"
  gcc -O2 -Wall -o "$OBS" "$HERE/ptrace_observer.c" || exit 2
fi

run_scenario() {
  local scenario="$1"
  local inproc="$WORK/inproc.$scenario.jsonl"
  local ptrace="$WORK/ptrace.$scenario.jsonl"
  : > "$inproc"; : > "$ptrace"
  echo
  echo "=================================================================="
  echo "SCENARIO: $scenario"
  echo "=================================================================="
  SPIKE_CANARY="$CANARY" SPIKE_ALLOWED_DIR="$ALLOWED" \
  SPIKE_INPROC_EVENTS="$inproc" SPIKE_SCENARIO="$scenario" \
  PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}" \
  "$OBS" "$CANARY" "$ptrace" -- \
    "$PYTHON" -X importtime=0 -m pytest -q -p no:cacheprovider \
      -p inproc_hook "$HERE/test_exploit.py" >/dev/null 2>"$WORK/pytest.err"
  local rc=$?
  echo "pytest exit code: $rc  (1 = test failed/red = exploit 'worked')"
  echo "--- in-process hook records (canary opens seen in Python, with stack) ---"
  if [ -s "$inproc" ]; then nl -ba "$inproc"; else echo "(none)"; fi
  echo "--- ptrace observer records (canary opens seen at the syscall boundary) ---"
  if [ -s "$ptrace" ]; then nl -ba "$ptrace"; else echo "(none)"; fi
  echo "--- what each signal reports ---"
  local inproc_n ptrace_n prov
  inproc_n=$(wc -l < "$inproc" | tr -d ' ')
  ptrace_n=$(wc -l < "$ptrace" | tr -d ' ')
  # Provenance, the way the real oracle reads it: does the in-process record
  # carry an application entry-point frame (demo_app.serve)? This record is a
  # file the TEST can write, so provenance here is only as trustworthy as the
  # test's inability to forge it.
  if grep -q '"function": "serve"' "$inproc" 2>/dev/null; then prov=YES; else prov=no; fi
  echo "in-process: canary read = $([ "$inproc_n" -gt 0 ] && echo YES || echo no)   app-provenance claimed = $prov"
  echo "ptrace    : canary read = $([ "$ptrace_n" -gt 0 ] && echo YES || echo no)   app-provenance          = n/a (syscall level)"
  # Combined oracle rule: proven iff an out-of-process observer saw the open
  # (fact) AND the in-process record shows app provenance.
  local fact=no; [ "$ptrace_n" -gt 0 ] && fact=YES
  if [ "$fact" = YES ] && [ "$prov" = YES ]; then
    echo ">> combined (ptrace fact + in-proc provenance) => PROVEN"
  else
    echo ">> combined (ptrace fact + in-proc provenance) => not proven"
  fi
}

run_scenario honest_via_entrypoint
run_scenario cheat_forge_inproc
run_scenario cheat_hide_subprocess
run_scenario cheat_read_then_forge

echo
echo "workdir kept at: $WORK"
