#!/usr/bin/env bash
# Run the observer spike inside a container that mirrors the product sandbox
# posture EXACTLY, to answer: what must be loosened for the ptrace observer?
#
# Finding (see docs/oracle-observer-spike.md): nothing. When the observer is the
# PARENT of the test process (PTRACE_TRACEME + same uid), tracing needs no
# CAP_SYS_PTRACE, and modern Docker's default seccomp profile already permits
# the ptrace syscall. So we run under the product's own flags unchanged:
#   --cap-drop ALL --security-opt no-new-privileges --user <uid> --network none
#   --read-only  (+ the tmpfs /tmp the product uses)
# and the observer still records every canary open. (A separate-container
# sidecar that ATTACHES to a non-descendant would instead need CAP_SYS_PTRACE
# and a shared PID namespace -- that variant is discussed in the write-up and is
# not exercised here.)
#
# Build phase (host, needs a compiler + a package registry):
#   * compile the observer to a STATIC binary (so the run image needs no libc
#     matching and no compiler);
#   * install pytest into a host directory.
# Run phase (container): stock python image, NO network, NO compiler, binary and
# pytest mounted read-only. Mirrors image.py's build-then-run split; a real
# image would bake both in (note: the binary must sit on an exec filesystem --
# Docker --tmpfs is noexec -- so it is baked into a layer / bind-mounted, not
# dropped on tmpfs).
#
# Usage: ./run_in_container.sh [image]
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${1:-mirror.gcr.io/library/python:3.11.9-slim}"
BIN="$HERE/ptrace_observer.static"
PYLIBS="${PYLIBS:-/tmp/exhibit-a-spike-pylibs}"

echo "### build phase (host): static observer + pytest into a dir ###"
gcc -O2 -Wall -static -o "$BIN" "$HERE/ptrace_observer.c"
file "$BIN" | cut -d, -f1-2
[ -d "$PYLIBS/_pytest" ] || pip install --target "$PYLIBS" "pytest==7.3.2" -q
echo "pytest staged at $PYLIBS"

echo
echo "### run phase: EXACT product sandbox posture, nothing added ###"
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,size=64m,mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 -e HOME=/tmp \
  -v "$HERE":/spike:ro -v "$PYLIBS":/pylibs:ro \
  -e PYTHON=python3 -e PYTHONPATH=/pylibs \
  -e OBSERVER_BIN=/spike/ptrace_observer.static \
  "$IMAGE" bash -lc '
    echo "sandbox check:"; id; grep -E "^(Seccomp|CapEff|NoNewPrivs):" /proc/self/status
    cp /spike/*.py /spike/*.sh /tmp/ && cd /tmp && bash run_demo.sh'
