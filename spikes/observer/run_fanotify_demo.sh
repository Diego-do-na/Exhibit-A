#!/usr/bin/env bash
# Demonstrate the host-side fanotify second signal (candidate 3).
#
# The watcher runs on the HOST and watches the real canary file. We then open
# that same inode from a container that bind-mounts it, in three ways the
# in-process Python hook would (a) see, (b) miss (subprocess cat), (c) miss
# (dd, no python open()). fanotify reports every one, because it hooks the VFS
# on the host superblock the bind mount shares.
#
# Needs: root/CAP_SYS_ADMIN on the host, Docker. Linux only.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${IMAGE:-mirror.gcr.io/library/python:3.11.9-slim}"
WORK="$(mktemp -d)"
CANARY="$WORK/canary.txt"
EV="$WORK/fanotify.jsonl"
echo "CANARY-TOKEN-$RANDOM" > "$CANARY"

gcc -O2 -Wall -o "$WORK/fanotify_observer" "$HERE/fanotify_observer.c"

# Self-terminating watcher (SIGTERM after 10s) so the demo never blocks on wait.
# Its stderr goes to a file, not the terminal, so a backgrounded pipe can't make
# the demo look like it is hanging while the watcher lives out its 10s.
timeout 10 "$WORK/fanotify_observer" "$CANARY" "$EV" >"$WORK/watcher.log" 2>&1 &
WATCHER=$!
sleep 0.5

echo "### opening the canary from INSIDE a container, three ways ###"
docker run --rm --network none -v "$CANARY":/canary:ro "$IMAGE" bash -lc '
  echo "(a) python open()";        python3 -c "open(\"/canary\").read()"
  echo "(b) subprocess: cat";      cat /canary > /dev/null
  echo "(c) dd (no python open)";  dd if=/canary of=/dev/null bs=1 count=4 2>/dev/null'

sleep 0.5
kill "$WATCHER" 2>/dev/null || true   # stop the watcher now; don't wait out its timeout
echo
echo "### fanotify recorded (one line per open of the canary inode) ###"
nl -ba "$EV" 2>/dev/null || echo "(none)"
echo "(host_pid is the opener's pid in the HOST namespace, not the container's)"
echo "workdir: $WORK"
