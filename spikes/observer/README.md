# Observer spike (A-1)

**Research spike, not product code.** Prototypes an out-of-process observer for the oracle.
Full analysis and the recommendation: [`docs/oracle-observer-spike.md`](../../docs/oracle-observer-spike.md).

These prototypes deliberately use a relaxed capability in one case (a separate-container
ptrace sidecar would need `CAP_SYS_PTRACE`); the parent-model demo below needs **no** policy
change. Nothing here loosens the product sandbox. Linux only; the ptrace prototype is
x86_64-only (see the write-up for the aarch64 note).

## Files

- `ptrace_observer.c` — candidate 1: a ptrace supervisor that runs the test as a traced
  child and records every `open`/`openat`/`openat2` of the canary, following subprocesses.
- `fanotify_observer.c` — candidate 3: a host-side `fanotify` watch on the canary file.
- `inproc_hook.py` — a stripped copy of the product's in-process audit-hook idea (fact +
  stack), so the demo can show the two observers side by side. **Not** the product plugin.
- `demo_app.py` — a toy app with a declared entry point `serve` and a file-reading sink.
- `test_exploit.py` — one honest exploit and three cheats (forge, subprocess-hide,
  read-then-forge), selected by `SPIKE_SCENARIO`.
- `run_demo.sh` — runs every scenario and prints what each observer recorded plus a combined
  verdict. Runs bare on a Linux host (python3 + gcc), or inside the container runner.
- `run_in_container.sh` — runs `run_demo.sh` inside a container under the **exact** product
  sandbox posture (`--cap-drop ALL --security-opt no-new-privileges --user`, no network,
  read-only root). Build phase on the host; run phase offline.
- `run_fanotify_demo.sh` — host-side fanotify watch catching container opens via a bind
  mount, including `cat`/`dd` that the Python audit hook misses.

## Run it

Everything below is from the repo root. Needs Docker running and `gcc`.

```bash
# A) The main demo: ptrace + in-process hook, side by side, inside a container
#    held to the exact product sandbox posture. Prints uid/caps/seccomp to prove
#    nothing was loosened, then all four scenarios.
bash spikes/observer/run_in_container.sh
```

```bash
# B) The same scenarios on a bare Linux host (no container), for a quick check.
bash spikes/observer/run_demo.sh
```

```bash
# C) Host-side fanotify second signal: three in-container opens, all caught.
bash spikes/observer/run_fanotify_demo.sh
```

## What to look for

In demo A the four scenarios show, under the product posture (verified at runtime):

| scenario | ptrace sees read | in-proc provenance | combined |
|---|---|---|---|
| honest exploit through `serve` | yes | yes | **PROVEN** (correct) |
| forge an event, never read | no | yes (forged) | not proven — forgery caught |
| read via `cat` subprocess | yes | no (hook bypassed) | not proven — bypass caught |
| read the canary then forge the stack | yes | yes (forged) | **PROVEN — false positive** |

The last row is the honest limit: a syscall-level second signal fixes *fact* forgery and
audit-hook bypass, but not *provenance* forgery. See the write-up for why and for the
Apple-Silicon/Colima commands to reproduce these on your Mac.

## Build artifacts

`ptrace_observer.static` and `*.o` are build outputs (git-ignored); regenerate with the
scripts above. Compile the observers by hand with:

```bash
gcc -O2 -Wall -o /tmp/ptrace_observer   spikes/observer/ptrace_observer.c
gcc -O2 -Wall -o /tmp/fanotify_observer spikes/observer/fanotify_observer.c
```
