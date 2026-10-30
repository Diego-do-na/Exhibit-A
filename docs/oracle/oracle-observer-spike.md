# Oracle observer spike (A-1): out-of-process observation

**Status:** time-boxed research spike. **Date:** 2026-10-28/29. **Author:** claude-cloud.
**Scope:** `spikes/observer/` + this file only; no product `src/` or `tests/` touched.
**Recommendation:** **B — adopt a syscall-level observer as a second signal**, not as a
replacement for the in-process stack hook. Full out-of-process *provenance* is real but
too heavy for the Nov 2 freeze; it goes on the roadmap. Details and evidence below.

Every claim is tagged **TESTED** (I ran it and saw the result), **REASONED** (argued from
how the mechanism works, not run end-to-end), or **UNVERIFIED** (needs your Mac or more
time). The cloud machine is **x86_64 Linux, root, Docker 29.9.2, kernel 6.18, no YAMA
`ptrace_scope`, seccomp/fanotify/BPF all compiled in**. It is **not** aarch64 and has **no
Colima**, so every aarch64/Colima statement is REASONED or UNVERIFIED and flagged for you.

---

## 1. The problem, restated precisely

A-1 (from `docs/sprint-review.md`) is really two separate weaknesses, and keeping them
apart is the whole point of this spike:

- **Fact forgery / suppression.** The oracle's "the canary was read" comes from an events
  file the test process can also write (mounted `:rw`), and the observer (the audit hook)
  runs *inside the test's own process*. The test can append fake events, or suppress real
  ones, or read the plugin's memory.
- **Provenance forgery.** Even a perfect fact signal is not enough: the proof standard
  (SPEC §4) requires the read to have come from **application code reached through a
  declared entry point**. That judgement is made from the **Python call stack**, which is
  recorded into the same test-writable file.

The distinction drives the result: **the fact of a read can be observed out-of-process and
made unforgeable; provenance lives in the interpreter's call stack and cannot be recovered
by a syscall-level observer at all.** So any syscall observer is, at best, a tamper-proof
*second signal*, never a drop-in replacement for the stack hook. The prototypes below were
built to prove exactly where that line falls.

---

## 2. What was built and run

Two runnable prototypes under `spikes/observer/` (see its `README.md` for exact commands):

1. **`ptrace_observer.c`** — candidate 1 (ptrace variant). A supervisor that runs the test
   as a traced child and reports every `open`/`openat`/`openat2` of the canary, following
   `fork`/`clone`/`exec`, by reading the path argument out of the tracee at the
   syscall-entry stop. x86_64 only.
2. **`fanotify_observer.c`** — candidate 3. A host-side watcher on the canary *file* using
   `fanotify` (`FAN_OPEN`), run by the orchestrator outside any container.

Alongside them, `inproc_hook.py` is a stripped copy of the product's audit-hook idea (fact
+ stack, written to a test-writable file) so the demo can show the two side by side, and
`test_exploit.py` drives an honest exploit plus three cheats.

### 2.1 Results — all TESTED under the EXACT product sandbox posture

`run_in_container.sh` runs everything inside a container started with the product's own
flags, verified at runtime: `uid=1000` (non-root), `CapEff=0000000000000000` (all caps
dropped), `NoNewPrivs=1`, `Seccomp=2` (filter active), `--network none`, `--read-only`,
the product's `--tmpfs /tmp`. **Nothing was added to that posture.**

| scenario | in-proc: read / prov | ptrace: read | combined verdict |
|---|---|---|---|
| `honest_via_entrypoint` (real exploit through `serve`) | YES / YES | YES | **PROVEN** ✔ correct |
| `cheat_forge_inproc` (forge event, never read canary) | YES / YES | **no** | not proven ✔ caught |
| `cheat_hide_subprocess` (`cat` the canary, bypass audit hook) | no / no | **YES** | not proven ✔ caught |
| `cheat_read_then_forge` (really read canary, forge the stack) | YES / YES | YES | **PROVEN** ✘ **false positive** |

"Combined verdict" is the rule *proven iff an out-of-process observer saw the open AND the
in-process record shows app provenance.*

Reading of the table:
- The syscall observer **catches pure fact-forgery** (`cheat_forge_inproc`: it saw no open,
  so the forged "proof" is contradicted) and **catches audit-hook bypass**
  (`cheat_hide_subprocess`: `cat` and `dd` never trip the Python hook, but ptrace/fanotify
  see them). These are the two cases the current oracle is blind to.
- It **does not** catch **provenance forgery** (`cheat_read_then_forge`): a test that really
  opens the canary and then writes a fake application stack makes both signals agree on a
  read that never went through the app. **This is the honest limit of a second signal.**

### 2.2 fanotify — TESTED

`run_fanotify_demo.sh`: a host-side `fanotify` watch on the canary file caught **all three**
opens performed inside a container that bind-mounts it — Python `open()`, `cat` in a
subprocess, and `dd` — each with a distinct host-namespace pid. fanotify hooks the VFS on
the shared superblock, so it sees reads by any mechanism and the test cannot touch the
watcher (it is a different process in a different namespace). It reports only the **fact**
and a **host-namespace pid**; no stack, no app provenance.

---

## 3. Candidate-by-candidate evaluation

### Candidate 1 — ptrace supervisor (prototyped)

- **(a) Both environments?** x86_64 Ubuntu GH runner: **TESTED here** (same arch/engine).
  aarch64 Colima: **REASONED, needs a port.** The prototype reads x86_64 registers
  (`orig_rax`, `rdi/rsi`) and hard-codes syscall numbers (`openat`=257, `openat2`=437). On
  aarch64 the numbers differ (`openat`=56) and registers come via `PTRACE_GETREGSET`
  (`regs[8]` = nr, `regs[0..]` = args). A clean port is ~a day; or lean on `strace -f -e
  openat` (it IS ptrace and already handles both arches) and parse its output, trading the
  custom binary for a dependency. **UNVERIFIED on Colima until you run §6.**
- **(b) Can the test forge/suppress/alter?** **No, for the fact.** The record is produced by
  the tracer process from the tracee's registers at the syscall-entry stop; the test cannot
  write the tracer's file, and it cannot issue `openat` without the tracer seeing it. It
  **cannot forge the fact and cannot hide a `cat`/`dd`/mmap read** (TESTED). It **can still
  forge provenance** by the `cheat_read_then_forge` path, because provenance is not in this
  signal.
- **(c) Provenance?** **Only the fact + pid/path**, not application provenance, on its own.
  To combine: use ptrace as the authoritative *fact-of-read*, and keep the existing
  stack-based hook for provenance; mark a finding proven only if the ptrace fact and the
  in-process provenance agree. That upgrades the oracle against §2.1 rows 2–3 but not row 4
  (see Risk). Recovering provenance out-of-process is possible in principle — at the
  syscall stop the tracer can walk the tracee's CPython frames (this is exactly what
  `py-spy`/`gdb` do) to read the real Python stack the test cannot forge — but that is a
  CPython-internals unwinder, version-specific and fiddly. **REASONED; not built;** it is
  the "strongest" answer and the main roadmap item.
- **(d) Policy to loosen?** **None, surprisingly — TESTED.** Because the observer is the
  *parent* of the test (`PTRACE_TRACEME` + same uid), tracing needs **no `CAP_SYS_PTRACE`**,
  and modern Docker's default seccomp profile already permits the `ptrace` syscall on
  kernels ≥4.8. It ran under `--cap-drop ALL --security-opt no-new-privileges --user
  1000:1000` unchanged. A *separate-container sidecar* that attaches to a non-descendant
  would instead need `CAP_SYS_PTRACE` on the sidecar and a shared PID namespace
  (`--pid=container:<test>`) — **REASONED, not exercised;** my in-container attach check was
  not representative because the target was a forked descendant. Note the binary must live
  on an **exec** filesystem: Docker `--tmpfs` is `noexec`, so bake the observer into an
  image layer (TESTED: running it off `/tmp` tmpfs fails with `Permission denied`).
- **(e) Effort:** keep-the-parent-model second signal on x86_64 + wire into
  `sandbox/runner.py` and `oracle.py`: **~1–1.5 days.** Add the aarch64 port (or switch to
  `strace` parsing): **+0.5–1 day.** Out-of-process CPython stack unwinding for real
  provenance: **~1–2 weeks, post-freeze.**
- **(f) Risks:** per-syscall stop adds overhead (acceptable for one short test; measure);
  arch-specific C is a maintenance seam; correct `fork`/`clone`/`exec` following and signal
  forwarding are easy to get subtly wrong; **does not close provenance forgery.**

### Candidate 2 — gVisor (runsc) as the runtime

- **(a)** `runsc` is **not installed here** and its release bucket is outside the registry
  allow-list, so **UNVERIFIED**. REASONED: on x86_64 GH runners gVisor installs and runs
  (ptrace or KVM platform); on **aarch64 Colima** support is historically partial and the
  default `ptrace` platform is slow — this is the environment most likely to break, and you
  must test it (§6).
- **(b)** Strong: `runsc`'s `--strace`/debug log records syscalls from *outside* the
  sandboxed kernel, so the guest test cannot forge or suppress it.
- **(c)** Same ceiling as candidate 1: syscalls, not Python stacks. **Fact only.**
- **(d)** It *replaces the runtime* rather than loosening a flag, but that is a large
  compatibility and ops change: every sandbox run goes through a different kernel
  implementation; pytest and the Starlette case must be re-validated under it. Startup is
  slower.
- **(e)** Install + runtime registration + re-validate the whole sandbox + parse strace
  logs: **~3–5 days, and riskiest on the exact second environment we cannot test here.**
- **(f)** Biggest risk is Colima/aarch64 viability and compatibility regressions a week
  before freeze. **Roadmap, not this week.**

### Candidate 3 — host-side fanotify/inotify (prototyped)

- **(a)** x86_64: **TESTED.** `fanotify` `FAN_OPEN` marking of a single file is
  arch-independent, so aarch64 is **REASONED-portable** (no register/syscall-number issues
  like ptrace). Needs the watcher to run on the host with `CAP_SYS_ADMIN`; on Colima the
  "host" is the Linux VM, and the canary must be a file on a filesystem the VM watches and
  bind-mounts into the container — **UNVERIFIED on Colima (§6).**
- **(b)** **Cannot be touched by the test at all** — different process, different namespace.
  It **cannot be forged or suppressed** and **catches audit-hook bypass** (TESTED: `cat`,
  `dd`). With `FAN_OPEN_PERM` it could even *block* the open.
- **(c)** **Fact only, and weakest on identity:** the pid is in the host/VM namespace, so
  mapping it back to "the test's app code" is not possible from here. Best used as a coarse
  "someone read the canary" tripwire combined with the in-process provenance.
- **(d)** No change to the *container* policy (it does not run in the sandbox). It needs
  `CAP_SYS_ADMIN` on the **orchestrator/host**, which already launches Docker.
- **(e)** **~0.5–1 day.** Cheapest of all candidates. Cross-arch for free.
- **(f)** No provenance and no in-container pid; a second reader of the same inode is
  ambiguous. Pure tripwire.

### Candidate 4 — different-uid test + root-owned plugin writing a pre-opened fd

- **Finding: this does not work as stated, and the reason matters.** The audit-hook plugin
  runs **in the test's own process**. Same process ⇒ same uid and same address space ⇒ any
  fd the plugin holds, the test can `os.write()` to, and any key the plugin holds, the test
  can read from memory (A-1's own "read the plugin's memory"). A different uid only helps if
  the writer is a **different process** — at which point you are back to candidates 1/2/3.
  **REASONED.** In-process HMAC-signed events have the same flaw against an in-process
  adversary. So "harden the in-process channel" cannot, by itself, close provenance forgery;
  provenance has to move out of process (candidate 1's roadmap unwinder) to be unforgeable.
- **(e)** A weaker but cheap variant — run the test as uid B and the events *file* owned by
  uid A so the test cannot append to it — only helps if a **separate** process does the
  writing, i.e. it is candidates 1/3 wearing a hat. **~1 day, but it buys fact-integrity
  only, same as candidate 3 with less coverage.**

### Candidate 5 — eBPF

- **REASONED/UNVERIFIED.** An eBPF LSM/tracepoint on `openat` would be a clean host-side
  fact signal (kernel has `CONFIG_BPF_LSM=y`, BTF present here). But it needs
  `CAP_BPF`/`CAP_SYS_ADMIN` and a matching kernel/BTF on the host, and on **Colima's
  aarch64 VM** BTF/toolchain availability is uncertain — likely **not realistic by Nov 2**,
  and fanotify gets ~90% of the same value with none of the kernel-version coupling. Did not
  pursue.

---

## 4. Recommendation — **B**, with a concrete plan

Adopt a syscall-level observer **as a second signal**, combined with the existing
stack-based provenance. Do the cheap, cross-arch, zero-policy-change version first:

1. **Ship fanotify host-side tripwire (candidate 3) now.** ~0.5–1 day, cross-arch, cannot
   be touched by the test, and it closes the *audit-hook-bypass* blind spot (subprocess /
   mmap / C-extension reads) and *fact suppression*. Oracle rule: if the in-process hook
   reports a proven read but fanotify saw **no** open of the canary, **downgrade to
   unproven** (contradiction). If fanotify saw an open but the in-process hook has **no app
   provenance**, that is effect-without-provenance → unproven (already the oracle's stance).
2. **Add the ptrace parent-observer (candidate 1) on x86_64** as the richer fact signal
   (gives the in-container-adjacent pid and the path, follows subprocesses) — **no sandbox
   policy change** (TESTED). Gate it behind a flag; keep `strace -f` as the aarch64 fallback
   until the aarch64 port lands.
3. **Keep provenance where it is** (the hardened in-process stack hook) for the freeze, and
   **document the residual limit honestly**: a test that both reads the canary and forges
   its own stack can still manufacture a proof (`cheat_read_then_forge`). The product
   already says "isolated and resource-limited," never "100% safe"; this is the oracle
   analogue and belongs in `SPEC.md` §10 / `docs/GUIDE.md` as a declared limit.
4. **Roadmap (post-freeze), the true "strongest":** out-of-process **provenance** via a
   ptrace supervisor that walks the tracee's CPython frames at the `openat` stop (py-spy
   technique). That is the only mechanism that makes provenance itself unforgeable by an
   in-process test. ~1–2 weeks; do not attempt before Nov 2.

Why not **A** (adopt one mechanism as *the* answer now): no syscall-level mechanism recovers
provenance, so none can replace the stack hook; adopting one as the whole oracle would be a
regression on the proof standard. Why not **C** (not viable / fall back to signed events):
the second-signal win is real, cheap, tested, and needs **no policy relaxation** — leaving
it on the roadmap would ship a weaker oracle than we can have by Nov 2; and the signed-events
design does not, on its own, close provenance forgery either (candidate 4).

**Against the deadline (freeze Nov 2, today Oct 28/29):** step 1 is ~1 day and low-risk;
step 2 is ~1 day on x86_64 with the strace fallback for Macs; step 3 is documentation. All
three fit before freeze. Steps toward true out-of-process provenance (and gVisor) are
explicitly deferred.

---

## 5. Honest limits — what this spike did and did not establish

- **Biggest risk / single most important caveat:** the second signal **does not close
  provenance forgery** (`cheat_read_then_forge`, TESTED false-positive). If the threat model
  must exclude a test that forges its own stack, only out-of-process stack reconstruction
  suffices, and that is not shippable by Nov 2. Everything in Recommendation B is an honest
  improvement, not a complete fix.
- **Could not test:** anything on **aarch64 / Colima** (no such machine here) — the ptrace
  port, gVisor on aarch64, fanotify inside the Colima VM; **gVisor at all** (not installed,
  release outside the registry allow-list); the **separate-container ptrace sidecar** with a
  shared PID namespace and `CAP_SYS_PTRACE` (my attach check used a descendant, so it was
  not representative); the **YAMA-restricted** ptrace case (this kernel has no
  `ptrace_scope`, a developer Mac's VM may differ); out-of-process CPython frame unwinding
  (not built).
- **Environment caveat:** results come from an x86_64 Linux container under this repo's own
  sandbox flags, not from a live GH Actions run or a Mac. The posture was verified at
  runtime (uid/caps/seccomp printed by the demo), but CI and Colima can still differ.

---

## 6. Exact commands to run on your Mac (Apple Silicon, Colima)

Colima must be running (`colima start`). These reproduce the x86_64 results on aarch64 and
fill the gaps I could not test. Run from the repo root.

```bash
# 0. sanity: Docker via Colima is up, and note the arch (expect aarch64)
docker info | grep -E 'Server Version|Architecture'
uname -m
```

```bash
# 1. ptrace observer under the EXACT product sandbox posture.
#    EXPECT on aarch64: the current prototype is x86_64-only, so it will either
#    build-fail or see no opens. That is the datapoint: it tells us the aarch64
#    port (or the strace fallback) is required. Run it and paste the output.
cd spikes/observer
bash run_in_container.sh
```

```bash
# 2. aarch64 fallback check: does strace (which IS ptrace, cross-arch) see the
#    canary open under the product posture? If yes, the strace-parsing fallback
#    is viable on Macs today.
docker run --rm --network none --read-only --tmpfs /tmp:rw,size=64m,mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 -e HOME=/tmp \
  -v "$PWD":/spike:ro mirror.gcr.io/library/python:3.11.9-slim bash -lc '
    apt-get help >/dev/null 2>&1; command -v strace || echo "NOTE: install strace in the image";
    mkdir -p /tmp/a /tmp/o && echo CANARY-X > /tmp/o/canary.txt;
    strace -f -e trace=openat -qq python3 -c "open(\"/tmp/a/../o/canary.txt\").read()" 2>&1 | grep canary || echo "no strace or no match"'
```

```bash
# 3. host-side fanotify from INSIDE the Colima VM (the "host" on a Mac).
#    fanotify watches a VM file; the container bind-mounts it. EXPECT: all three
#    opens caught, same as x86_64. If the canary lives on a virtiofs/9p share
#    from macOS instead of inside the VM, fanotify may NOT see it — that is the
#    key Colima-specific thing to confirm.
colima ssh -- 'uname -m; cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "no yama"'
cd spikes/observer
bash run_fanotify_demo.sh        # run on the Linux side; if on macOS host, run inside: colima ssh
```

```bash
# 4. (optional, gVisor viability on aarch64) only if you want to scope candidate 2:
#    does runsc even install and run one container on your Colima?
#    If this fails, candidate 2 is off the table for this week — that is the answer.
colima ssh -- 'runsc --version 2>/dev/null || echo "runsc not installed (expected)"'
```

Paste the outputs of 1–3 back and I can turn Recommendation B into concrete tasks
(`sandbox/runner.py` + `oracle.py` wiring, the aarch64 ptrace port vs. strace fallback
decision, and the `SPEC.md`/`GUIDE.md` limit note).
