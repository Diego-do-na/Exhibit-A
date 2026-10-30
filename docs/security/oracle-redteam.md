# Oracle red-team — A-1-redteam

Date: 2026-10-28 · Branch: `a1-redteam` · Author: Claude (cloud) · Mode: **report only** (nothing under `src/`, `bench/`, `tests/`, `web/` was changed).

Posture: hostile exploit-test author trying to make the oracle return a **false `proven`** verdict against a *safe* app, or to **suppress a true** one against a *vulnerable* app. All PoCs call the real oracle exactly as the product does (`run_oracle`, same call shape as `tests/test_oracle_eval.py`), via `spikes/redteam/_harness.py`. Every result below was **run**; Docker was unavailable in this machine, so sandbox-path confirmation is given as a Mac command, not claimed as run.

## 1. Executive summary

| Class | Count | Attacks |
|---|---|---|
| **FALSE_PROVEN** (critical) | **3** | `forged_frame_filename` (NEW), `write_app_module` (NEW), `forge_events` (known A-1) |
| **SUPPRESSED_TRUE** (recall) | 3 | `subprocess_sink`, `os_open_dir_fd`, `ctypes_libc_open` |
| **VERDICT_CONFUSION** | 0 | — |
| **BLOCKED** (oracle held) | 1 | `symlink_recheck` (confirms the A-2 fix) |
| **NOT_TESTABLE_HERE** | 0 | the sandbox twin of `write_app_module` is provided as a driver (Docker) |
| **UNTESTED** | see §5 | ideas not run |

Two **new** false-proven holes, both with the same root cause the review did not name: **provenance is a purely lexical, unauthenticated check** — a frame "is application code" iff `os.path.realpath(co_filename)` lands under `app_root` and is not under the test dir, and the "entry point" is just a string match on `co_qualname`/`co_name`. A hostile test controls both. It needs neither the events file (A-1) nor a symlink (A-2).

The most dangerous one, `forged_frame_filename` combined with gating (`differential_bypass`), **survives the entire proof standard** (SPEC §4): baseline passes, the exploit fails on the vulnerable code with "valid" provenance, it is deterministic so it is stable across N runs, and it *passes* on the fixed code — so the loop's differential check is satisfied and a finding is reported against an app that is safe on both sides. The loop's differential is therefore **not** a backstop for this.

One-line most dangerous: *a test can fabricate a stack frame that looks like the app's declared entry point (crafted `co_filename` + name), read the canary from inside it, and gate the read on a source marker so the exploit passes on the "fixed" code — a fully `proven` verdict for a vulnerability that does not exist.*

## 2. Findings table (ranked by how plausibly an LLM-written test stumbles in by accident, highest first)

| # | Attack | PoC file | Result | Severity | Accidental-by-LLM? | Suggested fix (1–3 sentences) | Effort |
|---|---|---|---|---|---|---|---|
| 1 | Write a module into the app root and call it | `attack_write_app_module.py` (+ `sandbox_write_app_module_driver.py`) | FALSE_PROVEN | Critical | **Plausible** — an LLM may write a helper `.py` beside the app, or `/workspace`, as scaffolding | Record the set of application files that existed *before* the run (hash them) and count a frame as app code only if its file is one of them; equivalently, stage the app read-only and give the test a separate writable scratch dir that is never treated as app code. | M |
| 2 | Forge a frame via crafted `co_filename` + entry-point name | `attack_forged_frame_filename.py` | FALSE_PROVEN | Critical | Low (deliberate) | Do not trust `co_filename`: resolve each frame to a real, pre-existing app source file (reject frames whose `co_filename` is not a file that was present at stage time, or whose code object was produced by `compile`/`exec` at run time — e.g. check the file's content hash against what was staged). | M |
| 3 | Gated forgery that also passes on fixed code | `attack_differential_bypass.py` | FALSE_PROVEN (defeats differential) | Critical | Low (deliberate) | Same fix as #1/#2 removes it; additionally, the loop should not let the *same untrusted test* decide both the vulnerable-run failure and the fixed-run pass without the oracle re-validating provenance identically on both. | M |
| 4 | Forge the events file directly | `attack_forge_events.py` | FALSE_PROVEN | High | Low | **Known A-1.** Sign each event with an HMAC key that lives only in the orchestrator and is delivered to the plugin out of band (inherited fd/pipe opened before the test imports), not via env/file; or write events through a fd the test cannot open. | M–L |
| 5 | Vulnerable app reads via `os.open(..., dir_fd=…)` (openat) | `attack_os_open_dir_fd.py` | SUPPRESSED_TRUE | High (recall) | **Plausible** as a real app sink | In the audit hook, when `open` carries a `dir_fd`, resolve the path relative to that fd (`/proc/self/fd/<dfd>` join, or `os.readlink`), not the cwd, before comparing to the canary. | S–M |
| 6 | Vulnerable app reads via subprocess (`cat`) | `attack_subprocess_sink.py` | SUPPRESSED_TRUE | Medium (recall) | Plausible | Partly the declared "only observes `open()`" limit, but concrete: also audit `subprocess.Popen`/`os.exec*` and inspect argv for the canary path, or mark any child-process spawn during a canary-adjacent test as unobservable (invalid, not proven). | M |
| 7 | Vulnerable app reads via `ctypes` libc `open` | `attack_ctypes_libc_open.py` | SUPPRESSED_TRUE | Low (recall) | Low | Declared limit (non-Python read path). Document; optionally audit `ctypes.CDLL`/`ctypes` calls to flag the run as unobservable rather than silently "not proven". | S (doc) / L (fix) |
| 8 | Planted-symlink cheat (A-2 regression check) | `attack_symlink_recheck.py` | BLOCKED ✅ | — | — | None — confirms the A-2 defense still holds. | — |

## 3. Detail — every FALSE_PROVEN and SUPPRESSED_TRUE (exact PoC output)

### 3.1 FALSE_PROVEN · `write_app_module` (NEW, highest-ranked)

A lexically safe app (`realpath` + `commonpath` confinement) that is **never called**. The test writes `handler_shim.py` into the app root, imports it, and calls `handle_request()` which opens the canary.

```
=== write_app_module ===
  app_is_safe   : True
  test_outcome  : failed
  observed_effect: True
  provenance_ok : True
  reason        : canary read by application code reached through an entry point; test failed
  events        : 1
    via_symlink=False stack=... -> pytest_pyfunc_call -> test_write_module_into_app_root -> handle_request
  >>> RESULT    : FALSE_PROVEN
```

Why it works: `_provenance_problem` accepts the read because `handler_shim.py` is `_under(app_root)` and not under the test dir, its function is the declared entry point `handle_request`, and the test frame sits above it. Nothing checks that the file was part of the app before the run. **In the product this is worse, not better:** `SandboxRunner` mounts the app clone at `/workspace` read-write (`src/exhibit_a/sandbox/runner.py`: `-v {workspace}:/workspace:rw`) and runs the exploit from `/workspace/<oracle_dir>/`, so the exploit can create `/workspace/handler_shim.py` at run time — exactly this condition. Sandbox confirmation (Docker required), from the repo root:

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python spikes/redteam/sandbox_write_app_module_driver.py
```

### 3.2 FALSE_PROVEN · `forged_frame_filename` (NEW)

Same safe app, never called. The test `compile`s a function with `co_filename` pointing at the app module's real path (`app.__file__`, discovered on `PYTHONPATH`) and name `handle_request`, then opens the canary inside it.

```
=== forged_frame_filename ===
  app_is_safe   : True
  test_outcome  : failed
  observed_effect: True
  provenance_ok : True
  reason        : canary read by application code reached through an entry point; test failed
  events        : 1
    via_symlink=False stack=... -> pytest_pyfunc_call -> test_forged_provenance -> handle_request
  >>> RESULT    : FALSE_PROVEN
```

The `co_filename` need not even exist; `os.path.realpath` does not require it, so any string under the app root is accepted. Provenance is decided entirely by attacker-controlled frame metadata.

### 3.3 FALSE_PROVEN · `differential_bypass` (NEW — defeats proof step 5)

Shows the forgery is not stopped by the loop's "exploit must pass on the fixed code" step. The exploit reads the app source and only forges+fails when the vulnerable marker (`commonprefix`) is present; otherwise it returns (passes). Both apps are lexically safe.

```
=== differential_bypass [vulnerable-marked] ===
  reason        : canary read by application code reached through an entry point; test failed
  >>> RESULT    : FALSE_PROVEN
  [fixed-marked] test_outcome=passed observed_effect=False provenance_ok=False
  fixed-code exploit passes (differential satisfied): True
  >>> COMBINED  : DIFFERENTIAL_DEFEATED
```

Consequence against the full SPEC §4 proof standard: (1) baseline passes — unaffected; (2) exploit fails on vulnerable code + effect observed — yes (forged); (3) provenance — "holds" (forged); (4) stable across N=3 — yes, deterministic; (5) passes on fixed + baseline still passes — yes (gated). A `proven` finding would be emitted for an app that is safe either way. *End-to-end loop emission is UNTESTED here (needs replay/model plumbing), but each required branch is demonstrated above at the oracle layer the loop depends on.*

### 3.4 FALSE_PROVEN · `forge_events` (KNOWN — declared limit A-1, still open)

Included only to confirm the declared limit reproduces unchanged. The test appends a fully-formed event (app stack through the entry point, using its real `__file__` for the test frame) to `EXHIBIT_A_EVENTS` and `assert False`.

```
=== forge_events ===
  test_outcome  : failed
  observed_effect: True
  provenance_ok : True
  reason        : canary read by application code reached through an entry point; test failed
  >>> RESULT    : FALSE_PROVEN
```

Note: an earlier attempt that named the test frame with a *literal* path was correctly rejected ("the entry point was not called from the test") — the forgery must use the real test-file path, which the test knows via `__file__`.

### 3.5 SUPPRESSED_TRUE · `os_open_dir_fd` (recall; a *mishandled* open, not just an exotic read path)

A genuinely vulnerable app reads the canary with `os.open(name, O_RDONLY, dir_fd=outside_fd)`. `os.open` *does* raise the `open` audit event, but with the **relative** name; the plugin does `os.path.realpath(requested)` against the cwd, so it never matches the canary and writes no event.

```
=== os_open_dir_fd ===
  test_outcome  : failed
  observed_effect: False
  provenance_ok : False
  reason        : test failed but the canary was never read: it failed for the wrong reason
  >>> RESULT    : SUPPRESSED_TRUE
```

This is more than the blanket "only observes `open()`" limit: the hook *sees* the open and discards it because it resolves the path wrongly when `dir_fd` is present.

### 3.6 SUPPRESSED_TRUE · `subprocess_sink` (recall)

Vulnerable app shells out to `cat path`. The child has no audit hook; the parent never opens the file.

```
=== subprocess_sink ===
  test_outcome  : failed
  observed_effect: False
  reason        : test failed but the canary was never read: it failed for the wrong reason
  >>> RESULT    : SUPPRESSED_TRUE
```

### 3.7 SUPPRESSED_TRUE · `ctypes_libc_open` (recall)

Vulnerable app opens the canary through libc via `ctypes`, bypassing CPython's `open` audit event entirely. Same "wrong reason" suppression. Covered by the declared non-Python-read-path limit; listed because it is concrete and runnable.

## 4. BLOCKED (oracle held)

`symlink_recheck` — the A-2 planted-symlink cheat is correctly rejected (`via_symlink=True`, "canary reached through a symlink created during the run"). The A-2 fix still holds.

## 5. UNTESTED ideas (not run — listed honestly)

- **uvloop / `call_soon` origin loss** (recall): declared limit; would need uvloop installed and a real async sink driven by `call_soon`. Not installed here.
- **`multiprocessing` fork / `ProcessPoolExecutor`** (recall): the child process has no hook; expected SUPPRESSED_TRUE, same family as `subprocess_sink`. Not run.
- **`os.sendfile` / `mmap` of a pre-opened fd** (recall): if the canary fd is obtained once via a path that is audited, the event still fires; the pure-fd read paths are a narrower recall gap. Not isolated into a PoC.
- **Writing to the plugin module file**: in the sandbox the plugin is mounted `:ro` (`sandbox/runner.py`); on the host `run_oracle` loads it from the installed package, not writable by the staged test. Expected not exploitable from the test; not probed.
- **`sys.addaudithook` removal / disabling the hook mid-run**: audit hooks cannot be removed once added (CPython has no API). The test could stop *calling* audited opens (that is the recall class above) but not un-register the hook. Not separately demonstrated.
- **End-to-end loop emission of the gated forgery** through `VerificationLoop` with real recordings: the logic is shown at the oracle layer (§3.3); wiring a full replay was out of scope for a report-only spike.

## 6. Recommendation — fix before the demo vs. document as a limit

**Must fix before the demo (or the "proof" claim is unsafe):**
- **Findings #1/#2/#3 (provenance forgery).** This is a *false positive* path — the product's whole thesis is "report only what we can prove," and these produce a `proven` verdict for a safe app, surviving the differential. Minimum viable fix: treat as application code only files that were present in the staged app before the run (content-hash the staged tree; reject run-time-created files and `compile`/`exec` frames). This closes #1 and #2, and #3 falls with them.

**Fix if time, else document prominently as a limit:**
- **#5 `dir_fd` open** — small, high-value: resolve the audited path relative to `dir_fd`. It is a real recall bug in code the oracle already runs, not an out-of-scope read path.
- **#4 forged events (A-1)** — already a declared limit; the HMAC/out-of-band-fd fix is M–L. If not fixed, keep it loudly documented (it is today).

**Document as accepted limits (recall / false-negative only, never false-positive):**
- #6 subprocess, #7 ctypes, and the untested uvloop/`call_soon`/multiprocessing/fd-read paths. These can only *miss* a true vulnerability (hurting recall), never invent one — consistent with "green = nothing could be proven, not safe." Say so explicitly in the demo.

Bottom line: the recall gaps are tolerable for a demo if named; the **three forgery findings are not** — they turn the engine's core promise (no finding without proof) false, and should be closed or, failing that, called out before any `proven` result is presented as trustworthy.
