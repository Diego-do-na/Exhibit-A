# Oracle provenance (A-1p): admitting only staged application code

**Status:** implemented on branch `a1-provenance`. **Author:** claude-cloud. **Date:** 2026-10-29.
**Builds on:** `docs/oracle-a1.md` (signed events, key on stdin), `docs/oracle-redteam.md`
(the attacks), `docs/oracle-observer-spike.md` (out-of-process observers).

Exhibit A reports a vulnerability only when it can prove it (SPEC §4). For a path traversal
the oracle's proof is "the canary was read, and the read came from application code reached
through a declared entry point, called by the test". The sandbox that runs the test is
isolated and resource-limited; it is not "100% safe", and neither is this oracle. A green
result still means "nothing could be proven", never "safe".

## 1. The problem

Before this change, provenance was lexical and unauthenticated. A stack frame counted as
application code if `realpath(co_filename)` lay under the app root and outside the test's
directory, and the entry point was a string match on `co_qualname`/`co_name`. The exploit
test controls both. The red team (`docs/oracle-redteam.md` §3.1–3.3) turned that into
`proven` verdicts for a safe app in two ways:

- **(a) write a module into the app root.** In the sandbox `/workspace` is mounted
  read-write, so the test can create `/workspace/handler_shim.py`, import it, and call a
  function named like the entry point.
- **(b) forge a frame.** `compile(src, app.__file__, "exec")` builds a code object whose
  `co_filename` is a real app file and whose name is the entry point.

Gated on a marker in the app source, (b) also survives the differential check (proof step 5),
because the exploit passes on the fixed code.

There was also a recall bug. `os.open(name, ..., dir_fd=fd)` raises the `open` audit event
with the relative `name` only. The hook resolved that against the cwd, so a real canary read
through a directory descriptor was dropped (`spikes/redteam/attack_os_open_dir_fd.py`).

## 2. Threat model

**Attacker.** The author of the exploit test, which is model output and therefore
untrusted. It may be accidental: a model writes a helper module beside the app. It may also
be deliberate: a prompt-injected or adversarial model.

**What the attacker controls.** All Python in the test process: the test file, a
`conftest.py` beside it, and everything they import or execute. They share the process with
the oracle plugin. In the sandbox they can write to `/workspace` (the app copy), to `/tmp`,
and to the events file. On the host path (`run_oracle`) they can write to the app root
itself. They know the app's source and the canary's location.

**What the attacker does not control.** The orchestrator, which runs on the host outside the
container. Concretely: the key and manifest generation, the staged copy kept on the host
(`SandboxRunner`'s stage is copied into the container's workspace and is never mounted), the
judge, and the post-run rehash.

**Goal we defend.** No `proven` verdict for a read that the application's own, unmodified
code did not perform when reached through an entry point. The secondary goal is not to
miss real reads (recall), but recall gaps are tolerated and declared.

**Out of scope.** The repository under analysis is the target, not the attacker. Code it
ships (including a `sitecustomize.py`) is trusted as "the app". See R2 for why that matters
on the host path.

## 3. Design

```
host (orchestrator)                                  test process (sandbox)
-------------------                                  ----------------------
stage app copy (test dir excluded)
manifest = {rel path: sha256 | "dir" | "symlink:t" | "special"}
key = 32 random bytes
stdin: "EXHIBIT-A-KEY <hex>\n"
       "EXHIBIT-A-MANIFEST {"root":..,"files":..}\n" ─▶ plugin reads fd 0 at import
                                                       (before collection, before capture)
                                                     audit hook on "open"; os.open wrapped
                                                     canary read ─▶ for each frame under root:
                                                       admitted? (manifest, digest, ast, code ==)
                                                     signed event {stack: [.. line, admitted ..]}
container exits
rehash workspace ─▶ app_tree_changes
verify signatures ─▶ forged count
judge: frames count as app code only if admitted
       AND host re-check on the stage copy passes
```

### 3.1 Layer 1: staged-app manifest on the authenticated channel

- `provenance.app_manifest(root, exclude)` walks the staged tree without following symlinks.
  It maps every entry to its sha256 (regular files), `"dir"`, `"symlink:<target>"` or
  `"special"`. The test's directory is excluded (`staging_exclude`): the exploit and its
  conftest are test code. The walk is bounded at 200,000 entries and 4 GiB. Beyond that the
  tree cannot be verified: host path `error` (`manifest_failed`), sandbox path
  `env_failure`.
- The manifest is computed before any test code runs: by `SandboxRunner.run_exploit` on the
  host stage, and again by `sandbox.run` on its workspace copy. The two must be equal, or the
  run is an `env_failure`. On the host path `run_oracle` computes it.
- **Channel v2 (backward compatible).** The stdin message is the v1 key line, followed by an
  optional second line `EXHIBIT-A-MANIFEST <ASCII JSON>\n`. `plugin.parse_channel` accepts:
  - v1 (key only): the key is used and there is no manifest. No frame can then be admitted,
    so nothing proves under authenticated provenance.
  - v2: key and manifest.

  Anything else fails closed, with no key, so the run cannot prove anything. That includes
  a third line, a malformed manifest, a relative root, or non-string values. The stdin read
  is bounded at 64 MiB. The manifest is integrity data, not a secret: it travels with the key
  so the test cannot alter it, never through the environment or a file in the writable tree.
- Tests: `tests/test_oracle_provenance.py` (`test_v1_*`, `test_v2_*`, `test_malformed_*`,
  manifest and diff tests), `tests/test_sandbox_fake_docker.py`.

### 3.2 Layer 2: frame admission

When the canary is read, the plugin annotates every frame whose real file lies under the app
root with `line` (`co_firstlineno`), `admitted`, and, when rejected, `admission` (why). A
frame is admitted only if all of these hold:

1. **In the manifest.** Its path relative to the root is a regular-file entry. This defeats
   (a): a module written at run time is not there.
2. **Unchanged.** The file's current sha256 equals the manifest digest. The file is read
   at the moment of the canary read, not from a cache keyed by path.
3. **Declared by the staged source.** `ast` of that verified content has a function, class,
   lambda or comprehension with the frame's `co_qualname` starting at its `co_firstlineno`.
   `plugin.code_keys` follows CPython's rules: the first line is the first decorator's
   line; defaults and decorators run in the enclosing scope; it lists both namings for
   3.12+ inlined comprehensions (PEP 709). This defeats (b) in its plain form: the forged
   `handle_request` at line 1 does not exist in the staged source.
4. **Same code object.** The frame's code object `==` the code object of the same
   qualname and line in `compile(verified content, dont_inherit=True)`. CPython compares
   bytecode, constants, names and line table this way, but not the file name. This defeats
   a forgery padded to the right qualname and line, and the modify-import-restore attack:
   the test edits `app.py`, imports the edited copy, then writes the original back. At the
   read the file digest matches again, but the code that ran does not.

A frame under the root that fails any check is **never** application code. The plugin binds
`os.open`, `os.read`, `hashlib.sha256` and `compile` when it installs, before the test runs,
so later rebinding of those names does not change admission. That is a tripwire, not a
boundary (R1).

**Host re-check.** The judge (`provenance.AppTree.check`) accepts an admitted frame only if
the host agrees with checks 1–3, using its own copy of the staged source. On the sandbox path
that copy is the stage, which is never mounted. On the host path it is the app root, which
the tamper check (§3.3) vouches for. The host cannot repeat check 4: it has no code object.
So a plugin that was fooled, or an event signed by a test that stole the key, can claim
admission only for a qualname/line that really exists in the staged source. It cannot
claim admission for a made-up one (`test_host_rejects_an_admitted_frame_*`,
`test_run_exploit_rechecks_admitted_frames_against_the_host_stage`).

**Recall costs (declared).** These frames are no longer application code:

- code generated at run time from app files, such as template engines that compile
  templates under the template's path;
- PEP 695 generic-parameter scopes (`code_keys` does not list them; 7 of 7,726 code objects
  in the 3.13 stdlib);
- frames whose `.pyc` does not match their source.

A frame that fails admission only matters if it was the outermost app frame, normally the
entry point.

### 3.3 Layer 3: app-tree-changed check

After the run the tree is hashed again (`tree_changes`). `sandbox.run` rehashes the
workspace after the container exits; `run_oracle` rehashes the app root. Every added,
removed or modified entry is listed in `Judgement.app_tree_changes` (`"added: p"`,
`"removed: p"`, `"modified: p"`). A tree that cannot be hashed is listed as
`"unverifiable: ..."`. Any entry:

- sets `reason_code = "app_tree_changed"`, and the reason starts with `app_tree_changed:`;
- sets `provenance_ok = False`, so the verdict can never be `proven`;
- turns a **passing** run into `test_outcome = "error"`. The loop then classifies it as
  `invalid_test`, not `discarded_unproven`, and it cannot satisfy the "exploit passes on the
  fixed code" step of the differential. The same applies to a passing run with forged event
  lines.

This follows the `forged_events` pattern: a count or list on `Judgement`, checked before
provenance, never proven. **Recall cost (declared):** an app that legitimately writes into its
own tree during the exploit (logs, uploads, a SQLite file) can no longer be proven.

### 3.4 Layer 4: test tripwire (`oracle/guard.py`)

`channel_problem` now also applies the application-tree rules after the channel rules. It
still uses `ast` only and never executes the test. A hit returns `error` (`invalid_test`) with
"test tampers with the application tree: <file> matches rule '<name>'" and
`reason_code = "channel_tripwire"`. The tables at the top of the rules section are the whole
configuration:

| rule | kind | looks for |
|---|---|---|
| `code_object_rewrite` / `_qualname` / `_firstlineno` | pattern | `co_filename`, `co_qualname`, `co_firstlineno` |
| `code_type` | pattern | `CodeType` |
| `sitecustomize` / `usercustomize` / `pth_file` | pattern | start-up files (strings, names, imports; `.pth` suffix) |
| `app_tree_write` | flow | open/`io.open` in a write mode, `os.open` with write flags, `Path.write_*`/`touch`/`mkdir`/`symlink_to`/..., `os.*` and `shutil.*` writers, applied to a name derived from an app path (`module.__file__`, `__path__`, `__spec__`, `sys.path`, `getcwd()`/`Path.cwd()`, `inspect.getsourcefile`, `"/workspace..."`) or to a relative literal (the cwd is the app root on both paths); helpers called with such a name are followed |
| `compile_app_filename` | flow | `compile(src, <app path>, ...)` |
| `app_source_forge` | flow | a read of app source (`open(app path)`, `read_text`, `inspect.getsource`, `linecache`) in a module that also calls `compile`/`exec`/`eval` or names `CodeType`/`FunctionType` |
| `module_monkeypatch` | flow | assignment to an attribute of an imported module, `setattr`/`delattr` on one, `monkeypatch.setattr`, `mock.patch` |

Honest patterns stay allowed and are tested (`TREE_ALLOWED`): `re.compile`, passing the app
directory to the app, writing under `EXHIBIT_A_ALLOWED_DIR` or the test's own directory,
reading app source without building code, `str.replace` on an app path, and setting
attributes on an instance. Every shipped exploit fixture passes the guard. The taint pass
ignores scopes on purpose: it over-approximates. Like the channel rules, this is a tripwire,
not a boundary. Computed names (`getattr(os, "pa" + "th")`) evade it. That is why layers 2
and 3 are tested with the guard switched off (`unguarded` fixture,
`spikes/redteam/run_all.py` "guard off" column).

### 3.5 Layer 5: `dir_fd` resolution

At install the plugin wraps `os.open`. The wrapper records the call's `dir_fd` in a
thread-local for the duration of the real call (the audit hook runs inside it, on the same
thread). For every directory it opens, it registers `fd -> (st_dev, st_ino, path as
requested, made absolute)`. With a relative name and a `dir_fd`, the hook resolves:

- through `os.readlink("/proc/self/fd/<dir_fd>")` and then `realpath`;
- where `/proc` is missing (macOS host path), by identity instead: `os.stat(name,
  dir_fd=...)` compared to the canary's `(st_dev, st_ino)`. This is used only while the
  canary has a single link, so a hard link cannot be mistaken for it.

The A-2 symlink walk runs on the path the directory was *requested* by, from the registry, so
a directory symlink planted by the test is still flagged. If the descriptor was not opened
through the wrapper, or the number was reused for another directory (identity mismatch), the
origin is unknown. The event is then flagged `via_symlink` with `<unverified: dir_fd of
unknown origin>`, which fails closed. Tests: `test_dir_fd_*`, `test_relative_open_*`,
`test_resolve_falls_back_to_identity_without_proc`, `test_dir_fd_origin_*`.

### 3.6 Wiring and verdicts (`loop/runner.py`)

`SandboxRunner.run_exploit` now does the following:

1. runs `guard.channel_problem` before staging. A hit is an `error` judgement
   (`invalid_test`), and the sandbox is never started;
2. hashes the stage, passes the manifest to `sandbox.run`, and keeps the stage for the host
   re-check;
3. calls `_judge` with `forged_events`/`forged_reason` (from `oracle_forged_events`),
   `app_tree_changes`, and `AppTree("/workspace", stage, manifest)`;
4. still raises `OSError` (`env_failure`) when the sandbox cannot run. That now includes a
   workspace that does not hash to the stage manifest, or a stage that cannot be hashed.

No new top-level verdict was added. Tampering is the test cheating or misbehaving, which the
existing taxonomy already calls `invalid_test`. An environment that cannot be verified is
`env_failure`. `Judgement.reason_code` (`channel_tripwire`, `forged_events`,
`app_tree_changed`, `frame_not_admitted`, `provenance`, `no_effect`, `manifest_failed`) says
which, without parsing the reason text.

## 4. What each layer defends

| attack | L1 manifest | L2 admission | L3 tree check | L4 tripwire | L5 dir_fd |
|---|---|---|---|---|---|
| (a) module written into the app root | provides the "before" | rejects (not in manifest) | rejects (added) | flags `app_tree_write` | — |
| (b) frame compiled under an app file name | — | rejects (ast qualname/line) | — | flags `compile_app_filename` | — |
| (b') same, padded to the real qualname and line | — | rejects (code object) | — | flags `code_object_firstlineno` | — |
| modify, import, restore | — | rejects (code object) | — (restored) | flags `app_tree_write` | — |
| gated forgery vs. differential | — | rejects on the vulnerable run | — | flags | — |
| passing run that tampered | — | — | `error`, cannot satisfy the fixed-code re-run | — | — |
| real read via `os.open(dir_fd=)` | — | — | — | — | now observed |
| planted dir symlink used as `dir_fd` | — | — | — | — | flagged `via_symlink` |

## 5. Red-team results, before and after

`python3 spikes/redteam/run_all.py` (host path, `run_oracle`, run in this session).
"Before" is `main` at `896f298` (A-1 signed events and A-2 symlink flag already in). The four
PoCs added in this change were run against that tree's `src/` in a temporary worktree.

| PoC | app | before | after, guard on | after, guard off | stopped by |
|---|---|---|---|---|---|
| `attack_forged_frame_filename` | safe | **FALSE_PROVEN** | BLOCKED | BLOCKED | L4; L2 (ast qualname/line) |
| `attack_forged_frame_same_line` (new) | safe | **FALSE_PROVEN** | BLOCKED | BLOCKED | L4; L2 (code object) |
| `attack_write_app_module` | safe | **FALSE_PROVEN** | BLOCKED | BLOCKED | L4; L3 (`added: handler_shim.py`) and L2 |
| `attack_modify_import_restore` (new) | safe | **FALSE_PROVEN** | BLOCKED | BLOCKED | L4; L2 (code object) |
| `attack_differential_bypass` | safe | **FALSE_PROVEN**, differential defeated | BLOCKED | BLOCKED | L4; L2 on the vulnerable-marked run |
| `attack_forge_events` | safe | BLOCKED | BLOCKED | BLOCKED | A-1 (channel guard; events path not in env; signatures) |
| `attack_key_introspection` (new, R1) | safe | BLOCKED, by accident¹ | **FALSE_PROVEN** | **FALSE_PROVEN** | not stopped (R1) |
| `attack_dependency_monkeypatch` (new, R5) | safe | **FALSE_PROVEN** | **FALSE_PROVEN** | **FALSE_PROVEN** | not stopped (R5) |
| `attack_subprocess_sink` | vulnerable | SUPPRESSED_TRUE | SUPPRESSED_TRUE | SUPPRESSED_TRUE | not observed (R3) |
| `attack_os_open_dir_fd` | vulnerable | SUPPRESSED_TRUE | **DETECTED** | **DETECTED** | L5 |
| `attack_ctypes_libc_open` | vulnerable | SUPPRESSED_TRUE | SUPPRESSED_TRUE | SUPPRESSED_TRUE | not observed (R4) |
| `attack_symlink_recheck` | safe | BLOCKED | BLOCKED | BLOCKED | A-2 |

¹ On `main` the forged body was dropped only because it carried the new `line`/`admitted`
fields, which the old schema rejects. With the old frame shape the same key theft forges a
proof. `docs/oracle-a1.md` declared this limit; R1 now pins it with a test.

The sandbox twin of `attack_write_app_module`
(`spikes/redteam/sandbox_write_app_module_driver.py`) needs Docker and was **not run** here.
The expected result is BLOCKED twice: `channel_tripwire` with the guard on, and
`app_tree_changed` with it off. The fake-docker tests exercise the same sandbox code path
without a container.

## 6. What is proven by tests, what is only designed

Proven by tests that ran in this session (no Docker):

- channel v2 parsing and fail-closed cases;
- manifest and diff;
- `code_keys` against the compiler on the fixture apps;
- admission of genuine frames (including a decorated view) on the real host path;
- rejection of each forgery shape and of modify-import-restore;
- tamper reason codes, and passing+tampered becoming `error`;
- the host re-check;
- the `dir_fd`, relative, planted-symlink and pre-existing-symlink cases;
- every tripwire rule, plus allowed patterns and all shipped fixtures;
- `sandbox.run` and `SandboxRunner.run_exploit` end to end through a fake `docker` callable:
  stdin bytes, colliding env names, the key never in argv or env, forged count, workspace
  tamper, manifest mismatch, guard before staging.

Only designed, not run here:

- the real container path. The plugin inside the image, the `/workspace` rehash after a real
  container, and Python-version agreement between the sandbox image and the host's `ast`
  are covered by the existing Docker tests listed in the task. They were NOT RUN.
- macOS: the `/proc`-less identity fallback is unit-tested by stubbing `os.readlink`, not on
  a Mac.

## 7. Residual limits

Each limit is pinned by a strict xfail in `tests/test_oracle_residual.py`
(`raises=AssertionError`, preconditions via `pytest.fail`). A fix shows up as XPASS and fails
the suite until this section is updated.

### 7.1 R1: in-process introspection of the plugin (FALSE_PROVEN)

The key, `seq`, events descriptor and admission object live in the audit hook's closure, in
the test's own process. A test can:

1. find the hook with `gc.get_objects()`, using computed names to slip past the tripwire;
2. read the key from the closure cells;
3. sign an event that claims admitted frames at the entry point's real qualname and line.

The host re-check passes because those are real. The same access allows patching the
admission object or reading `/proc/self/mem`. `test_r1_*` demonstrates it end to end; it was
only declared in `docs/oracle-a1.md`. Nothing in-process can close this.

### 7.2 R2: `sitecustomize` in the app tree (FALSE_PROVEN, host path)

On the host path the app root is on `PYTHONPATH`. A `sitecustomize.py` there runs at
interpreter start, before the plugin, and can capture the hook as it is installed
(`test_r2_*`). It was in the tree before the run, so it is in the manifest. The tamper check
does not see it, and the tripwire checks only the test.

In the product sandbox, `/workspace` is not on `sys.path` at start-up: `PYTHONPATH` is the
plugin directory only, and the conftest adds `/workspace` later. So this applies to
`run_oracle` (host child process), not to `SandboxRunner`. It also requires the app tree to
contain such a file. The repo can ship one, or, on the host path, an earlier run can plant
it: the host path stages nothing. That earlier run is itself flagged `app_tree_changed`.

`.pth` files are processed only in site directories, and the app root is not one
(`test_pth_file_in_the_app_root_is_not_processed_on_the_host_path`). The tripwire flags a
test that names either kind of file.

### 7.3 R3: subprocess reads (recall)

The hook lives in the Python process. A child process (`cat`) reading the canary is not seen
(`test_r3_*`), so the read is missed. This can never cause a false proof.

### 7.4 R4: ctypes / native reads (recall)

A libc `open` through `ctypes` raises no CPython audit event (`test_r4_*`). Same class as R3.

### 7.5 R5: dependency monkeypatching by computed names (FALSE_PROVEN)

The test replaces something the app calls, for example
`setattr(getattr(os, "pa" + "th"), "common" + "path", ...)`. The safe app's own, unmodified,
admitted entry point then reads the canary (`test_r5_*`). Provenance is genuine; the
vulnerability is not. `module_monkeypatch` catches the plain spellings only. The differential
re-run on fixed code helps only if the fix does not use the patched function, and a gated
test can defeat it as in `docs/oracle-redteam.md` §3.3. An out-of-process observer would not
close this either: the read really happens in app code.

### 7.6 Smaller limits

- `dir_fd` origin is tracked only for descriptors opened through `os.open`. A directory fd
  from `posix.open`, from before install, or a reused number pointing at the same directory
  opened through another path is either unknown (fail closed) or taken at its registered
  path.
- Hard links to the canary are still not observed (A-2 limit); identity matching is used only
  without `/proc` and only while the canary has one link.
- Admission compares code objects, not behaviour. Genuine app code run in a namespace whose
  globals the test replaced is admitted. That is R5 again.
- Frames from code generated from app files at run time, and PEP 695 scopes, are not admitted
  (§3.2). This is a recall cost.
- An app that writes into its own tree during the run cannot be proven (§3.3). This is a
  recall cost.

## 8. Why the ptrace/fanotify observer stays a deferred second signal

`docs/oracle-observer-spike.md` §1 separates *fact* (was the canary opened) from *provenance*
(by which code). A syscall observer outside the test process, such as host-side fanotify or a
ptrace parent, can make the fact unforgeable. Per spike §4 step 1 it would also close R3 and
R4 and catch suppression: if the hook claims a proof but fanotify saw no open, downgrade.

It cannot recover provenance. The spike's §5 names the residual false positive
(`cheat_read_then_forge`). Of what remains here:

- R1 is a provenance forgery that a fact signal does not stop;
- R5 is a genuine app read, which any observer would confirm.

So this change hardens provenance where it lives, in-process and authenticated against the
staged app. The observer stays the second signal the spike recommends (§4 steps 1–2). The
only mechanism that makes provenance itself unforgeable by an in-process test is
out-of-process CPython stack reconstruction (§4 step 4), and it stays on the post-freeze
roadmap. Neither is built here.

## 9. Commands

Host-path tests (no Docker), from the repo root:

```bash
PYTHONPATH=src python -m pytest -q tests/test_oracle.py tests/test_oracle_eval.py tests/test_oracle_provenance.py tests/test_oracle_residual.py tests/test_sandbox_fake_docker.py tests/test_loop.py
```

Red team:

```bash
python3 spikes/redteam/run_all.py
```

Docker tests, on a Mac with Colima running, from a worktree of this branch next to the main
checkout:

```bash
git -C ~/Desktop/Proyects/Exhibit-A worktree add ../Exhibit-A-a1p a1-provenance
```

```bash
cd ~/Desktop/Proyects/Exhibit-A-a1p && PYTHONPATH=src ../Exhibit-A/.venv/bin/python -m pytest tests/test_oracle.py tests/test_sandbox_events.py tests/test_oracle_eval.py
```

```bash
cd ~/Desktop/Proyects/Exhibit-A-a1p && PYTHONPATH=src ../Exhibit-A/.venv/bin/python -m pytest tests/test_loop.py tests/test_sandbox.py tests/test_sandbox_security.py tests/test_sandbox_limits.py tests/test_sandbox_image.py
```

```bash
cd ~/Desktop/Proyects/Exhibit-A-a1p && PYTHONPATH=src ../Exhibit-A/.venv/bin/python spikes/redteam/sandbox_write_app_module_driver.py
```
