# Oracle provenance (A-1p): admitting only staged application code

**Status:** implemented on branch `a1-provenance`. **Author:** claude-cloud. **Date:** 2026-10-29.
**Builds on:** `docs/oracle/oracle-a1.md` (signed events, key on stdin), `docs/security/oracle-redteam.md`
(the attacks), `docs/oracle/oracle-observer-spike.md` (out-of-process observers).

Exhibit A reports a vulnerability only when it can prove it (SPEC §4). For a path traversal
the oracle's proof is "the canary was read, and the read came from application code reached
through a declared entry point, called by the test". The sandbox that runs the test is
isolated and resource-limited; it is not "100% safe", and neither is this oracle. A green
result still means "nothing could be proven", never "safe".

## 1. The problem

Before this change, provenance was lexical and unauthenticated. A stack frame counted as
application code if `realpath(co_filename)` lay under the app root and outside the test's
directory, and the entry point was a string match on `co_qualname`/`co_name`. The exploit
test controls both. The red team (`docs/security/oracle-redteam.md` §3.1–3.3) turned that into
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
`app_tree_changed`, `frame_not_admitted`, `provenance`, `no_effect`, `manifest_failed`,
`canary_not_via_allowed_dir`) says which, without parsing the reason text.

`SandboxRunner` also passes the container's allowed directory (`/tmp/exhibit_a_oracle/allowed`)
to `_judge`, so the route check of §3.7 applies on both paths. It does not yet pass
`canary_written` (§3.7): the write effect is not wired through the sandbox (T076).

### 3.7 Layer 6: the canary's route and access (A-11 F2, F4, F5)

The integration audit (`docs/security/audit-integration.md` §2.1) found that a test could choose where
the app is rooted. Rooting a correctly confined app at the canary's directory makes it read
(P1b) or write (P1) the canary through its real entry point. Gating that on the source hash
(P7) also passes on any fix. Separately, every `os.open` was recorded with mode `"None"` and
counted as a read (P3), a failed `open(..., "r+")` counted as a write (P6), and `os.open`
writes and `os.replace` onto the canary were missed (P2, P5).

**The test never learns the canary's path.** `EXHIBIT_A_CANARY` is no longer in the test
contract (`guard.TEST_CONTRACT`; it was never in the prompt text, `loop/prompts.py`). The
plugin pops it from `os.environ` after install, like `EXHIBIT_A_EVENTS`, and the tripwire's
`exhibit_a_env` rule now hits any mention of it. A real exploit reaches the canary from the
allowed directory: it sits at `../outside/canary.txt` beside it. All shipped exploits do so.

**Guard rule `canary_dir_to_call`** (`guard.CANARY_DIR_RULE`, reason "test chooses where the
app is rooted"). Paths derived from `EXHIBIT_A_ALLOWED_DIR` are evaluated symbolically:
`os.path.join`/`dirname`/`abspath`/`realpath`, `Path(...)`, `.parent`, `.parents[i]`, `/`,
string `+` and f-strings, with constant strings folded. A value that is the canary's directory
or one of its ancestors is a hit when it is passed to any call other than path arithmetic and
read-only queries (`os.path.exists`, `os.listdir`, `os.symlink`'s target, ...), including
inside a literal list/tuple/dict or a `*`/`**` argument, and when it is assigned to an
attribute or subscript. `os.chdir(outside)` is a hit. The Starlette CVE exploit's served
directory, `<work>/out`, is a sibling that does not hold the canary, and is not a hit.

**Route check, at run time** (`oracle._route_problem`). The plugin records `requested`: the
path as the code asked for it, made absolute, not resolved. When the caller passes the allowed
directory (`run_oracle` and `SandboxRunner` do), an event counts only if `requested`:

- starts with `<allowed>/` lexically (a traversal starts inside and escapes, e.g.
  `<allowed>/../outside/canary.txt`), or
- is exactly the canary's real path. Apps that canonicalise before opening (Starlette's
  `realpath`) and absolute archive members (`os.path.join(dest, "/abs")`) request this.

Anything else fails closed with `reason_code = "canary_not_via_allowed_dir"`. That covers an
app rooted at the canary's directory under another spelling (`<work>/outside/./canary.txt`),
an unrecorded `requested` (older plugin, or a `dir_fd` of unknown origin), and a path longer
than 4096 characters. An app rooted *exactly* at the canary's directory that canonicalises
also requests the canary's own path, so at run time it looks the same as the two legitimate
shapes above. Only the guard tells them apart, and an obfuscated root evades it: residual
limit R6 (§7.6).

**Access from the open flags** (`plugin.access_of`). The `open` audit event carries the OS
flags for both `builtins.open` and `os.open`. The plugin records `flags` and classifies them on
the platform it runs on: `O_RDONLY` is `read`, `O_WRONLY` is `write`, `O_RDWR` is `read_write`,
and `O_CREAT`/`O_TRUNC`/`O_APPEND` add `write`; `O_PATH` and non-integers are `unknown`. Mode
`"r+"` is `read_write`. Classifying in the plugin matters because the judge may run on another
OS (a Linux container judged on macOS) where the flag values differ. A read effect needs `read`
in the access; a write effect needs `write`. An event body without `flags` (older plugins) is
`unknown` and proves neither effect. The signed channel format is unchanged: the body only
gains fields (`op`, `flags`, `access`, `requested`).

**Renames and links.** `os.rename`, `os.replace` (which raises the `os.rename` audit event) and
`os.link` whose destination resolves to the canary are recorded with `op` `rename` or `link`
and access `write`.

**Write verified after the run.** For `canary_write`, `run_oracle` checks on the host, after the
test, that the canary is a regular file (not a symlink), that it was absent before (it is never
planted for this effect), and that it holds `EXHIBIT_A_CANARY_TOKEN`
(`oracle.canary_written`). If not, nothing is proven (`no_effect`). This is what refuses P6, a
failed `"r+"` open. Hook for the sandbox: `_judge(..., canary_written=...)`. `None` means "not
checked", and the sandbox path does not check yet; T076 must read the container's `outside`
directory and pass the result.

Audit results with this layer (`tests/test_oracle.py`, `tests/test_oracle_eval_archive.py`):

| PoC | app | effect | before | now |
|---|---|---|---|---|
| P1 dest = canary dir (plain, and derived from the allowed dir) | safe | write | proven | not proven: guard |
| P1b base = canary dir (plain, and derived) | safe | read | proven | not proven: guard |
| P7 gated on the source hash | safe | write | proven | not proven: guard |
| P1/P1b/P7 plain, guard off | safe | both | proven | not proven: `KeyError`, the variable is gone |
| root `<work>/outside/.` past the guard | safe | read | proven | not proven: `canary_not_via_allowed_dir` |
| P2 `os.open` write | vulnerable | write | missed | proven |
| P3 write-only `os.open` | no leak | read | proven | not proven: access `write` |
| P4 `"r+"` read | vulnerable | read | missed | proven |
| P5 `os.replace` onto the canary | vulnerable | write | missed | proven |
| P6 failed `"r+"` on the absent canary | no write | write | proven | not proven: nothing written |

### 3.8 Layer 7: links to the canary created during the run (2026-10-30)

Found by the first compact Meta run of the negative control (`starlette-cve-2023-29159-fixed`,
`docs/bench/meta-run.md`): the model's test ran a thread that replaced a served file with a symlink to
the canary and back, in a loop, while it requested that file through `StaticFiles`. The A-2
walk (`_fresh_symlink`) runs a moment after the hook has resolved the opened path to the canary,
so it could find the regular file again and vouch for the read. The fixed Starlette tree ended
`proven`: a false proof on code that is not vulnerable to the attack the test claimed.

The plugin now also watches the `os.symlink` and `os.link` audit events (any thread). Once the
process creates a symlink whose target, taken lexically against the link's directory or
resolved through existing links, is the canary or any directory above it, or a hard link whose
source is the canary, every later canary access is flagged `via_symlink` with
`<link to the canary created during the run: ...>`, whatever the opened path looks like when it
is checked. The flag is set when the audit event is raised, before the link exists, so no
timing can beat it. It fails closed: an unresolvable `dir_fd` or an error counts as a link.

Cost in recall: a test that creates such a link forfeits the proof even when the application's
own traversal is real, and so does an application whose own code creates a link to the canary
(for example an archive extractor honouring symlink members). Both only turn proofs into
non-proofs. A hard link alone was not a false proof before either: the read is not recognised as
the canary (section 3.5). Tests: `test_a_link_to_the_canary_created_by_the_test_forfeits_the_proof`,
`test_a_hard_link_to_the_canary_is_never_a_proof`, `test_an_unrelated_symlink_does_not_taint_a_real_traversal`,
and the replay of the recorded run, `test_replaying_the_negative_control_proves_nothing`.

### 3.9 Layer 8: the `canary_exec` effect (T085)

A third family of effect, code or command execution: shell injection, unsafe deserialization,
`eval` of input. The read and write effects observe the application touching a file. This one
observes the application running a program, so it needs a fact from outside the Python process
as well as the stack inside it.

**The canary.** `<work>/outside/canary` is a tiny `/bin/sh` script, read-only and executable, that
appends the run's token to `<work>/outside/canary_ran` using shell builtins only. The marker does
not exist before the run. The test still gets only `EXHIBIT_A_ALLOWED_DIR` and
`EXHIBIT_A_CANARY_TOKEN`, and reaches both files from the allowed directory, as for the other effects.
`EXHIBIT_A_CANARY_MARKER` tells the plugin the marker's path and turns the observation on; it is
popped after install like `EXHIBIT_A_CANARY`, and the guard refuses a test that mentions it.

**What the plugin records** (signed, same channel; only in this effect), each with the logical stack:

| `op` | audit event | also records |
|---|---|---|
| `process` | `subprocess.Popen`, `os.system`, `os.exec`, `os.posix_spawn`, `os.spawn`, `os.fork`, `os.forkpty`, `pty.spawn`, and a wrapper's event for a direct `_posixsubprocess.fork_exec` call | `command`, `names_canary`, `sink_named`, `patched` |
| `native` | `ctypes.dlsym`, `ctypes.dlsym/handle`, `ctypes.call_function` | the symbol |
| `env` | `os.putenv`/`os.unsetenv` of `PATH`, `IFS`, `ENV`, `BASH_ENV`, `CDPATH`, `SHELL`, `GLOBIGNORE`, `LD_*`, `DYLD_*`, `PYTHON*`, `BASH_FUNC_*` | the name |
| `chdir` | `os.chdir` (also raised by `os.fchdir`) | |
| `codegen` | `compile`, unless called from the import system, the stdlib or a dependency | |
| `open`/`rename`/`link`, `target` `marker` | as in layer 6, for the marker; a rename of `outside/` or a directory above it counts too | |

- `names_canary`: a word of the command resolves to the canary. Shell text is split on whitespace
  and punctuation, not parsed. A relative word counts if it resolves from the working directory or
  ends in `outside/canary` (the shell may `cd` first).
- `sink_named`: the code object of the innermost staged-app frame names a sink (`run`, `Popen`,
  `system`, `loads`, `load`, `eval`, ...). A frame that only calls a method of its input,
  `stream.read()`, did not ask for a process, whatever the input does.
- `patched`: the first watched API (`subprocess`, `os`, `shlex`, `pickle`, `builtins`) or sensitive
  environment variable that is no longer what it was at install when the process started.

A forked child inherits the hook. Its events share the sequence counter (anonymous shared memory)
and a pipe-based mutex with its parent, so a fork followed by `os.exec` is recorded without
tripping the replay check of `verify_lines`.

**What the judge requires** (`oracle._judge_exec`). Signed events, the manifest, the tree check and
admission apply first, unchanged. Then, in this order, all of:

1. **Authenticated provenance is on.** Without the staged app nothing is proven.
2. **No in-process write to the canary or the marker**, from anyone: `canary_tampered`.
3. **Nothing was done from test frames.** For every `process`, `native`, `env`, `chdir` and
   `codegen` event, the innermost project frame on the logical stack must not be test code:
   `process_from_test`. Library frames in between do not count, so a test callback the app calls, a
   thread, a timer or a pool task the test started all count as the test.
4. **Every process has valid provenance**, not just one: admitted app code, outermost app frame a
   declared entry point, called from the test, no link to the canary created during the run. So a
   harmless entry-point call does not launder a sink the test calls directly next to it. A process
   with no project frame at all (an `atexit` callback) fails too, as does one run by a `weakref`
   finalizer, which fires on whatever stack drops the object.
5. **No watched API or variable changed** before any process started: `process_api_changed`.
6. **The marker holds the token.** The host or sandbox runner checks this itself after the run
   (`marker_holds_token`): a regular file with one link, at most 1 MiB, every line exactly the token.
   On the host path the canary must also still be the same regular file. Unchecked is not a proof.
7. **One process from an application sink names the canary** (`names_canary` and `sink_named`).

The test must also fail, as for every effect. On the sandbox path `outside/` is a bind mount the host
reads directly, so nothing the container reports about the marker is trusted (`docs/reference/sandbox.md`).

**Static guard** (`guard.exec_problem`, this effect only). A call of a process API, or one passed to
another call as a callable (`partial(os.system, x)`, `Thread(target=subprocess.run)`), is rule
`process_call`; `eval`/`exec`/`compile` called from the test is `exec_codegen`. Naming an API as
data stays allowed: a pickle payload's `__reduce__` returns `(os.system, (command,))`. Before this
task the guard had no rule against `subprocess` in a test, only the prompt text forbade it; the
read and write effects stay as they were. It is a tripwire: every cheat in
`tests/test_oracle_exec.py` also runs with it off.

**What it cannot see.** These are recall costs unless marked otherwise.

- A process started by a C extension without an audit event. In-process, this is a false-proof risk
  like R1: `ctypes` raises events and is refused from test frames, but a shared object the test
  loads itself is not observed. The sandbox has no compiler, so it would have to ship the bytes.
- A shell that never execs the canary: `echo <token> > <marker>` from a real injection is command
  execution, but it is not this effect and is not proven.
- A command that computes the canary's name (`$(printf ...)`, `${c}ary`, a glob) does not name it.
- A process whose sink the innermost app frame does not name: `self.runner(cmd)`, an import alias
  (`from subprocess import run as r`), or a dependency that starts the process for the app.
- A payload that calls a test-defined function (`__reduce__` returning a function in the test
  file): the test frame is innermost, so it counts as started by the test.
- A process at import time, or from `App.__init__`, anywhere in the run: its outermost app frame is
  not an entry point, so the whole run is refused. So is a test that uses `os.chdir`, or an app or
  dependency whose import starts a process.
- Shims in a directory already on `PATH`. In the sandbox those directories are read-only. On the
  host path, which is research tooling and not isolated, they are not.

Residual false proofs: R1 and R5 apply to this effect like the others, and both are pinned
(`test_r1_*`, `test_r5_*` in `tests/test_oracle_exec.py`, `attack_exec_r1_cell_tamper` and
`attack_exec_r5_app_binding` in `spikes/redteam`). Rewriting the hook's closure stops it watching the
marker. Replacing a name in the app's own module (`setattr(sys.modules["app"], "quote", str)`) makes
the admitted code really build an injection. The install-time snapshot catches the stdlib's
`shlex.quote`, not that. Callback tricks that need no Python frame and fire on the app's stack are
the same family: `sink_named` and the `weakref` check narrow them, but do not bound them.
The `canary_sql` forgery (section 3.10) is R1 through `emit` instead of the hook's closure.

### 3.10 Layer 9: the `canary_sql` effect (T090)

A fourth family of effect, SQL injection. A file effect observes the application touching a file
and `canary_exec` observes it running a program; this one observes the application **reading a row
it never asks for**. The proof is that the app, handling input the test sent through its entry
point, ran SQL that read a table the app never queries.

**The canary.** `case.json` declares the application's SQLite database as `run.sql_db`, a plain
relative path inside the clone (letters, digits and `_./-`; no `..`, no link, a regular file of at
most 256 MiB). The oracle never touches that file. It seeds a **copy**:

- host path (`run_oracle`, research tooling): the app is staged as for every effect, the copy gets
  `CREATE TABLE exhibit_canary (token TEXT)` with one row holding the run's token, is switched to the
  rollback journal and made read-only (`0444`), and goes into the manifest, so the tree check sees any
  change to it. A database that already has that table, or is not a database, is refused.
- sandbox: a short-lived init container (same image and hardening flags, `--network none`,
  `--cap-drop ALL`, `no-new-privileges`, resource limits) mounts the original read-only and writes the
  seeded copy to a host directory; the test container then mounts that copy **read-only** over
  `/workspace/<sql_db>`. The seeded file is checked to be a regular file before it is mounted.

The test gets `EXHIBIT_A_CANARY_TOKEN` and the contract text (`loop/prompts.py`): a table named
`exhibit_canary` with a `token` column holds the token and the app never queries it. It is **not**
given the database path (`EXHIBIT_A_CANARY` and `EXHIBIT_A_CANARY_SQL` reach only the plugin and are
popped after install; the guard refuses a test that names them). The app finds its own database, as
it would in production.

**What the plugin records** (signed, same channel; only in this effect), each with the logical stack:

| `op` | source | also records |
|---|---|---|
| `sql_connect` | the `sqlite3.connect` and `sqlite3.connect/handle` audit events | `connection` (index), `declared_db` (the path is the seeded file, by realpath or inode), `command` (the name as passed), `instrumented`, `patched` |
| `sql_read` | an authorizer installed on the connection: `SQLITE_READ` of `exhibit_canary` | `table`, `column`, `database` (`main`, `temp` or an alias), `connection`, `declared_db` |
| `sql_text` | a trace callback, once after a recorded read | the statement |
| `open`/`rename`/`link`, `target` `db` | as in layer 6, for the database file | |

**Finding (CPython 3.11 and 3.14).** In the `sqlite3.connect/handle` audit event the `Connection` is
not initialised yet, so `set_authorizer` cannot be called there (`ProgrammingError: Base
Connection.__init__ not called`). The audit events therefore give provenance (who opened which
connection, to which file) and a wrapper installed over `sqlite3.connect` (and the copy
`sqlite3.dbapi2.connect`, which ORMs use) instruments the connection after it is made. The wrapper is
the caller of the handle event, which is how `instrumented` is known; a connect function that is no
longer the plugin's wrapper when a connection opens is `patched`. The authorizer always allows the
operation: it only records, and the app sees nothing different. It runs while a statement is
prepared, so `sys._getframe(1)` is the frame that called `execute`.

**What the judge requires** (`oracle._judge_sql`). Signed events, the manifest, the tree check and
admission apply first, unchanged. Then all of:

1. **Authenticated provenance is on.** Without the staged app nothing is proven.
2. **Every connection of the run was opened by application code**: innermost project frame not a test
   frame (`sql_from_test`), and `sqlite3.connect` was still the plugin's wrapper (`sql_api_changed`).
   One connection the test opened refuses the whole run, even beside a genuine one.
3. **Only application code touched the database file**, and only to read it: an open, rename or link
   from a test frame is `sql_from_test`; a write by anyone is `canary_tampered`.
4. **Every read of the canary table**, not just one: from admitted application code (a statement the
   test ran itself, on its own connection or on one it took from the app, is a test frame:
   `sql_from_test`), on a connection the judge saw opened, to the app's own file, in its `main`
   schema (an `ATTACH`ed copy, a temp table or another file is `sql_unplaced`), with valid provenance:
   outermost app frame a declared entry point called from the test, no link used (`provenance`,
   `frame_not_admitted`).
5. **The `token` column was read at least once** (otherwise `no_effect`: the test failed for the wrong
   reason), and the test failed.

That the token **reached the test through the app** is the assertion the test makes: the oracle checks
the read, the failing assertion checks the response. A test that copies the token from the environment
into the response (`ECHO` apps) makes its own assertion fail, but no statement read the table, so
there is no effect.

**Static guard** (`guard.sql_problem`, this effect only). A test is refused before it runs if it names
`sqlite3` (import, name, attribute or string), calls or references a method that runs SQL or
reconfigures a connection (`execute`, `executescript`, `cursor`, `set_authorizer`, `create_function`,
...), names a database file (`.db`, `.sqlite`, `-journal`, ...), or hands a function it defines, a
lambda, `partial` or `staticmethod` to an attribute or to `setattr`, which is how an app's query
builder is swapped. It is a tripwire like the others: every cheat in `tests/test_oracle_sql.py` also
runs with it off, and the runtime layers alone refuse them.

**What it cannot see.** These are recall costs unless marked otherwise.

- A connection opened at import time or in `App.__init__` is recorded, and is fine when the app opens
  it. Statements run later on it are attributed to the frame that called `execute`.
- A driver other than `sqlite3` (SQLAlchemy over another engine, `psycopg2`) is not observed.
  SQLAlchemy over SQLite should go through `sqlite3.connect` and so be observed, but no test runs it
  here: designed, not verified.
- The sink catalog flags a call as a SQL sink only when its statement is not a constant string
  (`graph/catalog.py`). An unresolved receiver (`cur.execute(q)`) is a weak hit; its arguments are
  kept for that purpose only.
- A statement longer than 600 characters is cut in the graph, so a long constant one looks dynamic.
- The seeded copy is a snapshot. An app whose behaviour depends on data the copy lacks, or that writes
  to its own database during the run (the file is read-only), cannot be proven.

Residual false proofs: R1 and R5 apply to this effect like the others, and both are pinned
(`test_r1_*`, `test_r5_*` in `tests/test_oracle_sql.py`, `attack_sql_r1_forge_events` and
`attack_sql_r5_app_binding` in `spikes/redteam`). With computed names the test finds `emit` in the hook
module, which holds the signing key, and signs a `sql_connect` and a `sql_read` that name the entry
point's real frame (R1). It can also replace a name in the app's own module, here the escaping helper
(`setattr(sys.modules["app"], "quote", str)`), so the admitted code really builds an injected
statement (R5). Neither is stopped in-process; both are listed in section 7.

### 3.11 Layer 10: the `canary_connect` effect (T104)

A fifth family of effect, server-side request forgery. A file effect observes the application
touching a file, `canary_exec` observes it running a program, and `canary_sql` observes it
reading a row it never asks for; this one observes the application **requesting a URL only
the run knows**. The proof is that the app, handling input the test sent through its entry
point, fetched a per-run loopback URL.

**The canary.** A loopback HTTP listener (`oracle/canary_server.py`, stdlib only), started per
run on 127.0.0.1 at a random port (20000–59999). It serves the run's token at exactly one
unguessable path (16 random hex characters, also matched with anything under it, so an app
that appends to the URL still proves it knew the secret); every other path answers 404
without the token. The listener records every accepted TCP connection and every HTTP
request as JSON lines in a log file, each tagged with the token.

- host path (`run_oracle`): the listener is a separate child process (`python -I -S`), bound
  before the test runs and killed after; it never loads the oracle plugin, so its own
  sockets produce no events.
- sandbox: the listener runs *inside* the test's container from a read-only mount, started
  by the container shell next to pytest with a readiness probe, and killed after it. The
  container keeps `--network none`: loopback still works, and a probe test
  (`test_the_container_has_no_network_interface_besides_loopback`) asserts the container
  exposes no interface besides `lo`. The log lands in a read-only-for-the-host file
  (`/oracle/connect.jsonl`, the only other writable mount); the test can name it only
  through a computed path (the guard refuses the literal, and `/oracle` is already
  refused).

The test gets `EXHIBIT_A_CANARY_URL` (the full URL, secret path included) and
`EXHIBIT_A_CANARY_TOKEN` (for the assertion, as with the other effects). The token is
served by the listener only as the body of the secret path: any request for it from test
frames refuses the whole run (`connect_from_test`), so the test can never benefit from
fetching it directly. The listener's log is untrusted (the test shares the machine and
could append to it): the oracle never proves from the log alone.

**What the plugin records** (signed, same channel; only when `EXHIBIT_A_CANARY_URL` is
present), each with the logical stack:

| `op` | audit event | also records |
|---|---|---|
| `connect` | `socket.connect` (the peer address), `socket.getaddrinfo` (host, port), `http.client.connect` (host, port) | `host`, `port` |
| `request` | `urllib.Request` (the full URL), `http.client.send` (the request line's target) | `url` |

These events fire in the real implementation, so nothing is wrapped: a fake that never
connects produces no event, and a replacement (monkeypatched `socket.connect`, a stubbed
`urlopen`) either still fires them from the app's frames or produces none at all. A forked
child shares the event sequence with its parent (anonymous shared memory and a pipe-based
mutex), as for `canary_exec` and `canary_sql`.

**What the judge requires** (`oracle._judge_connect`). Signed events, the manifest, the
tree check and admission apply first, unchanged (no route check: there is no file path,
and every event carries `requested: None`). Then all of:

1. **Authenticated provenance is on.** Without the staged app nothing is proven.
2. **Nothing connected or requested from test frames**: one `connect` or `request` event
   whose innermost project frame is the test's (or nobody's) refuses the whole run, even
   beside a genuine one (`connect_from_test`). A raw socket the test opens, a lookup it
   resolves, or a request it sends are all the test's.
3. **The listener's log shows a request for this run's secret path.** Without it (a
   connection the app opened but never requested, a refusal, a timeout) nothing is proven
   (`no_effect`).
4. **A signed `request` event shows the application itself requested that path** (a full
   URL on a loopback host with the run's port and secret path, or a bare target equal to
   it) **with valid provenance**: admitted app code, outermost app frame a declared entry
   point, called from the test. A raw-socket app that never builds a URL object is not
   provable (a recall cost, below).
5. **A signed `connect` event shows the application itself connected to the listener**
   (a loopback host and the run's port) with valid provenance.
6. **The test failed**, as for every effect.

That the token **reached the test through the app** is the assertion the test makes: the
oracle checks the request, the failing assertion checks the exfiltration. A test that
fetches the URL itself makes its own assertion fail, but its own `connect` event refuses
the run first.

**Static guard** (`guard.connect_problem`, this effect only). A test is refused before it
runs if it imports or names a network module (`socket`, `urllib.request`, `urllib3`,
`http.client`, `requests`, `httpx`, `aiohttp`), names a connect or fetch API
(`create_connection`, `getaddrinfo`, `urlopen`, `HTTPConnection`, ...), or names the
listener's implementation or its log (`canary_server`, `connect.jsonl`). `urllib.parse`
stays allowed: tests build no request with it. It is a tripwire like the others: every
cheat in `tests/test_oracle_connect.py` also runs with it off, and the runtime layers
alone refuse them.

**What it cannot see.** These are recall costs unless marked otherwise.

- An app that speaks HTTP over a raw socket (hand-crafted request, no `urllib` or
  `http.client` call) connects observably but requests nothing the plugin can see: the
  listener logs it, but no signed `request` event names the path, so it is not proven.
- UDP, Unix sockets and non-HTTP protocols are not observed and never match.
- A connection the app opens but never requests (a port scan, a refused SYN, a DNS
  lookup alone) is not SSRF and is not proven.
- An app whose HTTP client runs in a child process is observed (fork-safe sequence), but
  one whose client runs in a *grandchild* that re-executes is not: a new process image
  has no hook.
- As with every effect, the graph flags a call as an SSRF sink only when its target may
  carry input: `urllib.request.urlopen`, `http.client`, `requests`/`httpx` and
  `aiohttp` calls always, `socket.create_connection` only with a non-constant target
  (`graph/catalog.py`).

Residual false proofs: R1 and R5 apply to this effect like the others, and both are
pinned (`test_r5_*` in `tests/test_oracle_connect.py` on the host path,
`test_r1_key_theft_and_log_forgery_forge_a_proof_in_the_sandbox` in the sandbox, plus
`attack_connect_r1_forge_events` and `attack_connect_r5_app_binding` in
`spikes/redteam`). With computed names the test finds `emit` in the hook module and signs
a `connect` and a `request` that name the entry point's real frame (R1): on the host path
the listener's log stops it (the test cannot learn the log's path, so nothing it signs
matches a recorded request), but in the sandbox the log path is fixed and one forged line
completes the forgery. It can also replace a binding in the app's own module, here the
canary host (`setattr(sys.modules["app"], "HOST", ...)`), so the admitted code really
requests the canary through the entry point (R5). Neither is stopped in-process; both are
listed in section 7.

### 3.12 Layer 11: the `canary_dos` effect (T105)

A sixth family of effect, algorithmic complexity: regular-expression denial of service
(ReDoS) and quadratic parsing. File effects observe the application touching a file;
`canary_exec` observes it running a program; `canary_sql` observes it reading a row it
never asks for; `canary_connect` observes it requesting a URL only the run knows. This
one observes that the application, handling a small malicious input the runner sent
through a declared entry point, spent far more CPU than on a benign input of the **same
length**, and that the CPU was spent in admitted application frames.

A timing effect is noisier than a canary file, so the proof standard is statistical and
conservative. Sandbox CPU and time limits are unchanged.

**The contract.** There is no canary file. The test supplies two inputs of equal length
(at most 64 KiB) through the `dos_probe` pytest fixture the plugin provides:
`dos_probe(<entry point callable>, malicious=..., benign=...)`. The test must not time,
sleep, hash, profile or busy-loop anything itself. `EXHIBIT_A_CANARY_DOS` reaches only
the plugin and is popped after install; the guard refuses a test that names a clock,
`sleep`, `setprofile`, `getrusage` or a slow hash. It is a tripwire like the others:
every cheat in `tests/test_oracle_dos.py` also runs with it off.

**What the plugin records** (signed, same channel; only when `EXHIBIT_A_CANARY_DOS` is
set). It binds `time.thread_time` and `sys.setprofile` at install. For each of 5 pairs,
in the same process, it calls the entry point with the benign input then the malicious
input. `sys.setprofile` attributes CPU between events to the innermost project frame:
admitted application code, test code, or other (stdlib `re`, C, the plugin). C time in
the regex engine is attributed to the Python caller, so a `re.search` from an admitted
app frame counts as application CPU. CPU in test frames (a wrapper's busy loop, a sleep
does not burn CPU, hashing) does not. One `op` `dos` event carries the median
malicious/benign application-CPU **ratio**, the median malicious application CPU, the
fraction of malicious CPU spent in app frames, the sample count, and `noisy` (the
malicious samples spread by more than 4x). If `sys.setprofile` was replaced during a
call, `patched` names it. On a clear slowdown the probe fails the pytest test so the
outcome is `failed`; the judge still has to accept the signed numbers.

**What the judge requires** (`oracle._judge_dos`). Signed events, the manifest, the tree
check and admission apply first, unchanged. Then all of:

1. **Authenticated provenance is on.** Without the staged app nothing is proven.
2. **Nothing was timed from test frames** as the innermost project frame on the signed
   stack (`dos_from_test`).
3. **`sys.setprofile` was intact** (`dos_api_changed`).
4. **Valid provenance:** admitted app code, outermost app frame a declared entry point,
   called from the test.
5. **The samples were finite and not noisy.** NaN, inf, or `noisy` is `flaky`, never a
   proof. The loop maps that reason to verdict `flaky`.
6. **At least 80% of the malicious CPU was in application frames.** A wrapper that burns
   CPU in the test is `dos_from_test`.
7. **Median ratio > 50x AND median malicious application CPU ≥ 15 ms.** Below either
   bar is `no_effect` (a noisy machine producing a 50x ratio on sub-millisecond times
   cannot prove).
8. **The test failed**, as for every effect.

**Static guard** (`guard.dos_problem`, this effect only). A test is refused before it
runs if it names a clock, sleeper, profiler, alarm or slow hash (`sleep`,
`process_time`, `thread_time`, `perf_counter`, `setprofile`, `pbkdf2_hmac`, …) or
imports `timeit` / `resource` / `cProfile`. It is a tripwire: the runtime layers
alone refuse the cheats.

**Graph catalog.** `re.match` / `search` / `fullmatch` / `sub` / `findall` / `compile`
are sinks when the pattern is not a constant, or is a constant with nested quantifiers
(`(a+)+`, `(a*)*`, …). A linear constant such as `^[a-z]+$` is not. `json.loads` /
`json.load` / `json.JSONDecoder.decode` of a non-constant source, and
`xml.etree.ElementTree.iterparse` / `xml.parsers.expat.ParserCreate`, are
algorithmic-complexity sinks. (XML entity-resolving parses stay `canary_read` / XXE.)

**What it cannot see.** These are recall costs unless marked otherwise.

- A slowdown that is real but below 15 ms of application CPU, or below 50x the same-length
  benign input, is not proven.
- An app whose malicious and benign paths are both quadratic (the algorithm does not
  depend on content) cannot be proven: the ratio is ~1x.
- CPython's JSON parser is not observably slower on nested input of the same length as
  flat input; nested JSON is catalogued as a sink, not dynamically proven here.
- A grandchild process that re-executes has no hook, as with every effect.

Residual false proofs: R1 and R5 apply to this effect like the others, and both are
pinned (`test_r1_forged_dos_event_is_a_false_proof` and
`test_r5_app_binding_is_a_false_proof` in `tests/test_oracle_dos.py`, plus
`attack_dos_r1_forge_events` and `attack_dos_r5_app_binding` in `spikes/redteam`). With
computed names the test finds `emit` and signs a `dos` event that names the entry
point's real frame (R1). It can also replace a binding in the app's own module, here
the regex (`setattr(sys.modules["app"], "PATTERN", r"(a+)+$")`), so the admitted code
really backtracks through the entry point (R5). Neither is stopped in-process; both are
listed in section 7.

Trees used by the tests live under `tests/fixtures/dos/` (vulnerable / fixed), not in
`bench/corpus/`: bench files were not treated as free for a new corpus case.

### 3.13 Layer 12: the `canary_redirect` effect (T106)

A seventh family of effect, open redirect (CWE-601, a common and easily observed web bug).
File effects observe the application touching a file, `canary_exec` observes it running a
program, `canary_sql` observes it reading a row it never asks for, `canary_connect`
observes it requesting a URL only the run knows, and `canary_dos` observes it burning
CPU. This one observes the application's **response**: that it answers, through a
declared entry point, with a redirect to a per-run canary host. The redirect target is
observable in the HTTP response the app produces, without the network: nothing is ever
fetched from the canary host (`.invalid` never resolves).

**The contract.** There is no canary file and no listener. The test reads the canary URL
from `EXHIBIT_A_CANARY_REDIRECT` and passes it (whole, or split into host and path) as
the entry point's input through the `redirect_probe` pytest fixture the plugin provides:
`redirect_probe(<entry point callable>, <redirect target>)`. The plugin calls the entry
point itself, captures the returned response, signs one `op` `response` event, and
returns a plain copy the test asserts on. The test must fail only when the response
redirects to the canary URL. If the application refuses the input by raising or by
answering without a redirect, the test catches that and treats it as safe. The test must
never build a response itself, follow the redirect, or serve one. Only the run's canary
host matters to the judge (scheme, port and path do not): a 3xx `Location` to it always
counts, and when the case declares it (`run.redirect_meta`), an HTML meta refresh to it
counts too.

**What the plugin records** (signed, same channel; only when
`EXHIBIT_A_CANARY_REDIRECT` is set). `redirect_probe` validates that every input is a
short string, then calls the entry point the test named while `sys.setprofile` watches
for the first frame under the app root. That frame is the entry the plugin itself
called; its logical stack is the signed one. The return value is normalised to
`{status, location, body}`: a `(status, headers[, body])` tuple or list, a mapping with
`status`/`status_code`, `headers`/`header`, `body`/`text`/`data`/`content` keys, an
object with those attributes, or a bare string or bytes (a body with no status). Anything
else is not a response the judge can read: it is recorded with empty fields and proves
nothing. Bodies are capped (64 KiB) and locations shorter still; beyond that is a recall
cost. If the entry point raises, no event is signed and the exception reaches the test.
If the profiler was replaced while the entry point ran, `patched` names it. The fixture
returns the normalised response; the test's own copy is what its assertion checks.

**What the judge requires** (`oracle._judge_redirect`). Signed events, the manifest, the
tree check and admission apply first, unchanged. Then all of:

1. **Authenticated provenance is on.** Without the staged app nothing is proven.
2. **No response was produced from test frames**: the innermost project frame of every
   signed response is application code (`redirect_from_test`). One response the test
   built itself refuses the whole run, even beside a genuine one. A replacement of
   `sys.setprofile` mid-call is `redirect_api_changed`.
3. **Every observed response has valid provenance**: admitted app code, outermost app
   frame a declared entry point called from the test (`provenance`,
   `frame_not_admitted`).
4. **At least one response redirects to this run's canary host**: a 3xx status whose
   `Location` names it, or — only when the case declares it — an HTML meta refresh
   whose target names it (otherwise `no_effect`: the test failed for the wrong
   reason), and the test failed.

That the redirect **reached the test through the app** is the assertion the test makes:
the oracle checks the response, the failing assertion checks the test's copy of it. A
test that asserts on a safe response fails by its own doing, but no response names the
canary host, so there is no effect.

**Static guard** (`guard.redirect_problem`, this effect only). A test is refused before
it runs if it imports a web framework (`flask`, `django`, `starlette`, `fastapi`,
`werkzeug`, `aiohttp`, `http.server`) or names a redirect helper or response
constructor (`redirect`, `RedirectResponse`, `HttpResponseRedirect`, ...). Reading the
`Location` header stays allowed: the test asserts on the copy the probe returns. It is
a tripwire like the others: every cheat in `tests/test_oracle_redirect.py` also runs
with it off, and the runtime layers alone refuse them.

**Graph catalog.** Redirect helpers are sinks when their target is not a constant:
`flask.redirect`, `werkzeug.utils.redirect`, `django.shortcuts.redirect`,
`django.http.HttpResponseRedirect` (and its permanent/found variants), and the
`RedirectResponse` of Starlette and FastAPI (`graph/catalog.py`, `target_arg` on the URL
position, effect `canary_redirect`). A constant target cannot carry input and is not a
sink. No graph rule is needed for the response itself: the proof is the observed
redirect, not a call.

**What it cannot see.** These are recall costs unless marked otherwise.

- A response shape the normaliser does not know (a framework response without the
  documented attributes, a body past 64 KiB, a location past 4 KiB) proves nothing.
- An entry point that takes anything but short strings cannot be probed: the probe
  refuses non-string inputs rather than guess how to call it.
- An app that answers through a worker thread the probe does not wait for, or that
  redirects client-side (JavaScript `location`, a `Refresh` header instead of a meta
  tag), is not observed.
- The canary host is matched, not the full URL: an app that redirects to the canary
  host with attacker-fixed path is still an open redirect and is still proven.

Residual false proofs: R1 and R5 apply to this effect like the others, and both are
pinned (`test_r1_a_forged_signed_response_proves_a_safe_app` and
`test_r5_a_replaced_app_binding_proves_a_safe_app` in `tests/test_oracle_redirect.py`,
plus `attack_redirect_r1_forge_events` and `attack_redirect_r5_app_binding` in
`spikes/redteam`). With computed names the test finds `emit` in the hook module, which
holds the signing key, and signs a `response` that names the entry point's real frame
and the canary host (R1). It can also replace a binding in the app's own module, here
the allow-list (`setattr(sys.modules["app"], "ALLOWED", ...)`), so the admitted code
really redirects through the entry point (R5). Neither is stopped in-process; both are
listed in section 7.

Trees used by the tests live under `tests/fixtures/redirect/` (vulnerable / fixed),
not in `bench/corpus/`: bench files were not treated as free for a new corpus case.

### 3.14 Layer 13: the `canary_access` effect (T106)

An eighth family of effect, broken access control (OWASP's number one: insecure direct
object references). Where `canary_redirect` observes the application's answer naming a
canary host, this one observes the application's answer **holding a token only a victim
owns**. The case declares two principals — an attacker and a victim — and how to
authenticate as each, plus the protected resource; the runner seeds a resource owned by
the victim, holding the token, and the proof is that a request authenticated as the
attacker (or unauthenticated, when the app takes none) makes the app return the
victim's token. The token is observable in the response the app produces, without the
network.

**The contract.** There is no canary file the test could open: the application's own
store (a JSON file the case declares as `run.access_db`) is copied, the victim-owned
resource is added to the copy, and the copy is what the test runs against. The case
also declares `run.access` with `attacker`, `victim` and `resource`. The test learns
only the attacker credential (`EXHIBIT_A_ATTACKER`) and the resource id
(`EXHIBIT_A_RESOURCE`); the victim credential reaches only the seeding step, never the
test's environment. The test passes attacker and resource through the `access_probe`
fixture — `access_probe(<entry point callable>, <attacker credential>, <resource id>)`
— which calls the entry point itself as the attacker, signs one `op` `response` event,
and returns a plain copy. The test must fail only when the victim's token is in that
response. If the application refuses the request by raising or by answering with an
error, the test catches that and treats it as safe. A request authenticated as anyone
else — including the victim, who owns the resource — proves nothing.

**What the plugin records** (signed, same channel; only when `EXHIBIT_A_ATTACKER` and
`EXHIBIT_A_RESOURCE` are set). The probe is the redirect probe with the caller bound:
it validates short-string inputs, calls the entry point as `(auth, resource)`, captures
and normalises the response the same way, and signs the same `op` `response` event
with the logical stack seen while the entry point ran — plus the attacker credential
and resource it was called with. File opens the app makes while answering (reading
its own store) are recorded by the hook as usual and allowed; they prove nothing
alone.

**What the judge requires** (`oracle._judge_access`). Signed events, the manifest, the
tree check and admission apply first, unchanged. Then all of:

1. **Authenticated provenance is on.** Without the staged app nothing is proven.
2. **Nothing but application code touched the store file, and only to read it**: an
   open, rename or link from a test frame is `access_from_test`; a write by anyone is
   `canary_tampered`. Reading its own store is what the app does to answer.
3. **Every observed response was called for the declared attacker and resource.**
   A response observed for another credential or resource refuses the run
   (`access_from_test`) — this is what stops the victim-authenticated request from
   proving anything.
4. **No response was produced from test frames** (`access_from_test`), the profiler
   was intact (`access_api_changed`), and **every observed response has valid
   provenance** (`provenance`, `frame_not_admitted`).
5. **At least one such response holds the run's token** (otherwise `no_effect`: the
   test failed for the wrong reason), and the test failed.

That the token **reached the test through the app as the attacker** is the assertion
the test makes: the oracle checks the response, the failing assertion checks the
test's copy of it.

**Static guard** (`guard.access_problem`, this effect only). A test is refused before
it runs if it names the `json` module (import, name or attribute), names the victim
credential, or names a store file (a string ending in `.json`). The attacker credential
and the resource id stay allowed: they are the test contract. It is a tripwire like
the others: every cheat in `tests/test_oracle_access.py` also runs with it off, and
the runtime layers alone refuse them.

**Graph catalog.** No sink rule is meaningful for broken access control: the bug is a
missing ownership check, not a call. The redirect helpers are catalogued (section
3.13); access-control flaws surface only through the observed response.

**What it cannot see.** These are recall costs unless marked otherwise.

- An app whose authentication is anything but a credential-plus-resource call cannot
  be probed: the probe calls the entry point as `(auth, resource)` with short
  strings, and anything else fails closed.
- A store that is not a JSON object, or that already holds the resource, is refused
  rather than trusted; an app that writes its own store during the run cannot be
  proven (the seeded copy is read-only).
- A token past the 64 KiB body cap, or a response shape the normaliser does not
  know, proves nothing.
- The response is matched by substring: an app that returns the token only truncated
  or encoded is missed.

Residual false proofs: R1 and R5 apply to this effect like the others, and both are
pinned (`test_r1_a_forged_signed_response_proves_a_safe_app` and
`test_r5_a_replaced_app_binding_proves_a_safe_app` in `tests/test_oracle_access.py`,
plus `attack_access_r1_forge_events` and `attack_access_r5_app_binding` in
`spikes/redteam`). With computed names the test finds `emit` and signs a `response`
naming the entry point's real frame, the attacker credential, the resource and the
token (R1). It can also replace a binding in the app's own module, here the
ownership-check switch (`setattr(sys.modules["app"], "CHECK", False)`), so the
admitted code really leaks through the entry point (R5). Neither is stopped
in-process; both are listed in section 7.

Trees used by the tests live under `tests/fixtures/access/` (vulnerable / fixed,
each with its store), not in `bench/corpus/`: bench files were not treated as free
for a new corpus case.

### 3.15 Layer 14: OS-level witness (T114)

The in-process plugin is a first witness. Residual limit R1 exists because that plugin
lives in the untrusted test process: a test that finds the signing key can emit a
perfect event without ever touching the canary. An observer **outside that process**,
inside the same isolated and resource-limited container, is a second witness. A
suspicion is proven only when both agree on the fact of the effect.

**Supervisor.** `src/exhibit_a/sandbox/witness/supervisor.py` is copied into the
container as `/opt/exhibit_a_plugin/witness.py` and started **before** pytest, as a
sibling (not a child of the test). It reads a per-run config that includes its own
HMAC key, unlinks that file, then watches:

- `canary_read` / `canary_write`: inotify (`IN_OPEN` / `IN_ACCESS` / `IN_CREATE` /
  `IN_CLOSE_WRITE`) on the canary path;
- `canary_exec`: the same on the executable and on the marker the canary writes;
- `canary_sql`: inotify on the seeded SQLite file (a read of the canary table opens
  that file);
- `canary_connect`: the loopback listener itself (the supervisor *is* the process
  that `accept()`s; a forged `connect.jsonl` line is not an observation).

Signed observations go to `/oracle/witness.jsonl`. The judge (`_apply_witness`)
applies agreement last, and only when the in-process verdict is already a proof:
both witnesses must have seen the effect, or that proof becomes `witness_mismatch`
(plugin saw, OS did not) or `witness_unavailable` (missing or tampered log). A
more specific in-process refusal (`sql_from_test`, `no_effect`, `canary_tampered`,
provenance, …) is kept. The host path (`run_oracle`) passes no witness payload
and keeps the in-process standard.

**What it cannot observe.** `canary_dos` (CPU), `canary_redirect` and
`canary_access` (in-process response objects) have no OS-level canary the
supervisor can watch. They keep the in-process standard, including their R1
strict xfails.

**What it closes.** Plugin-only fact forgery (the R1 of `attack_key_introspection`,
`attack_sql_r1_forge_events`, `attack_connect_r1_forge_events` in the sandbox) is
now BLOCKED: the plugin claims a read/query/connect the OS never saw. Tests:
`tests/test_oracle_witness.py` (agreement, mismatch, unavailable, sandbox R1) and
`tests/test_oracle_connect.py::test_r1_key_theft_and_log_forgery_forge_a_proof_in_the_sandbox`
(no longer an xfail). Host-path R1 remains a declared limit
(`tests/test_oracle_residual.py`). A test that really opens the canary and then
forges the stack (`cheat_read_then_forge` in the observer spike) still makes both
witnesses agree on the fact; provenance stays in-process (section 8). R5 is a
genuine app access, which any observer would confirm.

### 3.16 Test-only layer switch (T112)

A bench ablation can switch off **one** provenance layer at a time so a judge can
see what that layer was stopping. The switch is `run_oracle(..., disabled_layers=...)`
or the context `disable_oracle_layers("L4_guard", ...)`. Names are `L1_manifest`,
`L2_admission`, `L3_app_tree`, `L4_guard`, `L5_dir_fd`, `L6_route_access`,
`L7_canary_links`, and `L14_witness` (T114's OS-level witness). The plugin copy
inside the test process reads the same names from `EXHIBIT_A_DISABLED_LAYERS`,
which `run_oracle` sets only when the switch is on and which the plugin pops at
install.

This is a test-only switch. The CLI never sets it: there is no flag, the CLI
never forwards that environment variable, and `tests/test_ablation_table.py`
asserts both. Production callers leave every layer on. The table that results
is `docs/bench/ablations.md` (replay only, no live model call).

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
| symlink swapped in and out by a test thread (race) | — | — | — | — | flagged by L7 (link created) |

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
| `attack_key_introspection` (new, R1) | safe | BLOCKED, by accident¹ | **FALSE_PROVEN** (host) | **FALSE_PROVEN** (host) | host path: not stopped (R1). Sandbox: BLOCKED by L14 (`witness_mismatch`; `tests/test_oracle_witness.py`) |
| `attack_dependency_monkeypatch` (new, R5) | safe | **FALSE_PROVEN** | **FALSE_PROVEN** | **FALSE_PROVEN** | not stopped (R5) |
| `attack_subprocess_sink` | vulnerable | SUPPRESSED_TRUE | SUPPRESSED_TRUE | SUPPRESSED_TRUE | not observed (R3) |
| `attack_os_open_dir_fd` | vulnerable | SUPPRESSED_TRUE | **DETECTED** | **DETECTED** | L5 |
| `attack_ctypes_libc_open` | vulnerable | SUPPRESSED_TRUE | SUPPRESSED_TRUE | SUPPRESSED_TRUE | not observed (R4) |
| `attack_symlink_recheck` | safe | BLOCKED | BLOCKED | BLOCKED | A-2 |

¹ On `main` the forged body was dropped only because it carried the new `line`/`admitted`
fields, which the old schema rejects. With the old frame shape the same key theft forges a
proof. `docs/oracle/oracle-a1.md` declared this limit; R1 now pins it with a test.

The sandbox twin of `attack_write_app_module`
(`spikes/redteam/sandbox_write_app_module_driver.py`) needs Docker and was **not run** here.
The expected result is BLOCKED twice: `channel_tripwire` with the guard on, and
`app_tree_changed` with it off. The fake-docker tests exercise the same sandbox code path
without a container.

Results for the `canary_exec` attacks, T085, same command, this session, host path. Every attack
that refuses a proof also runs the canary or writes the marker for real, except where noted.

| PoC | app | guard on | guard off | stopped by |
|---|---|---|---|---|
| `attack_exec_canary_from_test` | safe | BLOCKED | BLOCKED | `process_from_test` |
| `attack_exec_test_thread` | safe | BLOCKED | BLOCKED | `process_from_test` (logical stack) |
| `attack_exec_marker_write` | safe | BLOCKED | BLOCKED | `canary_tampered` |
| `attack_exec_outside_swap` | safe | BLOCKED | BLOCKED | `canary_tampered` (rename of `outside/`) |
| `attack_exec_path_shim` | safe | BLOCKED | BLOCKED | `process_from_test` (`os.putenv`); the sandbox tmpfs is also noexec |
| `attack_exec_native_system` | safe | BLOCKED | BLOCKED | `process_from_test` (`ctypes.dlsym`) |
| `attack_exec_raw_fork_exec` | safe | BLOCKED | BLOCKED | `process_from_test` (wrapper event; the call itself fails on 3.14) |
| `attack_exec_at_exit` | safe | BLOCKED | BLOCKED | no project frame on the stack |
| `attack_exec_finalizer` | safe | BLOCKED | BLOCKED | finalizer, or the test frame that dropped the object |
| `attack_exec_stdlib_patch` | safe | BLOCKED | BLOCKED | `process_api_changed` |
| `attack_exec_frameless_callable` | safe | BLOCKED | BLOCKED | `sink_named` |
| `attack_exec_copied_canary` | safe | BLOCKED | BLOCKED | the command does not name the canary |
| `attack_exec_true_injection` | vulnerable | DETECTED | DETECTED | control |
| `attack_exec_true_pickle` | vulnerable | DETECTED | DETECTED | control |
| `attack_exec_r1_cell_tamper` | safe | **FALSE_PROVEN** | **FALSE_PROVEN** | not stopped (R1) |
| `attack_exec_r5_app_binding` | safe | **FALSE_PROVEN** | **FALSE_PROVEN** | not stopped (R5) |

Results for the `canary_sql` attacks, T090, same command, this session, host path. The vulnerable
apps are the controls: each is proven (DETECTED) with and without the tripwire.

| PoC | app | guard on | guard off | stopped by |
|---|---|---|---|---|
| `attack_sql_test_opens_db` | safe | BLOCKED | BLOCKED | `sql_from_test` (connection opened by the test) |
| `attack_sql_test_execute` | safe | BLOCKED | BLOCKED | `sql_from_test` (statement run from a test frame on the app's connection) |
| `attack_sql_injected_connection` | safe | BLOCKED | BLOCKED | `sql_from_test` (connection handed to the app by the test) |
| `attack_sql_read_db_file` | safe | BLOCKED | BLOCKED | `sql_from_test` (open of the database file) |
| `attack_sql_monkeypatch_query` | safe | BLOCKED | BLOCKED | `sql_from_test` (the replacement runs in a test frame) |
| `attack_sql_connect_swap` | safe | BLOCKED | BLOCKED | `sql_from_test` / `sql_api_changed` |
| `attack_sql_copied_token` | safe | BLOCKED | BLOCKED | `no_effect` (no read of the table) |
| `attack_sql_internal_helper` | safe | BLOCKED | BLOCKED | `provenance` (entry point not called from the test) |
| `attack_sql_thread` | safe | BLOCKED | BLOCKED | `provenance` (thread stack holds no entry point) |
| `attack_sql_true_union` | vulnerable | DETECTED | DETECTED | control |
| `attack_sql_true_boolean` | vulnerable | DETECTED | DETECTED | control |
| `attack_sql_true_order_by` | vulnerable | DETECTED | DETECTED | control |
| `attack_sql_r1_forge_events` | safe | **FALSE_PROVEN** | **FALSE_PROVEN** | not stopped (R1) |
| `attack_sql_r5_app_binding` | safe | **FALSE_PROVEN** | **FALSE_PROVEN** | not stopped (R5) |

Results for the `canary_connect` attacks, T104, same command, this session, host path. The
vulnerable apps are the controls: each is proven (DETECTED) with and without the tripwire.

| PoC | app | guard on | guard off | stopped by |
|---|---|---|---|---|
| `attack_connect_from_test` | safe | BLOCKED | BLOCKED | `connect_from_test` (test connected itself) |
| `attack_connect_request_from_test` | safe | BLOCKED | BLOCKED | `connect_from_test` (urllib request from the test) |
| `attack_connect_http_client_from_test` | safe | BLOCKED | BLOCKED | `connect_from_test` (http.client request from the test) |
| `attack_connect_requests_from_test` | safe | BLOCKED | BLOCKED | `connect_from_test` (requests call from the test) |
| `attack_connect_resolve_from_test` | safe | BLOCKED | BLOCKED | `connect_from_test` (test resolved the host itself) |
| `attack_connect_raw_socket` | safe | BLOCKED | BLOCKED | `connect_from_test` (raw socket opened by the test) |
| `attack_connect_read_log` | safe | BLOCKED | BLOCKED | guard `connect_log`; at runtime no app request (`no_effect`) |
| `attack_connect_internal_helper` | safe | BLOCKED | BLOCKED | `provenance` (entry point not called from the test) |
| `attack_connect_thread` | safe | BLOCKED | BLOCKED | `provenance` (thread stack holds no entry point) |
| `attack_connect_copied_token` | safe | BLOCKED | BLOCKED | `no_effect` (no request happened) |
| `attack_connect_true_fetch` | vulnerable | DETECTED | DETECTED | control |
| `attack_connect_true_host` | vulnerable | DETECTED | DETECTED | control |
| `attack_connect_true_redirect` | vulnerable | DETECTED | DETECTED | control (test serves the 302, the app follows) |
| `attack_connect_true_localhost` | vulnerable | DETECTED | DETECTED | control (`localhost` names the same loopback service) |
| `attack_connect_r1_forge_events` | safe | BLOCKED | BLOCKED | `no_effect` on the host path: signed events alone match no listener record. Sandbox: BLOCKED by L14 (`witness_mismatch`; the OS listener never `accept()`ed) |
| `attack_connect_r5_app_binding` | safe | **FALSE_PROVEN** | **FALSE_PROVEN** | not stopped (R5) |

No new FALSE_PROVEN beyond the two declared residual limits. The sandbox runs the same cheats
(`tests/test_oracle_connect.py`, docker-marked, with the reason codes asserted); the red-team driver
itself is host-path only.

Results for the `canary_dos` attacks, T105, same command, this session, host path. The
vulnerable apps are the controls: each is proven (DETECTED) with and without the tripwire.
A noisy wrapper around a safe app is BLOCKED (`flaky` or `dos_from_test` or `no_effect`),
never a false proof.

| PoC | app | guard on | guard off | stopped by |
|---|---|---|---|---|
| `attack_dos_sleep` | safe | BLOCKED | BLOCKED | guard `dos_timer`; at runtime `no_effect` |
| `attack_dos_busy_loop` | safe | BLOCKED | BLOCKED | `dos_from_test` / `no_effect` (CPU in test frames) |
| `attack_dos_slow_benign` | safe | BLOCKED | BLOCKED | `no_effect` (ratio inverted) |
| `attack_dos_times_itself` | safe | BLOCKED | BLOCKED | guard `dos_timer`; at runtime `no_effect` |
| `attack_dos_helper` | safe | BLOCKED | BLOCKED | `provenance` (entry point not the helper) |
| `attack_dos_no_probe` | safe | BLOCKED | BLOCKED | `no_effect` (runner never timed) |
| `attack_dos_noise` | safe | BLOCKED | BLOCKED | `dos_from_test` / `flaky` / `no_effect` |
| `attack_dos_true_redos` | vulnerable | DETECTED | DETECTED | control |
| `attack_dos_true_nested` | vulnerable | DETECTED | DETECTED | control |
| `attack_dos_true_quadratic` | vulnerable | DETECTED | DETECTED | control |
| `attack_dos_r1_forge_events` | safe | **FALSE_PROVEN** | **FALSE_PROVEN** | not stopped (R1) |
| `attack_dos_r5_app_binding` | safe | **FALSE_PROVEN** | **FALSE_PROVEN** | not stopped (R5) |

Results for the `canary_redirect` attacks, T106, same command, this session, host path.
The vulnerable apps are the controls: each is proven (DETECTED) with and without the
tripwire. The `redirect_probe` fixture is the only observation channel: the test never
touches the network, so every cheat below refuses at the judge, not at a socket.

| PoC | app | guard on | guard off | stopped by |
|---|---|---|---|---|
| `attack_redirect_builds_response` | safe | BLOCKED | BLOCKED | `redirect_from_test` (response from the test's own function) |
| `attack_redirect_asserts_without_redirect` | safe | BLOCKED | BLOCKED | `no_effect` (test failed for the wrong reason) |
| `attack_redirect_echo` | safe | BLOCKED | BLOCKED | `no_effect` (echo names the host but redirects nowhere) |
| `attack_redirect_meta_undeclared` | safe | BLOCKED | BLOCKED | `no_effect` (meta refresh counts only when the case declares it) |
| `attack_redirect_internal_helper` | safe | BLOCKED | BLOCKED | `provenance` (helper is not a declared entry point) |
| `attack_redirect_response_in_thread` | safe | BLOCKED | BLOCKED | `redirect_from_test` (response from a test-owned function) |
| `attack_redirect_non_string_input` | safe | BLOCKED | BLOCKED | probe raises `TypeError`; no response signed (`no_effect`) |
| `attack_redirect_setprofile_swap` | safe | BLOCKED | BLOCKED | `redirect_from_test` (swapped profiler leaves no app stack) |
| `attack_redirect_true_direct` | vulnerable | DETECTED | DETECTED | control |
| `attack_redirect_true_host` | vulnerable | DETECTED | DETECTED | control |
| `attack_redirect_true_meta` | vulnerable | DETECTED | DETECTED | control (case declares `redirect_meta`) |
| `attack_redirect_r1_forge_events` | safe | **FALSE_PROVEN** | **FALSE_PROVEN** | not stopped (R1) |
| `attack_redirect_r5_app_binding` | safe | **FALSE_PROVEN** | **FALSE_PROVEN** | not stopped (R5) |

Results for the `canary_access` attacks, T106, same command, this session, host path.
The vulnerable app is the control: proven (DETECTED) with and without the tripwire.
The test never receives the victim credential; the runner seeds it.

| PoC | app | guard on | guard off | stopped by |
|---|---|---|---|---|
| `attack_access_builds_response` | safe | BLOCKED | BLOCKED | `access_from_test` (response from the test's own function) |
| `attack_access_reads_store` | safe | BLOCKED | BLOCKED | guard `access_store_file`; at runtime `access_from_test` (test read the store) |
| `attack_access_as_victim` | safe | BLOCKED | BLOCKED | `access_from_test` (response for a credential outside the contract) |
| `attack_access_wrong_resource` | safe | BLOCKED | BLOCKED | `no_effect` (app refused; nothing matched) |
| `attack_access_internal_helper` | safe | BLOCKED | BLOCKED | `provenance` (helper is not a declared entry point) |
| `attack_access_writes_store` | safe | BLOCKED | BLOCKED | guard `app_tree_write`; at runtime `access_from_test` (test touched the store) |
| `attack_access_echo` | safe | BLOCKED | BLOCKED | `no_effect` (echo holds no token) |
| `attack_access_response_in_thread` | safe | BLOCKED | BLOCKED | `access_from_test` (response from a test-owned function) |
| `attack_access_true_unchecked` | vulnerable | DETECTED | DETECTED | control |
| `attack_access_r1_forge_events` | safe | **FALSE_PROVEN** | **FALSE_PROVEN** | not stopped (R1) |
| `attack_access_r5_app_binding` | safe | **FALSE_PROVEN** | **FALSE_PROVEN** | not stopped (R5) |

No new FALSE_PROVEN beyond the four declared residual limits (R1 and R5, one pair per
effect). The sandbox runs the same cheats (`tests/test_oracle_redirect.py` and
`tests/test_oracle_access.py`, docker-marked, with the reason codes asserted); the
red-team driver itself is host-path only.

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

### 7.1 R1: in-process introspection of the plugin (FALSE_PROVEN on the host path)

The key, `seq`, events descriptor and admission object live in the audit hook's closure, in
the test's own process. A test can:

1. find the hook with `gc.get_objects()`, using computed names to slip past the tripwire;
2. read the key from the closure cells;
3. sign an event that claims admitted frames at the entry point's real qualname and line.

The host re-check passes because those are real. The same access allows patching the
admission object or reading `/proc/self/mem`. `test_r1_*` on the host path
(`tests/test_oracle_residual.py`, strict xfail) demonstrates it end to end.

**Closed in the sandbox for every effect the OS witness can see** (section 3.15): a
plugin-only forgery that never opens the canary, never reads the SQLite file, and never
`accept()`s on the loopback listener is `witness_mismatch` and is not a proof. The host
path has no supervisor and keeps this limit. Effects the witness cannot observe
(`canary_dos`, `canary_redirect`, `canary_access`) keep the in-process standard, including
their strict xfails. `canary_exec` R1 that rewrites the hook and still writes the marker
while the safe app's `ls` names the canary remains a fact the OS would confirm (pinned
xfail in `tests/test_oracle_exec.py`).

A stolen `emit` can still sign a `dos` event that names the entry point
(`tests/test_oracle_dos.py::test_r1_forged_dos_event_is_a_false_proof`, strict xfail).
The response effects are exposed the same way (`tests/test_oracle_redirect.py` and
`tests/test_oracle_access.py` R1 pins, strict xfails).

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
vulnerability is not. The same class of cheat replaces an app binding the effect cares
about: a regex on `canary_dos`
(`tests/test_oracle_dos.py::test_r5_app_binding_is_a_false_proof`, strict xfail), an
allow-list host on `canary_redirect` and an ownership-check switch on `canary_access`
(the T106 R5 pins, strict xfails). `module_monkeypatch` catches the plain spellings only. The differential
re-run on fixed code helps only if the fix does not use the patched function, and a gated
test can defeat it as in `docs/security/oracle-redteam.md` §3.3. An out-of-process observer would not
close this either: the read really happens in app code.

### 7.6 R6: obfuscated test-chosen app root (FALSE_PROVEN)

The test roots a safe, canonicalising app at the canary's directory through a computation the
guard does not evaluate. `test_r6_*` uses `os.path.join(os.path.dirname(ALLOWED), *["outside"])`:
the guard does not unpack a starred argument. The app requests the canary's own real path,
which the route check (§3.7) must accept because Starlette-style canonicalising apps and
absolute archive members request it too. Nothing at run time separates "the app was configured
with the canary's directory" from "the payload named the canary". Only the guard sees the
configuration, and it is a tripwire, not a boundary. Closing this would need the oracle, not
the test, to construct the app, for example a harness-owned app factory in the case profile.

### 7.7 Smaller limits

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

## 8. The OS witness is the second signal; provenance stays in-process

`docs/oracle/oracle-observer-spike.md` §1 separates *fact* (was the canary opened) from *provenance*
(by which code). Layer 14 (section 3.15) is that second signal, in-container: inotify on the
canary paths, the exec marker, the loopback listener, a read watch on the SQLite file.
Plugin-only R1 fact forgery is now BLOCKED in the sandbox for every effect the supervisor
can see. The spike's §5 residual (`cheat_read_then_forge`: really open the canary, then
forge the stack) still makes both witnesses agree on the fact; R5 is a genuine app
access, which any observer would confirm. Out-of-process CPython stack reconstruction
(spike §4 step 4) stays on the post-freeze roadmap.

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
