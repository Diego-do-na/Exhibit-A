# Oracle finding A-1: forged events

## The problem

The oracle plugin runs inside the same Python process as the exploit test and appends one
JSON line per canary open to an events file. Before this change that file was writable from
the test (bind-mounted `:rw` in the sandbox, a plain temp file on the host path) and its path
was in `os.environ["EXHIBIT_A_EVENTS"]`. A test could append a line with a fake application
stack and then `assert False`, and the judge returned a proof. `tests/test_oracle.py`
reproduces this (`test_cheat_forge_events_*`). Before the fix both cheats were judged
`provenance_ok=True`.

## What can and cannot be fixed in-process

Code in the plugin's process can, in principle, read anything the plugin holds: closure
cells, the heap through `gc`, `sys.modules`, raw memory through `ctypes` or
`/proc/self/mem`. A secret held in pure Python in that process cannot stop a test that is
written to dig it out. This change does not try to. It raises the bar in layers:

1. Naive and model-generated cheating fails loudly.
2. Every remaining bypass needs deliberate introspection, which a static check can flag.
3. What remains is written down here as a precise limit.

Closing the gap for good needs an observer outside the test's process (and outside the
sandbox). That is a separate task.

## Event format

Each line the plugin writes:

```json
{"body": {"path": "...", "mode": "r", "stack": [...], "via_symlink": false},
 "seq": 0,
 "sig": "<hex HMAC-SHA256>"}
```

- `body` is the event exactly as before (the `OracleEvent` fields).
- `seq` starts at 0 and goes up by one per event within a run.
- `sig = HMAC-SHA256(key, f"{seq}\n{canonical_json(body)}")`. Here `canonical_json` is
  `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
- An unsigned plugin (no key) writes `"sig": ""`.

The judge (`oracle.verify_events` on the host path, `sandbox.runner._read_events` in the
sandbox) accepts a line only if all of these hold:

- it has exactly those three keys, with the right types;
- `sig` is non-empty and matches under the run's key (`hmac.compare_digest`);
- `seq` is greater than the last accepted one.

Everything else is dropped and counted. `Judgement.forged_events` (default 0) carries the
count. With any dropped line, `provenance_ok` is False and the reason says
"forged or unverifiable oracle event line(s) dropped". For a failing test the loop
classifies this as `invalid_test`. The old unsigned line format is never accepted.

## Layers

### Layer 1: key delivery on stdin

The orchestrator generates the key per run (`secrets.token_bytes(32)`), never the test. It
writes `EXHIBIT-A-KEY <hex>\n` to the child's stdin and closes the pipe:

- host path: `subprocess.run(input=...)` in `oracle._run_test`;
- sandbox path: `docker run -i` plus `subprocess.run(input=...)` in `sandbox.runner.run`.

The plugin reads fd 0 once, at import. That happens before pytest collects anything and
before pytest's capture points fd 0 at `/dev/null`. It reads only from a pipe, socket or
regular file, never a terminal. It reads only when both oracle variables are set, so
importing the module in the orchestrator never touches the orchestrator's stdin. The pipe's
data is consumed, so the test cannot read it again from fd 0. The key is never put in the
environment, the command line or a mount.

If no key arrives, the plugin runs in explicit unsigned mode (`sig: ""`). The judge drops
and counts those lines, so a run without a key can never prove anything
(`test_unsigned_plugin_events_are_never_trusted`).

- Stops: reading the key from `/proc/self/environ`, `/proc/self/cmdline`, a mounted file,
  or stdin after the fact.
- Does not stop: reading the key from the plugin's memory (see residual bypasses).

**Empirical check (host path, run in this session):** a throwaway test run under
`_run_test` with a known key dumped its own `/proc/self/environ` and `/proc/self/cmdline`,
`fstat(0)`, and whatever was left on fd 0. Results:

- key hex not present;
- raw key bytes not present;
- the `EXHIBIT-A-KEY` header not present;
- fd 0 is `/dev/null` (a character device) by the time the test runs, with nothing left to
  read;
- the run's genuine event verified (1 event, 0 forged).

As expected, `EXHIBIT_A_EVENTS` *is* still visible in `/proc/self/environ` (see layer 3).
The same check for the container is
`tests/test_sandbox_events.py::test_key_is_not_in_the_container_environ_cmdline_or_events_env`.
It needs Docker and was not run in this session.

### Layer 2: signed events

- Stops: appending a fake line (old format, or new format with a guessed signature),
  replaying a genuine line (repeated `seq`), reordering lines, and truncated or malformed
  lines. All of these are dropped *and* counted, and the count blocks a proof.
- Does not stop: a test that obtains the key (layer 1 limits) and signs its own line with
  the next `seq`. It also does not stop a test that *removes* genuine lines (truncating the
  file). That can only hide an effect, which gives a false negative, never a false proof.

### Layer 3: hiding the channel

After install, the plugin pops `EXHIBIT_A_EVENTS` from `os.environ`. It opens the events
file once (`O_WRONLY|O_APPEND|O_CLOEXEC`) before installing its audit hook and writes every
event through that descriptor. The path is not kept anywhere a test can look it up by name.

- Stops: a test finding the events path through `os.environ`
  (`test_cheat_env_read_finds_no_events_path`).
- Does not stop:
  - `/proc/self/environ` still shows the environment block as it was at exec. That is why
    nothing secret is ever put there.
  - The path is guessable. In the sandbox it is a fixed bind mount (`/oracle/events.jsonl`),
    which must stay because the host reads the file after the container exits. A bind mount
    cannot be hidden from the process. On the host it sits next to the allowed directory.
  - The plugin's descriptor is visible in `/proc/self/fd`.

  Layer 2 is what makes knowing the path useless.

Since T079, `EXHIBIT_A_CANARY` is *not* part of the test contract (the contract is
`EXHIBIT_A_ALLOWED_DIR` and `EXHIBIT_A_CANARY_TOKEN`) and the plugin pops it from
`os.environ` after install, as it does `EXHIBIT_A_EVENTS`. It used to be kept because a test
could derive it from `EXHIBIT_A_ALLOWED_DIR` anyway, but a test that knows the canary's path
can root a safe app at the canary's directory (audit F2). Shipped exploits now reach the
canary from `EXHIBIT_A_ALLOWED_DIR` (`../outside/canary.txt`), and the guard treats any
mention of `EXHIBIT_A_CANARY` as a hit of `exhibit_a_env`. What remains is residual limit R6,
an obfuscated test-chosen app root (`docs/oracle-provenance.md` §7.6).

### Layer 4: static guard (`oracle/guard.py`)

Before running, `run_oracle` parses the exploit test and a `conftest.py` next to it with
`ast` only, never importing or executing them. A match against `CHANNEL_RULES` returns
`test_outcome="error"` (the loop's `invalid_test`) with the reason
"test touches the oracle channel: <file> matches rule '<name>'". The rules, one test each in
`test_guard_flags_each_channel_rule`:

| rule | looks for |
|---|---|
| `exhibit_a_env` | any `EXHIBIT_A_*` name or string except the test contract (`ALLOWED_DIR`, `CANARY_TOKEN`) |
| `plugin_module` | `exhibit_a_oracle_plugin` (the sandbox module name) |
| `oracle_package_import` / `oracle_package_string` | importing or naming `exhibit_a.oracle` |
| `addaudithook` | `sys.addaudithook` |
| `closure` / `globals` | `__closure__`, `__globals__` |
| `gc_get_objects` / `gc_get_referrers` | heap walks |
| `ctypes` | `ctypes`, imported or named |
| `proc_self` | `/proc/self` in a string |
| `oracle_mount` | `/oracle` in a string (the sandbox mount) |
| `events_file` | `events.jsonl` in a string |

This is a tripwire, not a security boundary. String building (`"events" + ".jsonl"`),
`getattr` with computed names, `importlib` with joined names, and `exec` of decoded text
all slip past it. `test_cheat_forge_events_old_format_is_dropped_and_counted` deliberately
does this, so that layer 2 is tested on its own.

Where the guard runs: on the host path (`run_oracle`). The sandbox exploit path
(`loop/runner.py: SandboxRunner.run_exploit`) is outside this task's scope and does **not**
call the guard or pass the forged count to `_judge` yet. In the sandbox, forged lines are
still dropped by `sandbox.run` (so they cannot create a proof), but the count does not reach
the judgement. See "Pending" below.

## Residual bypasses (known limits)

Each of these defeats the layers above. They are listed so they can be declared, not
because they are easy:

- **In-process introspection.** The key and descriptor live in the plugin's closure. A test
  that reaches them through function internals, the garbage collector or `sys.modules` can
  sign valid events. The guard flags the plain spellings only. No tests were written that
  demonstrate this bypass end to end; it is declared from the design, not from a proof.
- **Raw memory reads.** The key can also be read from `/proc/self/mem` or with `ctypes`.
  Same process, same uid, so nothing prevents it.
- **Monkeypatching the plugin's dependencies.** The test can replace `hmac`, `json`,
  `os.write` or builtins in its own process before the plugin writes. It can then alter or
  drop genuine events before they are signed. It cannot sign without the key, but it can
  suppress or rewrite a body the plugin is about to sign (the plugin signs whatever reaches
  it).
- **A second audit hook.** One added by the test sees the same events and runs in the same
  process. The guard flags `addaudithook` by name only.
- **Writing through another descriptor.** `/proc/self/fd/<n>` reopens the plugin's
  descriptor, and `os.dup` duplicates it. Either way the test can write without knowing the
  path. Lines without a valid signature are still dropped.
- **Subprocesses spawned by the test.** They inherit nothing secret: the key is not in the
  environment, and stdin was drained. They can still write to the events file by path, but
  those lines are unsigned. They can also read the parent's memory via `/proc/<ppid>/mem`
  where ptrace rules allow it (same uid, and `no-new-privileges` does not forbid it). That
  is the memory-read limit again.
- **Symlink or hardlink tricks on the events file.** Replacing or redirecting the file only
  changes where lines land. The host reads the file it created, and unsigned lines are
  dropped. Truncation hides events: a false negative.
- **Canary-side tricks.** Covered by A-2 (`via_symlink`), with its own declared limits:
  hard links, bind mounts, `dir_fd` opens, and links created less than 2 s before install.
- **Patching builtins before the plugin installs.** Not possible from the test file. The
  plugin installs at import, before collection. A `conftest.py` or `-p` plugin shipped by
  the test runs later, and a `sitecustomize`/`.pth` file in the app's tree is outside the
  guard's view. The latter runs at interpreter start and is a real gap if the app root
  contains one.

## Pending

- Done in A-1p (`docs/oracle-provenance.md` §3.6): `loop/runner.py` now runs
  `guard.channel_problem(test_path)` before staging and passes `oracle_forged_events` (with
  the first drop reason) to `_judge`, so forged lines count on the sandbox path too.
- The in-process introspection bypass above is now demonstrated end to end and pinned by a
  strict xfail (`tests/test_oracle_residual.py`, R1).
- T079 added residual limit R6 (obfuscated test-chosen app root,
  `docs/oracle-provenance.md` §7.6), also pinned by a strict xfail.
- An out-of-process observer (separate task) is the only real fix for the residual list.
