# Second vulnerability class — decision (A-8)

The engine had one real case: Starlette `StaticFiles` path traversal (CVE-2023-29159), a
**read** effect proven with a canary file. One case looks like a trick, so we added a second
class that is *different in kind* and meant to be proven by the same loop
(BASELINE → SUSPECT → EXPLOIT → RUN → VERDICT → FIX → VERIFY).

When A-8 landed, that class ran only at the oracle layer (`run_oracle(effect=...)`). The
sandbox-backed loop and the CLI were wired later by T076 (A-21; see
`docs/reference/sandbox-write-effect.md`): `TestRunner`, `SandboxRunner` and `VerificationLoop` take an
`effect`, and `exhibit-a run --case bench/corpus/archive-extraction-pathtraversal --replay`
answers from the case materials. The `--case` baseline still runs as a host child process.

## Criteria

A class is a good second case if it is: reproducible offline and deterministic; its effect is
observable by the oracle (a canary read/write or a process-spawn marker); backed by a small,
real public CVE with a roughly one-line fix; and licensable — either a minimal vulnerable copy
whose license permits vendoring, or an original equivalent.

## Candidates considered

### (a) Archive-extraction path traversal / zip-slip — **CHOSEN**

A crafted archive member (`../x` or an absolute path) escapes the extraction directory and the
extractor **writes a file outside** it.

- **Offline / deterministic:** yes — pure filesystem, no network, no clock.
- **Observable effect:** a **write** to a canary path outside the allowed directory. This is a
  genuinely new observed-effect type for the oracle (the first class only observed reads), which
  makes the second case different in kind rather than a second flavour of the same thing.
- **Real CVE, small fix:** **CVE-2007-4559** — directory traversal in Python's `tarfile`
  `extract`/`extractall`. The upstream fix is the extraction filter added in Python 3.11.4
  (PEP 706); `filter="data"` rejects unsafe members. The one-idea fix is "resolve the target and
  require it to stay under the destination."
- **License:** we vendor **no** third-party code; the case is an original synthetic extractor
  (see below), so licensing is a non-issue.

### (b) SSRF / open-redirect-style effect observable without network

An app fetches a user-controlled URL; the effect is a request to a forbidden target.

- Rejected: making the effect observable *without* a network means mocking the fetch, and a
  mocked sink is exactly the "adversarial lookalike" the oracle is supposed to reject. The honest
  effect (an actual outbound connection) needs network, which the sandbox forbids by design. The
  effect does not fit the canary/provenance model cleanly.

### (c) Command injection with an observable effect on a canary file

`os.system("... " + user_input)` lets input spawn a process that touches a canary.

- Viable and interesting (a process-spawn / write marker), but the effect is produced by a
  **child process** that has no audit hook, so the oracle's current provenance model (a Python
  call stack within one process) does not see it — this is exactly the `subprocess_sink` recall
  gap documented in `docs/security/oracle-redteam.md`. Proving it would need a cross-process observer,
  which is a larger oracle change than "extend minimally." Deferred.

### (d) Unsafe deserialization with a canary side effect

`pickle.loads` of untrusted data triggers a `__reduce__` side effect (e.g. writing a canary).

- Viable, but the natural payload runs attacker code directly, so the "did it go through a real
  entry point" provenance story is weaker and easy to confuse with the "test ran the sink
  itself" cheat. The write-effect zip-slip class exercises the same provenance machinery with a
  cleaner story, so (d) is deferred as a future third class.

## Decision

**Archive-extraction path traversal (zip-slip), proven through a `canary_write` effect.** It is
the strongest fit for every criterion and forces the oracle to grow a new, honest observed
effect (a write outside the allowed directory) while reusing the existing provenance and signed
-event machinery. The signed-event functions were not changed, but the plugin was (see below).

## CVE honesty

- **CVE-2007-4559 is real.** Its identity (directory traversal in `tarfile.extract`/`extractall`)
  and its fix (the PEP 706 extraction filter, `filter="data"`, added in Python 3.11.4) were
  **confirmed via web search on 2026-10-29**. No CVE number was invented.
- **The case app is original synthetic code**, written for this repository during the build
  period. It contains none of `tarfile`'s code; the archive format and extractor are written
  from scratch. The CVE is cited only as the real-world analog of the class, so the licensing and
  "write every line new" rules are satisfied with room to spare. See
  `bench/corpus/archive-extraction-pathtraversal/README.md` and `LICENSE.md`.

## What was built

- Case: `bench/corpus/archive-extraction-pathtraversal/` — `vulnerable/`, `fixed/`,
  `fixed_incomplete/` trees, `baseline_test.py`, labelled `exploits/`, and the manifests
  (`case.json`, `profile.json`, `suspicion.json`) validated against `src/exhibit_a/schemas`.
- Oracle extension: `run_oracle(..., effect="canary_write")` plus a read/write access classifier
  in `src/exhibit_a/oracle/oracle.py`; a fail-closed symlink-walk fix in `plugin.py` so an
  open-for-write of a not-yet-existing file is not mistaken for a symlink. A-8 left
  `sign_event`/`verify_lines` untouched, but `plugin.py` itself was changed here, and again by
  T079 (open flags, `os.rename`/`os.replace`/`os.link` observation, `EXHIBIT_A_CANARY` popped
  after install).
- Tests: `tests/test_case_archive_extraction.py` (baseline before/after the fix, fix
  verification, the incomplete-fix **bypass check**, schema validation) and
  `tests/test_oracle_eval_archive.py` (the labelled evaluation set across both classes, with the
  confusion matrix and real precision/recall written to `docs/oracle/oracle-eval.md`).
