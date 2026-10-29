# A-11 integration audit

**Branch:** `a5-audit` · **Base:** `main` at `780b9b3` · **Date:** 2026-10-29 · **Author:** claude-cloud
(independent reviewer; none of the audited code is mine).

**Scope:** the A-1, A-2, A-1p, A-8, A-9 and A-10 merges and the hand-resolved conflict in
`src/exhibit_a/oracle/oracle.py`. This change adds only this file and one line in
`docs/common.md`. Nothing under `src/`, `tests/`, `bench/`, `spikes/`, `.github/` or `action.yml`
was modified. Every PoC below ran from a scratch directory outside the repository.

**Labels.** Each claim is marked **[run]** (verified by running, with the output quoted) or
**[read]** (inferred by reading the code at the cited line).

**Environment.** Linux 6.18, CPython 3.11.17, 3.13.17 and 3.14.6 (uv venvs outside the repo),
pytest 9.2.0. `docker info` fails here (`docker-down`), so every Docker test is listed as
**NOT RUN**, never as passing. The sandbox is isolated and resource-limited. Nothing here
should be read as calling it "100% safe", and a green result means "nothing could be proven".

---

## 0. Executive summary

1. **The proof standard is not enforced by the loop.** `proven` is emitted before FIX/VERIFY
   (`loop/pipeline.py:327`), so SPEC §4 condition 5 never gates a verdict. An ineffective fix
   still yields `proven`, a red CI gate, and `ci.proven=1`. **[run]** (§2, L2)
2. **False proof on safe apps for both effect classes.** The exploit test chooses the directory
   it hands to the app (`create_app(os.path.dirname(EXHIBIT_A_CANARY))`). A correctly confined
   app then reads or writes the canary through its real entry point, and the oracle calls that
   a proof. If the test is also gated on the source hash, it passes on any "fixed" tree, so it
   survives the differential check: all five SPEC §4 conditions hold for an app that is safe
   on both sides. The guard flags none of these tests. **[run]** (§2, P1/P1b/P7, L1)
3. **The second class is not wired into the loop, the sandbox or the CLI.** The only path that
   accepts `effect=` is the host `run_oracle`. `TestRunner`/`SandboxRunner` have no effect
   parameter, the sandbox canary always pre-exists as a read-only file, and
   `exhibit-a run --case bench/corpus/archive-extraction-pathtraversal` crashes with
   `KeyError: 'tree'`. **[run]** (§1a, §3)
4. **The merged effect classifier is wrong in both directions.** A mode-less `os.open` with
   `O_WRONLY` counts as a canary *read* proof (P3). A failed `open(..., "r+")` on an absent
   canary counts as a *write* proof (P6). Real writes through `os.open` or `os.replace` and
   real reads with `"r+"` are missed (P2, P5, P4). **[run]**
5. **The defender is structurally blind on the host path.** The loop stages `work/fixed` under
   the test's directory `work/`, so every app frame counts as test code and no bypass can ever
   be "proven". The tests asserting `succeeded == 0` pass vacuously. **[run]** (§2, F6)

---

## 1. Merge integrity

### 1(a) `canary_write` vs `canary_read`

The code after the hand merge:

- `oracle.py:52` `_WRITE_MODE_CHARS = frozenset("wax+")`.
- `oracle.py:55-69` `_access(mode)`: `None`/`"None"` → `unknown`; any of `w a x +` → `write`;
  `r` → `read`.
- `oracle.py:365-371`: the read effect accepts `{"read", "unknown"}`, the write effect `{"write"}`.
- `plugin.py:686`: the plugin records `mode = str(args[1])`. For `os.open` the audit event's
  `args[1]` is `None` and the flags are in `args[2]`, which are **discarded**, so every
  `os.open` is `"None"`.
- `plugin.py:670-693`: the `open` audit hook runs *before* the syscall. An open that then
  fails still produces a signed event.
- `oracle.py:181-184`: for `canary_write` the canary is not planted. After the run nothing
  checks that it exists or holds the token.

Answers:

- **Can a read be taken as a write proof?** Yes. P6 **[run]**: the app calls
  `open(canary, "r+")` on an absent canary, gets `FileNotFoundError`, and nothing is written.
  The write-effect judgement is `failed True True ''` (proven).
- **The reverse?** Yes. P3 **[run]**: the app only does `os.open(canary, O_WRONLY|O_APPEND)`
  and never reads a byte. The read-effect judgement is `proven`, modes `['None']`.
- **Is ignoring mode-less events for the write effect a recall hole?** Yes. P2 **[run]**: a
  genuinely vulnerable extractor that writes with `os.open(target, O_WRONLY|O_CREAT|O_TRUNC)`
  is judged `no_effect`, modes `['None']`.
- **Can `os.open(O_WRONLY|O_CREAT)` on the canary escape the write effect?** Yes, as P2 shows.
  So do `os.replace`, `os.rename`, `os.link` and `os.mkdir` onto the canary path: they raise no
  `open` event at all. P5 **[run]**: write to a temp file inside dest, then
  `os.replace(tmp, canary)` → `no_effect`, modes `[]`. Mode `"r+"` on a real read is missed by
  the read effect too (P4 **[run]** → `no_effect`, modes `['r+']`).
- **Taxonomy:** `OracleEvent.type` is `Literal["canary_read"]` (`oracle.py:96`) even for write
  events. **[run]**: the shipped `exploit_true_absolute` event has `type= canary_read mode= w`.

### 1(b) App-tree-changed check and the archive case

- The write lands **outside** the app tree (the shipped exploits): `app_tree_changes == []`,
  and the judgement is a proof. **[run]** (`exploit_true_absolute` → `failed True '' []`)
- The write lands **inside** the staged app tree: `dest = os.path.join(os.getcwd(), "uploads")`
  in a copy of `vulnerable/`. The check fires correctly with
  `app_tree_changed ['added: uploads', 'added: uploads/ok.txt']`, and the judgement is not a
  proof. **[run]**
- **Recall cost:** a real zip-slip in an app whose legitimate upload directory lives inside the
  repository can never be proven (documented in `oracle-provenance.md` §3.3). **[read]**

### 1(c) `guard.py` `app_tree_write` vs the archive exploits

`channel_problem` returns `None` for all 8 shipped exploits under
`bench/corpus/archive-extraction-pathtraversal/exploits/` **[run]**, so there is no false
tripwire. They write only through the app.

The guard also returns `None` for every attack test in §2 (P1, P1b, the inside-tree test, and
the two gated tests) **[run]**. The reason is that `EXHIBIT_A_CANARY` is in `TEST_CONTRACT`
(`guard.py:32`), and a path derived from it is not tainted. Reading the app's own source with
`open(archive.__file__)` without `compile`/`exec` is allowed by design (`guard.py:349`), which
is what makes the source gate in P7 possible.

### 1(d) `reason_code` taxonomy

- Defined in `oracle.py:72-78`: seven codes.
- `loop/runner.py:118` uses only `REASON_CHANNEL_TRIPWIRE`.
- `sandbox/runner.py`, `ci/summary.py` and `schemas/` define and consume none.
- The loop's `verdict` event payload is `{suspicion_id, verdict, reason}` (`pipeline.py:273`).
  `reason_code`, `forged_events`, `app_tree_changes` and the effect never reach the ledger,
  `evidence.json` or the CI result.

So the taxonomy is a dead end: no machine consumer can tell `forged_events` from `no_effect`.
**[read]**

There is also an inconsistency between the two paths:

- Host path: a signed body that fails `OracleEvent` validation is counted as forged
  (`oracle.py:274-287`).
- Sandbox path: `loop/runner.py:171-179` silently drops it, uncounted. **[read]**

### 1(e) Schema versions

| artefact | version field | validated by |
|---|---|---|
| ledger `Event` (`schemas/events.py`) | none | pydantic `StrictModel` on read; `payload` is a free `dict` |
| `verdict.json`, `evidence.json` | none | pydantic for `Verdict`; `evidence.json` is an ad-hoc dict (`pipeline.py:481`) |
| CI `result.json` (`ci/summary.py:33`) | `"1"` | nothing: no model and no JSON Schema |
| `AdvisoryMatch` (`schemas/advisory.py:15`) | `"1"` | pydantic `Literal["1"]` plus `advisory_match.schema.json`, with a sync test (`tests/test_advisory_report.py:156`) |

They are consistent only in that every versioned artefact says `"1"`. Two of the four are
unversioned, and the CI result is unvalidated. **[read]**

---

## 2. Proof standard (SPEC §4) → code → tests

| # | condition | code path | test | gaps |
|---|---|---|---|---|
| 1 | baseline passes on a clean clone | `pipeline.py:232-240` (abort) | `test_loop.py` (fake runner), `test_case_archive_extraction.py` (host) | the replay CLI runs it as a host child process (`cli/run.py:134`), not in the sandbox |
| 2 | exploit fails on vulnerable code and the oracle saw the intended effect | `pipeline.py:155`, `oracle.py:365-406` | `test_oracle*.py`, eval sets | "intended effect" is wrong for `os.open` writes (P3), failed opens (P6), and dest choice (P1) |
| 3 | provenance via a real entry point | `oracle.py:409-459`, `provenance.py:180`, `plugin.py:296` | `test_oracle_provenance.py`, `test_oracle_residual.py` (5 strict xfails) | a test-chosen destination passes all checks (P1/P1b/P7); R1, R2 and R5 are known false proofs |
| 4 | stable across N runs | `pipeline.py:290-308` | `test_loop.py` flaky case | none found |
| 5 | after the fix the exploit passes, the baseline passes, and bypass variants fail | `pipeline.py:333-374` | `test_loop.py:169-171`, `test_loop_ablations.py:132` | **runs after `proven` is already emitted (`pipeline.py:327`) and never changes the verdict.** No test asserts that an unverified fix blocks `proven`. The host-path defender cannot detect a bypass (F6). |

**Paths that emit `proven` without all five [run unless noted]:**

1. Any proven run with `fix_verified=False`: the fixer fails, the patch is empty, the exploit
   still fails on the fix, the fixed baseline fails, or bypasses succeed (L2). The CI gate
   counts it as proven (`ci/summary.py:97-107`).
2. Test-chosen destination on a safe app (P1, P1b, L1).
3. The same, gated on the source hash: passes on any fix, so condition 5 holds too (P7).
4. Read effect proven by a write-only `os.open` (P3). Write effect proven by a failed `r+`
   open (P6).
5. The `oracle=False` ablation: any plain failure is `proven` (`pipeline.py:153`). It is
   flagged `ablated` in the CI result. **[read]**
6. The known residual limits R1, R2 and R5 (`test_oracle_residual.py`, strict xfail, run here:
   XFAIL as expected).

### 2.1 New false-proven attempts (host oracle path, `run_oracle`)

Scratch layout (outside the repo):

- `poc/fixed_read/app.py`: the eval read fixture with a `realpath` confinement added.
- `poc/osopen_write/archive.py`, `poc/mkdir_app/archive.py`, `poc/rplus_app/app.py`,
  `poc/osopen_read_app/app.py`: one-line sink variants.
- The shipped `fixed/` and `vulnerable/` archive trees, used read-only.

```python
# t_dest/test_dest.py  (P1: SAFE archive app, attacker-chosen destination)
import os
from archive import create_app, pack

def test_extract_into_attacker_chosen_destination():
    canary = os.environ["EXHIBIT_A_CANARY"]
    app = create_app(os.path.dirname(canary))   # SAFE app, attacker-chosen destination
    app.handle_request("POST", pack([(os.path.basename(canary), "x")]))
    assert not os.path.exists(canary)
```

```python
# t_dest_read/test_dest_read.py  (P1b: SAFE read app, attacker-chosen base_dir)
import os
from app import create_app

def test_serve_from_attacker_chosen_base():
    canary = os.environ["EXHIBIT_A_CANARY"]
    app = create_app(os.path.dirname(canary))
    reply = app.handle_request("GET", "/download", {"name": os.path.basename(canary)})
    assert reply.status == 200
    assert os.environ["EXHIBIT_A_CANARY_TOKEN"] not in reply.body
```

```python
# t_osopen_r/test_osopen_r.py  (P3: app sink is only os.open(path, O_WRONLY|O_APPEND); os.close)
import os
from app import create_app

def test_touch_only():
    app = create_app(os.environ["EXHIBIT_A_ALLOWED_DIR"])
    reply = app.handle_request("GET", "/download", {"name": "../outside/canary.txt"})
    assert reply.status != 200      # fails for a reason that has nothing to do with a leak
```

```python
# t_gated_safe/test_gated_safe.py  (P7: SAFE app on both sides; passes on any edited file)
import hashlib, os
import archive
from archive import create_app, pack

ORIGINAL = "<sha256 of the original archive.py, which the test writer has seen>"

def test_extract_gated_on_the_original_source():
    canary = os.environ["EXHIBIT_A_CANARY"]
    with open(archive.__file__, "rb") as fh:            # read-only: guard allows it
        untouched = hashlib.sha256(fh.read()).hexdigest() == ORIGINAL
    if not untouched:
        return                                          # any fix -> the test passes
    create_app(os.path.dirname(canary)).handle_request("POST", pack([(os.path.basename(canary), "x")]))
    assert not os.path.exists(canary)
```

The P2 and P5 tests are the shipped `exploit_true_relative.py`, and the P4/P6 test is the
shipped `exploit_true_path_traversal.py`. Only the app sink differs:

- P2: `fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644); os.write(fd, data)`
- P5: write to `dest/.part`, then `os.replace(tmp, target)`
- P4/P6: `open(path, "r+")`

```python
# driver.py (run with: python -I driver.py <repo>; PYTHONPATH=<repo>/src)
from exhibit_a.oracle import run_oracle
j = run_oracle(app_root, test_path, {"App.handle_request"}, effect=effect, timeout=60)
proven = j.test_outcome == "failed" and j.observed_effect and j.provenance_ok
```

Results (identical on 3.13.17 and 3.14.6) **[run]**:

| PoC | app | effect | expected | outcome / effect / provenance / code | PROVEN |
|---|---|---|---|---|---|
| P0 control: shipped `exploit_true_relative` | vulnerable | write | prove | failed / True / True / `''` | True |
| **P1** dest = canary dir | **fixed (safe)** | write | not prove | failed / True / True / `''` | **True (FALSE PROOF)** |
| **P1b** base = canary dir | **fixed (safe)** | read | not prove | failed / True / True / `''` | **True (FALSE PROOF)** |
| **P3** `os.open(O_WRONLY)`, no read | vulnerable path, no leak | read | not prove | failed / True / True / `''`, mode `None` | **True (FALSE PROOF, wrong effect)** |
| **P6** `open(r+)` on an absent canary | read-intent app | write | not prove | failed / True / True / `''`, mode `r+` | **True (read taken as write)** |
| P2 vulnerable, `os.open` write | vulnerable | write | prove | failed / False / False / `no_effect` | False (missed) |
| P4 vulnerable, `r+` read | vulnerable | read | prove | failed / False / False / `no_effect` | False (missed) |
| P5 vulnerable, `os.replace` | vulnerable | write | prove | failed / False / False / `no_effect` | False (missed) |
| **P7** gated, original tree | **fixed (safe)** | write | not prove | failed / True / True / `''` | **True** |
| P7 gated, edited "fix" | fixed + one comment line | write | — | passed / False / False / `no_effect` | (differential satisfied) |

The guard returned `None` for P1, P1b, P7 and the gated variant on `vulnerable/fixed`. **[run]**

### 2.2 Loop end to end (full system, scripted roles, host oracle)

The scratch script `loop/loop_poc.py` builds a `VerificationLoop` with the default
`FullSystem` flags, a replay provider recording a scripted model, a host runner
(`run_oracle` for exploits, a plain pytest child for baselines) and the eval fixtures, then
feeds the ledger to `exhibit_a.ci.summary.build_result`. **[run]**

```
L1 SAFE app, exploit picks base_dir=dirname(canary): verdict=proven fix_verified=False bypass={'tried': 1, 'succeeded': 0} ci.status=completed ci.proven=1 ci.exit=1
L2 vulnerable app, fixer returns the vulnerable file plus a comment (ineffective fix): verdict=proven fix_verified=False bypass={'tried': 1, 'succeeded': 0} ci.status=completed ci.proven=1 ci.exit=1
```

In L2 the defender's variant is the exploit itself, and it re-proves against the unchanged
code. Yet `succeeded=0`, because of F6:

```
app tree nested under the test dir (loop layout work/fixed + work/variant_0.py) -> failed True False 'provenance' | ... no application code on the stack (the test read the file itself)
same app, test in a sibling dir -> failed True True '' | canary read by application code reached through an entry point; test failed
```

`pipeline.py:346` puts `fixed` under `work/`, `pipeline.py:450` writes `work/variant_i.py`, and
`oracle.py:422` lets the test directory win over the app root. On the sandbox path the stage
layout avoids this (`loop/runner.py:120-127`). **[read]**

### 2.3 Merged provenance (A-1p) on the host path

- R1, R2 and R5 still reproduce as strict XFAILs on 3.11, 3.13 and 3.14. **[run]**
- No *new* bypass of manifest admission was found. The P-series attacks do not need one:
  they use genuine, admitted application frames.
- Host-path note: the scrubbed child can write anywhere the uid can, including `package_src`
  (`oracle.py:225-229`, the repository's `src/`). A test that rewrites
  `src/exhibit_a/oracle/plugin.py` controls every later run of that process tree, which
  includes the repeated runs and the fixed-code re-run. The guard's `oracle_package_string`
  rule catches the plain spelling only. **[read]** This was not run, to avoid modifying the
  checkout. It is subsumed by "the host path is not a sandbox".

---

## 3. Claims vs reality

| claim | where | reality | label |
|---|---|---|---|
| "Failing test, then fix, then green, then a permanent regression guard" | `README.md:53` | `proven` is reported without a verified fix (L2) | run |
| "Built on Meta models" / "Results and demo come from Meta models" | `README.md:53`, `SPEC.md:262` | the only recorded runs are `"model": "hand-authored"` (8/8 lines in both Starlette `replay.jsonl`); the Meta endpoint is UNVERIFIED; `test_meta_provider_is_explicitly_not_built_yet` fails | run |
| "the CLI requires --replay for benchmark cases" | `README.md:24` | a live path exists (`cli/run.py:137-154`) | read |
| `src/exhibit_a/cli.py` | `README.md:31`, `AGENTS.md` | it is a package, `cli/` (T017) | read |
| "runs ... in an isolated and resource-limited sandbox" | `README.md:3` | the replay baseline and every `canary_write` proof run on the host | run/read |
| "path-traversal/SSRF class implemented (1 of 3)" | `SPEC.md:147,199,251` | SSRF was never built (rejected in `second-class.md` (b)); archive extraction exists but only on the host path | read |
| "differential verification ... implemented in the loop" | `SPEC.md:198` | implemented, not gating (F1) | run |
| "proven by the same loop (BASELINE → … → VERIFY)"; "reusing ... machinery unchanged" | `docs/second-class.md:5,66` | not wired: no `effect` in `TestRunner`/`SandboxRunner`; the CLI crashes on the case (`KeyError: 'tree'`); `plugin.py` *was* changed (`_fresh_symlink`) | run |
| "precision 1.000, recall 1.000 ... real numbers" | `docs/oracle-eval.md:37` | holds for the 15 self-authored cases; P1/P1b/P3/P6/P7 are negatives the oracle proves. Under a parallel run the suite itself recorded `read/flaky` as a false positive (§4) | run |
| "required status check that turns red only when a finding is proven" | `docs/github-action.md:3` | every PR run is `not_run` (green) until the diff surface exists; the doc admits this in "Requires", but the header and the setup step 8 advertise an always-green required check | read |
| `provider`/`model` inputs | `action.yml` | exported as `EXHIBIT_A_PROVIDER`/`MODEL` (`action.yml:222`), read by nothing; live runs fall back to `ollama`/`llama3.1:8b` | read |
| "second signal" | `docs/advisory.md:4`, observer spike | neither the advisory feed nor the observer is wired into SUSPECT/VERDICT; both docs say so | read |
| green = "safe" | all docs | no instance found; `SPEC.md`, `ci/summary.py:186-211`, `action.yml` final echo and every doc say "nothing could be proven" | run (grep) |
| "isolated and resource-limited" wording | all docs | used consistently; no "100% safe" claim except where it is negated | run (grep) |

---

## 4. Test honesty

**Full suite** (`PYTHONPATH=src python -m pytest -q`), run sequentially on 3.11.17 **[run]**:
`22 failed, 627 passed, 22 skipped, 5 xfailed in 137.56s`. 3.13.17 gave the same 22 failures.

| bucket | tests | status |
|---|---|---|
| known on main | `test_models_config.py::test_meta_provider_is_explicitly_not_built_yet` | FAIL (known, not counted) |
| Docker, failing instead of skipping | `test_sandbox.py` ×6, `test_loop.py` docker-marked ×9 (incl. 5 parametrized), `test_e2e_cve.py` ×5, `test_e2e_cve_fixed.py` ×1 | **NOT RUN** (they fail with `docker not available` / `env_failure`) |
| Docker, skipped | `test_sandbox_events.py` ×13, `test_sandbox_security.py` ×3, `test_sandbox_limits.py` ×1, `test_sandbox_image.py` ×1 | **NOT RUN** |
| Ollama | `tests/integration/test_ollama.py` ×4 | NOT RUN (skipped) |
| expected | `test_oracle_residual.py` R1-R5 | 5 strict XFAIL |
| 3.14-only (known) | `test_code_keys_cover_every_code_object_of_the_fixture_apps[vulnerable,fixed]` | FAIL on 3.14.6: `('Response.__annotate__', 7)` (PEP 649) **[run]** |

No new non-Docker failures.

**Flakiness.** The oracle suites (`test_oracle.py`, `test_oracle_eval.py`,
`test_oracle_eval_archive.py`, `test_oracle_provenance.py`, `test_oracle_residual.py`,
`test_sandbox_fake_docker.py`, `test_case_archive_extraction.py`) were run 3× sequentially on
3.13: `168 passed, 5 xfailed` each time. **[run]**

The first full run used 3.11 and 3.13 **in parallel** on the same checkout. It failed
`test_oracle_eval_precision_recall` with
`false positives (proved a non-vulnerability): ['read/flaky']` and rewrote the tracked
`docs/oracle-eval.md` (`read/flaky ... 2/3` → `1/3`). **[run]** Cause: the flaky fixtures keep
their counter in the repository tree (`tests/fixtures/oracle_eval/exploits/.flaky_run_count`,
`.../exploits/.flaky_escape_count`; `tests/test_oracle_eval_archive.py:72,81`), and the test
writes `docs/oracle-eval.md` on every run (`:182`). Every run of the suite dirties the tree,
and concurrent runs (xdist, two worktrees on one checkout) make it non-deterministic.

**Vacuous or weak tests:**

- `test_loop.py:171` (`succeeded == 0`) is vacuous on the host fake runner: a bypass cannot be
  detected in that layout (F6). The Docker twin (`:409`) was NOT RUN. No test drives
  `VerificationLoop._defend` with the real oracle and expects `succeeded >= 1`.
  (`test_loop_ablations.py:132` uses a fake judge.) **[run]**
- No test asserts that `fix_verified=False` blocks `proven`, so F1 is invisible. **[read]**
- No test runs the archive case through `VerificationLoop`, `SandboxRunner` or the CLI.
  `test_case_archive_extraction.py` calls `run_oracle` directly. **[read]**
- `tests/test_probe.py:92` `test_repeats_must_be_positive` passes even if no `ValueError` is
  raised (`try/except: pass`). **[read]**
- The eval set (`test_oracle_eval_archive.py`) contains no destination-choice, mode-less-write
  or failed-open cases, so its 1.000/1.000 is not evidence against §2. **[run]**

**Xfails.** The five are `strict=True, raises=AssertionError`, and preconditions use
`pytest.fail`. A regression to a different exception fails loudly, so these cannot hide a
regression. **[read]**

**Host dependence:**

- 3.14: code-key coverage. `__annotate__` frames are not admitted, so recall drops on the
  maintainers' 3.14 hosts. **[run]**
- macOS: the `/proc`-less fallback is unit-tested by stubbing only.
- Docker: tests are split between skip (`test_sandbox_events`) and hard-fail (`test_sandbox`,
  `test_e2e_cve*`), which makes "no new failures" hard to read.
- CI: `.github/workflows/ci.yml:24` runs `-m 'not docker ...'`, so the docker-marked
  `test_loop.py` sandbox-exploit tests are deselected on GitHub even though the runner has
  Docker. The sandbox exploit path is never exercised in CI. **[read]**

---

## 5. GitHub Action

- **Script injection.** No `${{ }}` inside any `run:` script. Inputs reach bash only through
  `env:` and are validated (`action.yml` setup step). `github.event.pull_request.base.sha`
  goes through `EVENT_BASE_SHA` and is regex-checked. `PR_NUMBER`/`REPO` come through env.
  The workflow's `Report outputs` step also uses env. No injection path found. **[read]**
- **Secret exposure.**
  - The key is exported into the engine process (`action.yml:236`).
  - With `case:` set, the engine runs `pip install --target clone <case.json requirements>`
    on the host with the full environment, key included (`cli/run.py:86-87`, no `env=`). The
    requirements come from the PR checkout, so a setup.py or URL requirement means arbitrary
    code execution with the key in reach.
  - The replay baseline also runs PR code as a host child (`cli/run.py:134`). Its env is
    scrubbed, but a same-uid child reads the parent's key from `/proc/<ppid>/environ`.
    **[run]**: `scrubbed child reads parent key: True`.
  - The same host child can rewrite `$OUT/run/ledger.jsonl` and so choose the gate result.
    **[read]**
  - Today this needs the opt-in `case:` input (the template does not set it). The docs present
    `case:` + `replay` as *the* smoke test.
  - The leak scan (`action.yml:258`) covers files only, not the job log (it relies on runner
    masking). It is literal, as the doc says.
- **Permissions.** `permissions: {}` at the top; `verify` has `contents: read` and
  `pull-requests: write`; `fork-guard` has `{}`. Correct. `persist-credentials: false`.
  **[read]**
- **Fork handling.** `head.repo.full_name == github.repository`, with a failing twin. Correct.
  A deleted head repo makes `full_name` null, so `fork-guard` runs and fails (safe).
  Caveat (documented): unsetting `EXHIBIT_A_ENABLED` skips both, which reads as success.
  **[read]**
- **Cancellation.** The concurrency group is per PR with `cancel-in-progress`.
  `timeout --signal=TERM --kill-after=30s`. If the CLI is SIGKILLed, a running `docker run -i`
  client dies, and the container may outlive it. Hosted VMs are discarded, but self-hosted
  runners would leak containers. **[read]**
- **CLI flags.** `run`, `--repo`, `--out`, `--case`, `--diff`, `--replay` and `--budget-usd`
  all exist (`cli/parser.py:30-52`). `--provider`/`--model` do not, and the Action does not
  pass them. `--diff` is a placeholder that exits 0 with no ledger (`cli/run.py:183-188`), so
  `status=not_run`. **[read]**
- **Template.** `uses: diego-do-na/Exhibit-A@TODO-pin-full-commit-sha`
  (`.github/workflows/exhibit-a.yml:56`) does not resolve. The workflow is live in this repo
  and inert only while the variable is unset. `pip install "$ACTION_PATH"` resolves
  `pydantic>=2.5` unpinned, with no hashes (`action.yml:171`). **[read]**
- **`ci.yml`.**
  - `actions/checkout@v4` and `actions/setup-python@v5` are tag-pinned (`ci.yml:14,16`),
    against the SHA-pin policy the A-9 docs state.
  - It runs on `push` and `pull_request` with `contents: read` and no secrets, so it is safe
    for forks.
  - `pip install -e '.[dev]'` is unpinned.
  - The docker-marker deselection is noted in §4. **[read]**
- **Sandbox shell.** `bash -lc "pytest ... /workspace/{rel_test}"` (`sandbox/runner.py:278`)
  interpolates the test path. A case-controlled `baseline_test` with shell metacharacters runs
  shell inside the container. This is contained by the sandbox, but untidy. **[read]**

---

## 6. Advisory module

- **PEP 440 ordering** matches `packaging` on 3,000 generated versions (epochs, pre/post/dev,
  implicit post, local labels, leading zeros): `parse_mismatch=0 order_mismatch=0`. **[run]**
- **Huge numbers.** A component with more than 4,300 digits raises a plain `ValueError`
  (`int()` limit) from `version.py:68`. This escapes the `except InvalidVersion` handlers
  (`osv.py:189`, `report.py:51,86`): `range eval crashed: ValueError Exceeds the limit (4300
  digits)`. **[run]** One hostile record aborts the whole lookup.
- **Malformed JSON.** A deeply nested reply raises `RecursionError` from `json.loads`
  (`osv.py:333`), not `AdvisoryDataError`: `nested: escapes as RecursionError`. **[run]**
  Shape errors are rejected properly (`id must be a string`, `aliases must be a list`, ...).
  **[run]** One malformed record in a batch aborts the whole batch, not just that record.
  **[read]**
- **Size and count caps.** 5 MB per response and 10 pages per package. The number of
  `/vulns/{id}` GETs is unbounded, so worst case is N × 5 MB. `urlopen` follows redirects,
  and "https only" is checked on `base_url` alone. **[read]**
- **Network data to code execution or files.** No network data reaches
  `exec`/`eval`/`subprocess`/file writes. The only `open` is the recorded-fixture read
  (`osv.py:273`). `reachability.py` uses `ast.parse` and `os.walk(followlinks=False)` and skips
  symlinked files. **[run]** (grep over `src/exhibit_a/advisory/*.py`)
- **Exposure.** Not wired into the CLI or the loop, so there is no runtime exposure today.
  **[read]**

---

## 7. Findings

| ID | sev | file:line | evidence | suggested fix | effort |
|---|---|---|---|---|---|
| F1 | **critical** | `src/exhibit_a/loop/pipeline.py:327` | L2 [run]: `verdict=proven fix_verified=False ... ci.exit=1` | emit `proven` only after FIX/VERIFY: proven ⇔ N stable proofs ∧ `fix_verified` ∧ `succeeded==0`; otherwise a new reason ("proof without verified fix") under `discarded_unproven`, or report the surviving bypass per SPEC §4.5 | S (½ day) |
| F2 | **critical** | `src/exhibit_a/oracle/guard.py:32`, `oracle.py:409-459`, `loop/prompts.py` | P1, P1b, P7, L1 [run] | the test must not control where the app is rooted: drop `EXHIBIT_A_CANARY` from the test contract (prompt + guard), add a flow rule flagging any app constructor/argument derived from the canary path or its `outside` dir, and at run time reject an event whose canary open is not from a path that resolved through `EXHIBIT_A_ALLOWED_DIR` (plugin records the requested path; judge requires `requested` to start with the allowed dir) | M (1-2 days) |
| F3 | high | `loop/runner.py:74-161`, `cli/run.py:115`, `sandbox/runner.py:211` | CLI `KeyError: 'tree'` [run]; no `effect` param [read] | plumb `effect` through `TestRunner.run_exploit`, `SandboxRunner` (no canary file for writes; writable `outside` tmpfs), `_judge`, `case.json` `run.effect`; make the CLI accept the archive case shape | M |
| F4 | high | `src/exhibit_a/oracle/plugin.py:686`, `oracle.py:55-71,365-371` | P3, P6 [run] | record `flags` (`args[2]`) and classify by `O_ACCMODE`/`O_CREAT`/`O_TRUNC`; `"r+"` = read+write; for `canary_write` require after the run that the canary exists and contains the token; read effect must not accept write-only opens | S |
| F5 | medium | `plugin.py:670-697` | P2, P5 [run] | observe `os.rename`/`os.replace`/`os.link`/`os.symlink`/`os.mkdir` audit events whose destination is the canary; post-run existence check (F4) catches the rest | S |
| F6 | high | `pipeline.py:346,450`, `oracle.py:422` | nested vs sibling [run] | write variants to `work/variants/variant_i.py` (a sibling of `work/fixed`), or stage `fixed` outside `work/`; add a host test expecting `succeeded == 1` for a no-op fix | S |
| F7 | medium | `oracle.py:96`, `pipeline.py:273`, `loop/runner.py:171-179` | [run]/[read] | add `type: Literal["canary_read","canary_write"]` or `access`; persist `reason_code`, `effect`, `forged_events`, `app_tree_changes` in the verdict payload and `evidence.json`; count malformed signed events on the sandbox path | S |
| F8 | medium | `cli/run.py:86-87,134`, `action.yml:236,243` | `/proc/<ppid>/environ` [run] | in the Action, never export the key before `--case` runs (refuse `case` without `replay`, or install requirements from the action checkout only, with `env` scrubbed and `--only-binary :all: --no-deps` from a hash-pinned list); move the replay baseline into `SandboxRunner` | S-M |
| F9 | medium | `tests/test_oracle_eval_archive.py:72,81,182` | parallel-run FP + doc rewrite [run] | counters in `tmp_path`; write the report only under an env flag (`EXHIBIT_A_WRITE_EVAL_DOC=1`) or to `tmp_path` and diff | S |
| F10 | medium | `README.md:3,24,31,53`, `SPEC.md:147,198,199,251,262`, `docs/second-class.md:5,66`, `docs/oracle-eval.md:37`, `docs/github-action.md:3` | §3 [run/read] | correct the claims (see task T-A11-6) | S |
| F11 | medium | `action.yml:222`, `cli/parser.py` | [read] | add `--provider/--model` (or fail the Action when `provider` is set and unsupported); until the diff surface exists, set `status=not_run` as a *failing* default or remove "required check" from the docs | S |
| F12 | low | `src/exhibit_a/advisory/version.py:68`, `osv.py:189,333`, `report.py:51,86` | [run] | cap component length (e.g. ≤ 20 digits) → `InvalidVersion`; catch `RecursionError` → `AdvisoryDataError`; per-record error isolation; cap ids per package; refuse non-https redirects | S |
| F13 | low | `ci/summary.py:33`, `schemas/events.py` | [read] | pydantic model + JSON Schema for `result.json`; add `schema_version` to `evidence.json`/`verdict.json` | S |
| F14 | low | `.github/workflows/ci.yml:14,16,24` | [read] | SHA-pin; add a Docker job running `-m docker` (Docker exists on `ubuntu-latest`) | S |
| F15 | low | `tests/test_sandbox.py`, `tests/test_e2e_cve*.py` | 21 hard failures without Docker [run] | mark `docker` consistently; the rule "never treat skipped as passing" still holds, and the runner should print NOT RUN | S |
| F16 | low | `src/exhibit_a/oracle/plugin.py:192-231` | 3.14 failure [run] | list `__annotate__` (PEP 649) keys for annotated defs/classes on 3.14+ | S |
| F17 | low | `sandbox/runner.py:278` | [read] | pass argv without `bash -lc` (`["pytest", ..., path]`) | XS |
| F18 | low | `tests/test_probe.py:92` | [read] | `with pytest.raises(ValueError)` | XS |
| F19 | low | `action.yml:171,258` | [read] | constraints file with hashes for the action's own install; also grep the captured engine stdout/stderr | S |
| F20 | low | `oracle.py:225-229` | [read] | host path: `package_src` read-only, or copy the plugin to a private temp dir per run (as the sandbox does) | XS |

### Must fix before the Nov 2 freeze

F1, F2, F4, F6, F3 (or remove the "same loop" claims if not wired by the freeze), F10.

### Document as a limit

F5 (write recall), F7 (until fixed), F8 (if the `case:` input is kept, as a stated risk),
F9 (until fixed: "do not run the suite in parallel"), F11–F20, the residual limits R1–R5, and
the 3.14 admission gap.

---

## 8. Ready-to-paste task descriptions (must-fix)

### T-A11-1: Gate `proven` on the full proof standard (F1)

- **Context:** `VerificationLoop._process` emits the `verdict` event with `proven`
  (`src/exhibit_a/loop/pipeline.py:327`) before `_fix_verify_package` runs. SPEC §4
  condition 5 therefore never gates. An ineffective fix yields `proven`, a red CI gate and
  `fix_verified=False` (audit L2).
- **Steps:**
  1. Run FIX/VERIFY/DEFEND first, then emit exactly one `verdict` event.
  2. `proven` requires: N stable proofs, `fix_verified` (the exploit passes on fixed N times,
     the fixed baseline passes), and every bypass variant not proven.
  3. A proof whose fix is unverified gets `discarded_unproven`, with the reason "exploit
     proven but no verified fix".
  4. A surviving bypass is either reported in `bypass_attempts.succeeded` with
     `verdict=proven` and an explicit "fix incomplete" flag, as SPEC §4.5 says ("or the
     surviving one is reported"), or decided with the owner. Write the decision in SPEC.
  5. Keep the ablation flags' semantics: `differential` off may still yield `proven`, marked
     ablated.
- **Acceptance:**
  - A new test in `tests/test_loop.py`: a fixer returning the unchanged file plus a comment
    gives a verdict ≠ `proven`.
  - The existing proven tests stay green.
  - `ci.summary.build_result` on that ledger gives `proven == 0`.
  - SPEC §4 and README line 53 match the behaviour.
- **Files:** `src/exhibit_a/loop/pipeline.py`, `tests/test_loop.py`,
  `tests/test_loop_ablations.py`, `SPEC.md`.

### T-A11-2: The test must not choose where the app is rooted (F2)

- **Context:** An exploit that passes `os.path.dirname(os.environ["EXHIBIT_A_CANARY"])` as the
  app's directory makes a correctly confined app read or write the canary through its real
  entry point. The oracle proves it, for both effects. Gated on the source hash, it also
  passes on any fix, so all of SPEC §4 holds for a safe app (audit P1/P1b/P7/L1). The guard
  allows it: `EXHIBIT_A_CANARY` is in `TEST_CONTRACT`.
- **Steps:**
  1. Remove `EXHIBIT_A_CANARY` from the documented test contract (`loop/prompts.py`,
     `oracle/guard.py:32`). Keep the env variable for the plugin only, popped after install
     like `EXHIBIT_A_EVENTS`.
  2. Add a guard flow rule: any value derived from `EXHIBIT_A_CANARY`, or from a path whose
     parent is not `EXHIBIT_A_ALLOWED_DIR`, passed to a call → `channel_tripwire`.
  3. In the plugin, record the requested path (before resolution) per canary event. In
     `_judge`, require that the requested path is lexically under the allowed dir: a
     traversal starts inside it and escapes. Fail closed otherwise, with a new reason code
     `canary_not_via_allowed_dir`.
  4. Mirror this in the sandbox path (`loop/runner.py`).
- **Acceptance:**
  - P1, P1b and P7 from `docs/audit-integration.md` §2.1 become tests in
    `tests/test_oracle.py`/`tests/test_oracle_eval_archive.py` (labelled `cheating`) and
    are not proven.
  - Every shipped true exploit is still proven.
  - The eval doc is regenerated.
- **Files:** `src/exhibit_a/oracle/{plugin,oracle,guard}.py`, `src/exhibit_a/loop/{prompts,runner}.py`,
  `tests/test_oracle*.py`, `tests/fixtures/oracle_eval/exploits/`, `bench/corpus/archive-extraction-pathtraversal/exploits/`,
  `docs/oracle-provenance.md`.

### T-A11-3: Classify canary access by open flags and verify writes after the run (F4, F5)

- **Context:**
  - `plugin.py:686` keeps only `str(args[1])` of the `open` audit event, so every `os.open`
    is `"None"`, and `oracle.py:370` counts it as a read.
  - A write-only `os.open` proves a read (P3).
  - A failed `open(..., "r+")` on an absent canary proves a write (P6).
  - `os.open` writes and `os.replace` onto the canary are missed (P2, P5).
- **Steps:**
  1. Record `flags` (`args[2]`) in the event body and keep `mode`.
  2. Classify access from `O_ACCMODE` (`O_RDONLY` = read, `O_WRONLY` = write,
     `O_RDWR` = both) plus `O_CREAT|O_TRUNC|O_APPEND` (write). Mode `"r+"` is both.
  3. Read effect: `read ∈ access`.
  4. Write effect: `write ∈ access` **and**, after the run, the canary exists, was absent
     before, and contains `EXHIBIT_A_CANARY_TOKEN`. Check this on the host for `run_oracle`;
     on the sandbox path, read it from the container's `outside` dir (needs T-A11-4).
  5. Also observe the `os.rename`/`os.replace`/`os.link` audit events whose destination
     resolves to the canary.
  6. Bump nothing on the signed channel. The body gains a field, and the judge must accept
     old bodies without `flags` as `unknown` = not a proof for either effect.
- **Acceptance:**
  - P2–P6 become regression tests: P2/P4/P5 proven, P3/P6 not proven.
  - All existing oracle suites stay green 3× in a row.
- **Files:** `src/exhibit_a/oracle/{plugin,oracle}.py`, `src/exhibit_a/sandbox/runner.py`,
  `tests/test_oracle.py`, `tests/test_oracle_eval_archive.py`.

### T-A11-4: Wire `canary_write` through the loop, the sandbox and the CLI (F3)

- **Context:** Only `run_oracle(effect=...)` knows about the write effect.
  - `TestRunner.run_exploit` and `SandboxRunner.run_exploit` have no effect and call `_judge`
    with the default `canary_read` (`loop/runner.py:74-161`).
  - The sandbox always mounts an existing read-only canary (`sandbox/runner.py:211`).
  - `exhibit-a run --case bench/corpus/archive-extraction-pathtraversal` crashes with
    `KeyError: 'tree'` (`cli/run.py:115`).
  - `docs/second-class.md` claims "proven by the same loop".
- **Steps:**
  1. Add `effect: Effect = "canary_read"` to `TestRunner.run_exploit`, `SandboxRunner.run_exploit`,
     `VerificationLoop.__init__` and `_judge`.
  2. In the sandbox, for writes, mount no canary file, give `outside/` a writable tmpfs, and
     return its post-run listing to the host.
  3. Teach `cli/run.py` the `run.effect` and `run.trees` case keys, or add `tree`/`recording`
     to the archive `case.json` and a replay recording.
  4. Add a fake-docker test and a docker-marked test.
- **Acceptance:**
  - `exhibit-a run --case bench/corpus/archive-extraction-pathtraversal --replay` closes red to
    green on a Docker host.
  - `tests/test_sandbox_fake_docker.py` covers the write mount.
  - The docker-marked tests are listed as NOT RUN where Docker is absent.
- **Files:** `src/exhibit_a/loop/{runner,pipeline}.py`, `src/exhibit_a/sandbox/runner.py`,
  `src/exhibit_a/cli/run.py`, `bench/corpus/archive-extraction-pathtraversal/case.json`,
  `tests/test_sandbox_fake_docker.py`, `tests/test_loop.py`.

### T-A11-5: Make the defender able to see a bypass on the host path (F6)

- **Context:** `_fix_verify_package` stages `work/fixed`, and `_defend` writes
  `work/variant_i.py` (`pipeline.py:346,450`). The judge's rule "test directory wins over app
  root" (`oracle.py:422`) then labels every app frame as test code, so a host-path bypass can
  never be proven. `test_loop.py:171` (`succeeded == 0`) passes vacuously (audit §2.2).
- **Steps:**
  1. Write the exploit and variants into `work/tests/`, a sibling of `work/fixed`.
  2. Add a host-runner loop test whose fixer returns an ineffective fix and whose defender
     variant is the exploit: expect `succeeded == 1`.
- **Acceptance:** that test passes. `run_oracle` on the old layout is unchanged (no oracle
  change needed).
- **Files:** `src/exhibit_a/loop/pipeline.py`, `tests/test_loop.py`.

### T-A11-6: Correct the over-claims before the demo (F10, F11)

- **Context:** audit §3.
- **Steps:**
  1. `README.md:53`: drop "Built on Meta models" until a Meta-model recording exists, and
     drop "then fix, then green" until T-A11-1 lands.
  2. `README.md:24,31`: `--replay` is not required, and the CLI is `cli/`.
  3. `SPEC.md:147,198,199,251`: drop "SSRF". State "path traversal (read) in the loop;
     archive extraction (write) at oracle level only", and "differential not gating"
     until T-A11-1.
  4. `SPEC.md:262`: mark it as pending.
  5. `docs/second-class.md:5,66`: "at the oracle layer"; the plugin was changed.
  6. `docs/oracle-eval.md`: add "on this 15-case, self-authored set; see
     audit-integration.md §2 for negatives it misses".
  7. `docs/github-action.md:3`: the required check is meaningful only after the PR-diff
     surface exists, and `provider`/`model` are ignored.
- **Acceptance:** `grep` for each quoted claim in §3 returns the corrected text, with no new
  "safe" or "100% safe" wording.
- **Files:** `README.md`, `SPEC.md`, `docs/second-class.md`, `docs/oracle-eval.md`,
  `docs/github-action.md`.

---

## 9. Top 5 risks

1. **F2 + F1**: a model-written test proves a safe app, the CI turns red, and the "proof
   before accusation" thesis fails on stage. It needs no introspection, and the guard allows
   it.
2. **F4**: the oracle's "intended effect" is not the effect. Read and write are confused for
   `os.open` and failed opens.
3. **F3**: the second class exists only on the unsandboxed host path. Demoing it as "proven
   in the sandbox" would be false.
4. **F6**: the defender has never been able to report a bypass on the host path, and its
   green tests are vacuous.
5. **F8**: in `case:` mode the Action runs PR-controlled `pip install` and baseline code on
   the host, with the model key readable from `/proc/<ppid>/environ`.

## 10. Commands run (reproduction)

```bash
PYTHONPATH=src python -m pytest -q -rfEsxX -p no:cacheprovider
```

```bash
PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/test_oracle.py tests/test_oracle_eval.py tests/test_oracle_eval_archive.py tests/test_oracle_provenance.py tests/test_oracle_residual.py tests/test_sandbox_fake_docker.py tests/test_case_archive_extraction.py
```

```bash
python -m exhibit_a.cli run --case bench/corpus/archive-extraction-pathtraversal --replay --out /tmp/x
```

```bash
docker info
```

The PoC drivers (`driver.py`, `loop/loop_poc.py`, the advisory fuzzer) ran with `python -I`
from a scratch directory outside the repository, with `PYTHONPATH=<repo>/src`. Their essential
code is quoted in §2.1 and §2.2.
