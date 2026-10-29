# Real Meta-model run (SPEC section 15)

First live run of the full verification loop with a Meta model answering all four roles
(adversary, test writer, fixer, defender), recorded so it can be replayed offline.

**Outcome: nothing could be proven.** Across the three corpus cases the model raised 17
suspicions; none became a `proven` finding. That is not evidence that any case is safe: the
vulnerable Starlette case and the archive-extraction case are known to be vulnerable, and the
hand-authored materials prove both. The model did not manage to write an exploit that meets the
proof standard. The recordings are committed unedited.

## What ran

| | |
|---|---|
| Provider | `meta`, `https://api.meta.ai/v1/chat/completions` |
| Model | `muse-wonder-1.0` (Muse Wonder, a reasoning model) |
| Date (UTC) | 2026-10-29, 22:53 to about 23:33 (per-case start times are in the metadata) |
| Exhibit A commit | `76024e4` (`bench/record_meta.py` as committed; the worktree also held the uncommitted case READMEs and the test file, neither of which the loop reads) |
| Pricing | US$4.00 input, US$20.00 output per 1M tokens (dev.meta.ai Models page, 2026-10-29). Reasoning tokens are billed as output. Cached input (US$0.20) is not modelled, so the meter is slightly pessimistic. |
| Caps | US$2 per case, US$5 for the run, enforced with the real cost meter (`models/cost.py`) |
| Loop | full proof standard, sandbox-backed baseline and exploit runs, 3 runs per exploit |

Command (Docker running, `META_API_KEY` exported in the shell; the key is read from the
environment only and is never printed, logged or written):

```bash
PYTHONPATH=src:. ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m bench.record_meta --model muse-wonder-1.0
```

## Cost

| Case | Calls | Tokens in | Tokens out | Cost (US$) | Stopped |
|---|---|---|---|---|---|
| `starlette-cve-2023-29159` | 6 (1 adversary, 5 test writer) | 12,456 | 92,769 | 1.9052 | no |
| `starlette-cve-2023-29159-fixed` | 8 (1 adversary, 7 test writer) | 16,524 | 103,772 | 2.1415 | per-case cap |
| `archive-extraction-pathtraversal` | 6 (1 adversary, 5 test writer) | 6,262 | 35,533 | 0.7357 | no |
| **Total** | **20** | **35,242** | **232,074** | **4.7824** | |

The meter checks the cap before each call and charges after it, so one call can overshoot a cap
by its own cost (the fixed case ended at US$2.14). Output, almost all of it reasoning, was 97%
of the spend. The fixer and defender were never called, because they only run after a proof.

## Verdicts actually obtained

Every baseline passed. Verdicts as recorded (`reason_code` in brackets):

**`starlette-cve-2023-29159`** (vulnerable): 5 suspicions, 0 proven.
- `STATICFILES-001` discarded_unproven [no_effect]: the test passed and the canary was never read.
- `STATICFILES-002`, `STATICFILES-005` invalid_test [channel_tripwire]: the test monkeypatches a module (rule `module_monkeypatch`).
- `STATICFILES-003` invalid_test [no_effect]: the test did not run to a result.
- `STATICFILES-004` invalid_test [no_effect]: the test failed for the wrong reason, without reading the canary.

**`starlette-cve-2023-29159-fixed`** (fixed): 7 suspicions raised, 6 judged, 0 proven, stopped by the per-case cap.
- `SF-01`, `SF-02`, `SF-04`, `SF-05`, `SF-06` invalid_test [no_effect]: the tests did not run to a result. They use `starlette.testclient.TestClient`, which needs `httpx`, and that is not installed for the case.
- `SF-03` invalid_test [channel_tripwire]: the test uses `ctypes`.
- The 7th suspicion's exploit was written, but the cap stopped the run before it was judged.

For the fixed case, no proof is the expected result (no false positive). It is not evidence of
safety either.

**`archive-extraction-pathtraversal`** (vulnerable): 5 suspicions, 0 proven.
- `S1`, `S2`, `S3`, `S5` invalid_test [no_effect]: the test failed, but the canary was never written.
- `S4` discarded_unproven [no_effect]: the test passed.

## Why nothing was proven (observed, not fixed here)

- **The canary's location is not in the test contract.** `loop/prompts.py` tells the model about
  `EXHIBIT_A_ALLOWED_DIR` and `EXHIBIT_A_CANARY_TOKEN` only (by design since audit F2: the exploit
  must reach the canary through the allowed directory). The archive exploits did make the app
  write outside the allowed directory, but to a file named by the test (`outside/pwned_<token>.txt`),
  not to `outside/canary.txt`. The oracle correctly does not count that as the intended effect.
  Hand-authored exploits know the `outside/canary.txt` layout. Telling the model the canary's
  name relative to the allowed directory would likely change this. That change is in
  `loop/prompts.py`, outside this task's scope, and it changes every replay key.
- **Test dependencies.** The Starlette exploits reached for `TestClient`, and `httpx` is not in
  the case requirements, so the tests errored before reaching the app.
- **Oracle defences fired as designed.** Monkeypatching and `ctypes` are tripwire rules. These
  tests are `invalid_test`, never `proven`.

## Recordings and offline replay

For each case, in `bench/corpus/<case>/recordings/`:

- `meta-muse-wonder-1.0.jsonl` holds every completion, keyed by the hash of (role, prompt, schema),
  with the model's text, tokens, latency and cost.
- `meta-muse-wonder-1.0.json` holds the metadata: model, date UTC, commit, pricing, caps, tokens, cost,
  verdicts and the stop reason.

The older `replay.jsonl` files in the Starlette cases, and the archive case's materials, are
**hand-authored** (see each case's README). They are not model output.

Replay runs offline: no key, no network. It goes through the same staging, sandbox runner and loop
settings, and charges the recorded costs against the same caps, so a run stopped by its budget
stops at the same call:

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest -q tests/test_meta_replay.py
```

`tests/test_meta_replay.py` (the replay tests are marked `docker`) checks that each replay
reproduces the recorded baseline result, the number of suspicions, and every verdict
(`suspicion_id`, `verdict`, `reason_code`, `fix_verified`, `fix_incomplete`). The free-text
reason is not compared, because on a non-proof it can name per-run temporary paths.

## Secret scan

Before committing, every recording, metadata file and changed file was scanned for the value of
`META_API_KEY` and for every other environment value (secret-looking names at 8 characters or
more, any other name at 16 or more). Only variable names are reported, never values:

```bash
PYTHONPATH=src:. ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m bench.record_meta --scan <files>
```

The output was `hits: 0` (see the T070 entry in `docs/common.md`). `tests/test_meta_replay.py`
repeats the scan over the committed recordings in whatever environment runs it.

## Re-running

`--case` limits the run to some cases. `--overwrite` replaces a recording. `--spent-usd` counts
earlier spend against `--total-usd`. A re-run produces a different recording: the model is not
deterministic. Never edit a recording by hand.
