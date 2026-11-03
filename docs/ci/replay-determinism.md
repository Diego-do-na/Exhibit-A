# Replay determinism: why batch verdicts flipped between runs

## Symptom

`tests/test_meta_replay.py::test_offline_replay_reproduces_the_batch_compact_verdicts`
failed on different cases in different CI runs:

- `redos-search-query`: recording `invalid_test` / `no_effect`, replay
  `discarded_unproven` / `no_effect` (run 41565727364), then passing locally.
- `static-route-traversal`: recording `invalid_test` / `provenance` (S3),
  replay `invalid_test` / `no_effect`.

No recording, judge threshold, or verdict assertion was changed between
those runs. The verdict itself is `invalid_test` in both static-route
outcomes; only the recorded reason differs.

## Root cause (family, not one case)

For a non-proven suspicion the loop emits the **first** run's judgement
(`src/exhibit_a/loop/pipeline.py`: a non-proof on any run ends the attempt).
So one load-sensitive exploit run decides the replayed verdict. Both
flipping cases build that run's pytest outcome from a mechanism whose
result depends on machine load inside a `--cpus 0.5`, 512 MB sandbox
(`src/exhibit_a/sandbox/runner.py`: `CPUS_LIMIT`, `MEMORY_LIMIT`):

1. **CPU-ratio timing (`redos-search-query`, `canary_dos`).** The recorded
   exploit calls `dos_probe`, which asserts (and the test then passes) only
   when the measured malicious/benign app-CPU ratio exceeds 50x. The app
   CPU is already measured in thread CPU time (`thread_time()` in
   `src/exhibit_a/oracle/plugin.py`), not wall time — but the benign input
   costs almost nothing, so its median is a near-zero denominator. The
   first timed call also paid import/cache costs. Small absolute noise in
   either median swings the ratio across 50x: below it the probe returns
   and the test fails (`invalid_test`); above it the probe raises, the
   test catches and passes (`discarded_unproven`).
2. **Thread race (`static-route-traversal` S3).** The recorded exploit
   races a swap thread against 3000 `serve()` calls. When the swap lands,
   the oracle flags a canary symlink created during the run
   (`provenance`) and the test fails fast. Under CPU contention the loop
   can instead hit the 60 s wall-clock test timeout before any leak is
   observed; the judge then correctly reports `no_effect` for a run that
   never completed. Which happens first is scheduling, not semantics.

Parallelism and host load change both mechanisms; the sandbox CPU cap
amplifies them. This is why the failing case moved between runs.

## Fix (no weakening)

- `dos_probe` discards one warm-up call per input and takes 9 + 9 CPU-time
  samples instead of 5 + 5. `DOS_RATIO` (50x), `DOS_FLOOR`, the app-frame
  fraction and the spread/flaky bars are unchanged, and a noisy run is
  still `flaky`, never a proof.
- Replay-only wall-clock slack: `bench.record_meta.replay_case` runs the
  loop with `REPLAY_TIMEOUT_S = 240` instead of the recording timeout
  (`RECORD_TIMEOUT_S = 60`). Live recording is unchanged. The slack only
  stops a timeout from masquerading as a verdict; every recorded test,
  oracle threshold and the test's exact verdict comparison
  (`comparable(...) == comparable(...)`) are unchanged. No case is
  skipped, xfailed, or compared loosely.

## Validation

Offline: `tests/test_replay_determinism.py` pins the thresholds, the
warm-up, the sample count, and that only replay gets the slack.

With Docker (owner, three times to prove stability):

```bash
~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_meta_replay.py -m docker -q
~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_meta_replay.py -m docker -q
~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_meta_replay.py -m docker -q
```
