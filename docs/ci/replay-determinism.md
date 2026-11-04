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
   exploit binds `dos_probe`'s return value and then does `assert ratio`
   (None was falsy) or `assert ratio < 10`. The probe asserts only when
   the malicious/benign app-CPU ratio exceeds 50x. Below 50x it used to
   return `None` and the test failed (`invalid_test`); above 50x it
   raises, the test catches and passes (`discarded_unproven`). The benign
   median is a near-zero denominator, so small noise swings the ratio
   across 50x.
2. **Thread race (`static-route-traversal` S3).** The recorded exploit
   races a swap thread against 3000 `serve()` calls. When the swap lands,
   the oracle flags a canary symlink created during the run
   (`provenance`) and the test fails fast. Under CPU contention the
   sandbox `cpu=` ulimit (equal to the wall-clock timeout) SIGXCPU-kills
   the busy loop, or the wall-clock timeout fires first; the judge then
   reports `no_effect` for a run that never completed.

Parallelism and host load change both mechanisms; the sandbox CPU cap
amplifies them. This is why the failing case moved between runs.

## Fix (no weakening)

- `dos_probe` discards one warm-up call per input and takes 9 + 9 CPU-time
  samples instead of 5 + 5. `DOS_RATIO` (50x), `DOS_FLOOR`, the app-frame
  fraction and the spread/flaky bars are unchanged, and a noisy run is
  still `flaky`, never a proof.
- On a miss, `dos_probe` returns `0.0` rather than `None`. Recorded tests
  that assert on the bound result then pass on both sides of 50x, so the
  compact redos case is stably `discarded_unproven` / `no_effect`. The
  signed event still carries the real ratio; the return value is not a
  measurement the test is allowed to time. Compact metadata matches that
  engine output (CI shard 4).
- Sandbox `cpu=` ulimit is `4 * ceil(timeout)` so a two-thread busy loop
  is bound by the wall clock, not SIGXCPU. Replay-only wall-clock slack
  is `REPLAY_TIMEOUT_S = 360` (live recording stays `RECORD_TIMEOUT_S =
  60`). Compact `static-route-traversal` S3 stays `invalid_test` /
  `provenance`, matching local Docker and the live recording.

No case is skipped, xfailed, or compared loosely.

## Validation

Offline: `tests/test_replay_determinism.py` pins the thresholds, the
warm-up, the miss sentinel, the sample count, and that only replay gets
the slack.

With Docker (owner, three times to prove stability):

```bash
~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_meta_replay.py -m docker -q
~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_meta_replay.py -m docker -q
~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_meta_replay.py -m docker -q
```
