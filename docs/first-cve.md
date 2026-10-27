# First real CVE end to end

**Target:** Starlette `StaticFiles` path traversal, CVE-2023-29159
([GHSA-v5gw-mw7f-84px](https://github.com/encode/starlette/security/advisories/GHSA-v5gw-mw7f-84px)).

| | commit |
|---|---|
| vulnerable | `24c1fac62a80bb153c6548145334fc643991e35a` (Starlette 0.26.1 + docs) |
| fixed | `1797de464124b090f10cf570441e8292936d63e3` (0.27.0) |

`StaticFiles.lookup_path` checked containment with `os.path.commonprefix`, which compares
characters. Serving `/srv/out` also served `/srv/outside/...` through a `..` segment. The
upstream fix is one line: `commonprefix` becomes `commonpath`.

## Run it

From the repository root, in an environment where `pip install -e ".[dev]"` was done and
`anyio` comes with the `dev` extra (the vendored Starlette needs it):

```bash
python -m exhibit_a.cli run \
  --case bench/corpus/starlette-cve-2023-29159 \
  --replay \
  --out runs/first-cve
```

Expected output (the run id and counts are fixed by the recording):

```
run starlette-cve-2023-29159: {"proven": 1, ...} dropped=0
PACKAGE <out>/packages/starlette-staticfiles-prefix fix_verified=True
ledger <out>/ledger.jsonl
```

Exit code 0 means a proven finding was fixed, verified and packaged.

## What the PACKAGE contains

`runs/first-cve/packages/starlette-staticfiles-prefix/`

- `test_exploit.py`: fails on the vulnerable code, passes on the fixed code.
- `fix.patch`: the one-line change, as a unified diff.
- `verdict.json`: `proven`, 3 repeated runs, `fails_on: vulnerable`, `passes_on: fixed`,
  bypass attempts `tried: 2, succeeded: 0`.
- `evidence.json`: the oracle event (the canary file read, with the call stack).

`tests/test_e2e_cve.py` checks all of this, and also re-runs the packaged test on the
vulnerable tree (red) and on the patched tree (green).

## What is in `bench/corpus/starlette-cve-2023-29159/`

- `case.json`: corpus entry (loads with `bench.corpus.load_corpus`) plus the run settings.
- `vulnerable/starlette/`: only the ten Starlette modules that `staticfiles.py` imports,
  verbatim from the vulnerable commit. `LICENSE.starlette.md` is Starlette's BSD-3-Clause
  license and must stay with them. `anyio` is the only dependency and is not vendored.
- `baseline_test.py`: the behaviour that must survive the fix (serve a file, 404, no parent
  access).
- `replay.jsonl`: the recorded model answers; `record.py` regenerates it.

## Limits you should know

- **The recorded answers are hand-authored, not Meta-model output.** They go through the
  real prompt builders and replay provider, so the loop is exercised as in a live run, but
  no number from this case may be quoted as a Meta-model result (SPEC section 5). Re-record
  with a Meta model first.
- **Baseline and exploit run in host child processes, not the Docker sandbox.** The sandbox
  installs only pytest and has no network, so it cannot import `anyio`. Say "scrubbed child
  process", not "isolated". Running this case in the sandbox needs a dependency image.
- **The exploit runs anyio's worker-thread calls inline.** The oracle records the call stack
  of the thread that opens the canary; Starlette opens files in a worker thread, whose stack
  holds no application frames. The test therefore patches `anyio.to_thread.run_sync` to
  call inline, so the provenance check can see `StaticFiles.__call__`. The patched shim is
  the innermost frame of the recorded stack. Propagating stacks across threads in the oracle
  would remove the need for it.
- The oracle's canary lives in `<work>/outside`; the exploit serves `<work>/out`, a name
  prefix of it. That is the exact condition the CVE needs.
