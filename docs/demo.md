# Demo storyboard: red to green in 2-3 minutes

The demo tells one story: a pull request introduces a vulnerability, Exhibit A
proves it, proposes a fix, goes green, and leaves a report plus a browsable
history. It runs two ways:

- `scripts/demo.sh --offline` — replays the committed compact-profile Meta
  recordings (`examples/demo-app/recordings/`, byte-identical copies of the
  live runs in `bench/corpus/<case>/recordings/`). No key, no Meta network.
  The sandbox still executes every baseline and exploit test, so Docker must
  be running. This is the reliable, video-safe path.
- `scripts/demo.sh --live` — runs the same story live against Muse Wonder
  (`muse-wonder-1.0`, `--profile compact --budget-usd 1`, archive case only).
  Needs `META_API_KEY` in the environment. The model is not deterministic: a
  live run can differ from the recording (see `docs/meta-run.md`).

The headline, and the only claim the demo makes: a real Meta model produced a
real proof with a verified fix, and the offline replay reproduces it for free —
archive zip-slip US$0.06, Starlette CVE-2023-29159 US$0.11 (live cost; replay
costs nothing). Never claim more than `docs/meta-run.md` says: a green result
means "nothing could be proven", never "safe", and the sandbox is "isolated
and resource-limited", never "100% safe".

## Storyboard (timings on a warm machine with Docker running)

| Time | Screen | Command / action |
|------|--------|------------------|
| 0:00 | The PR | `scripts/demo.sh --offline` starts; step 1 prints `pr.patch`: the "simplification" that replaces path confinement with a bare `os.path.join`. Say: "this PR drops the zip-slip check." |
| 0:20 | Red (proven) | Step 2 replays both compact Meta recordings through the real loop and sandbox. Say: "Muse Wonder's exploit runs in an isolated sandbox; the oracle watches the canary." Archive first (~1 min, dependency-free), then Starlette (~1-2 min, installs pinned `starlette`/`anyio` in the sandbox). |
| ~2:00 | The verdict | Step 3 prints both ledger verdicts: `S1=proven fix_verified=True`. Say: "proven, and the fix the model proposed held — the exploit passes on fixed code, the baseline still passes, three bypass variants failed." |
| ~2:10 | The report | Step 4 renders the finding package with `exhibit-a report`: verdict, evidence, fix. Say: "this is what a reviewer gets — the exploit test, the patch, the evidence." |
| ~2:25 | The history | Step 5 lists both runs with `exhibit-a runs`. Say: "every run is indexed; nothing is a claim without a ledger behind it." |
| ~2:35 | Live view | Step 6 prints the dashboard command. Open `http://127.0.0.1:8765` (or pass `--serve`). Say: "the same ledger, browsable." End. |

Total about 2.5 minutes; the variance is Docker image build and pip install
on a cold machine (see troubleshooting).

## Troubleshooting

- `docker info` fails / sandbox errors: start Docker (Colima: `colima start`)
  and re-run. The demo never skips sandbox tests; without Docker it stops.
- Starlette leg is slow or fails on install: the sandbox installs pinned
  `starlette==0.26.1` and `anyio` from PyPI, so that leg needs registry
  network. The archive leg is fully hermetic. On a machine with no registry
  access, demo just the archive case (see `tests/test_demo_kit.py`).
- `exhibit-a runs` reports problems: a corrupt `runs.jsonl` line. Delete
  `runs/demo-offline/runs.jsonl` and re-run; the script rebuilds it.
- `--live` exits 2 demanding `META_API_KEY`: export it first. The key is read
  from the environment only and is never printed, logged, or written; run the
  same secret scan as the recording pipeline before committing anything new:
  `PYTHONPATH=src:. python -m bench.record_meta --scan <files>`.
- `--live` ends with no proven finding: expected variance — the model is not
  deterministic, and the recording is one sample. Quote `docs/meta-run.md`,
  show the ledger, and fall back to `--offline` for the guaranteed ending.
- Port 8765 busy: `python -m exhibit_a.cli dashboard --source local:runs/demo-offline --port 8771`.
- Re-recording: never edit a recording by hand. A new live run overwrites
  only with `bench/record_meta.py --profile compact --overwrite`, and the
  demo copies under `examples/demo-app/recordings/` must be re-copied
  byte-identical afterwards (enforced by `tests/test_demo_kit.py`).
