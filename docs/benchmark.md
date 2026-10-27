# Benchmark

How the Exhibit A benchmark harness works: what the corpus looks like, what each
ablation proves, which metrics are reported, and how to run it. The harness lives
in `bench/` and implements SPEC section 11. Every metric is computed from ledger
events only; the ledger is the single source of truth.

A green result means "nothing could be proven", never "safe". The sandbox used for
real runs is isolated and resource-limited, never "100% safe".

## Corpus format

A corpus is one JSON file: `{"cases": [...]}`. Each case is loaded by
`bench/corpus.py` into a `Case` with this shape:

| Field | Meaning |
|---|---|
| `id` | Unique case id (duplicates are rejected). |
| `kind` | One of `vulnerable`, `fixed`, `clean`. |
| `repo` | Source repository (URL or label). |
| `commit` | Commit the case pins. |
| `ground_truth` | List of `{"class", "file"}` pairs. Only `vulnerable` cases may carry ground truth; any other kind with ground truth is rejected. |
| `synthetic` | Scripted suspicion/outcome list. Only for the smoke-test stand-in; real corpora leave this empty. |

Example: [synthetic.json](../bench/corpus/synthetic.json) (four cases: two
vulnerable, one fixed, one clean). A real case directory carries more than the
JSON: `case.json` plus the vendored `vulnerable/` tree, a `baseline_test.py`, a
recording (`replay.jsonl`), and a `record.py` script. Example:
`bench/corpus/starlette-cve-2023-29159/case.json`:

```json
{"cases": [{"id": "starlette-cve-2023-29159", "kind": "vulnerable",
  "repo": "https://github.com/encode/starlette",
  "commit": "24c1fac62a80bb153c6548145334fc643991e35a",
  "ground_truth": [{"class": "path_traversal", "file": "starlette/staticfiles.py"}]}],
 "cve": "CVE-2023-29159",
 "fixed_commit": "1797de464124b090f10cf570441e8292936d63e3",
 "run": {"tree": "vulnerable", "source_file": "starlette/staticfiles.py",
         "baseline_test": "baseline_test.py", "recording": "replay.jsonl"}}
```

Warning: the Starlette `replay.jsonl` answers are hand-authored stand-ins, not
Meta-model output (see `record.py`). Re-record with a Meta model before quoting
any number from that case. All benchmark and demo numbers must come from Meta
models.

## Ablations and what each proves

`bench/flags.py` defines one `Flags` set per ablation (`SPEC.md` section 11).
`naive` means "LLM reports everything": every suspicion is reported with no
exploit test and no verdict. The other flags switch verification modules on:

| Ablation | Flags | What it proves |
|---|---|---|
| `baseline` | naive, no oracle, no differential, no defender | The naive ceiling: suspicion volume and false positives when nothing is verified. |
| `failing_test_only` | no oracle, no differential, no defender | Value of requiring a failing test: still counts wrong-reason failures as proof. |
| `no_differential` | oracle on, differential off | Value of differential verification (the exploit must pass again after the fix). |
| `no_defender` | oracle and differential on, defender off | Value of the defender (bypass variants against the fix). |
| `full` | all on | The whole system. |

On the synthetic smoke corpus the ladder behaves as expected (see
`tests/test_bench.py`): `baseline` reports 8 with 6 false positives and proves
nothing; `failing_test_only` reports 5 with 3 false positives; `no_differential`
reports 3 with 1 false positive; `full` proves 2 with 0 false positives and
discards 6. Those synthetic numbers exercise the harness only and must never
appear in a benchmark or demo.

The SPEC oracle evaluation set (true exploits, wrong-reason failures, flaky
tests, cheating tests) is not built yet; only the verdict mapping behind it
exists (`classify` in `src/exhibit_a/loop/pipeline.py`).

## Metrics

`bench/metrics.py` scores each `(ablation, case)` run from its ledger events
under `run_id` `bench:<ablation>:<case_id>`:

- `reported`: findings shown to the maintainer. Naive runs report every raised
  suspicion; all other runs report only `proven` verdicts.
- `proven`: findings with a `proven` verdict.
- `true_positives` / `false_positives`: each reported suspicion is matched by
  `(class, location.file)` against the case ground truth.
- `discarded`: suspicions raised but never reported (dropped for lack of proof;
  counted, per the SPEC).
- `recall`: distinct ground-truth pairs found divided by total known
  vulnerabilities, summed over the corpus. `None` (rendered `n/a`) when the
  corpus has no known vulnerability. Recall is reported honestly: it measures
  coverage of known bugs, not safety.
- `tokens` / `cost_usd`: summed `tokens_in + tokens_out` and `cost_usd` from
  `ledger.totals(run_id)`, so costs always come from recorded events.
- `tokens_per_proven` / `cost_per_proven`: per-proven ratios; `None` (rendered
  `n/a`) when nothing was proven.

`aggregate` sums each column into one `Row` per ablation. `write_results`
writes `results.md` (the table) and `results.json` (rows plus derived ratios)
into the output directory.

## How to run it

Smoke run against the scripted stand-in (tests only; numbers are meaningless):

```bash
python -m bench --corpus bench/corpus/synthetic.json --out bench/out --synthetic
```

Run a subset of ablations with repeatable `--ablation` flags (default: all):

```bash
python -m bench --corpus bench/corpus/synthetic.json --out bench/out \
  --ablation full --ablation no_defender --synthetic
```

Run against the real loop: pass `--pipeline module:function` with a callable
matching `bench.runner.Pipeline` (`Callable[[Case, Flags, Ledger, str], None]`),
which analyses one case under the given flags and appends its events to the
ledger under the given `run_id`. The real-loop adapter is not wired yet; an
adapter must map each `Flags` onto the loop (naive = report suspicions without
verifying, oracle off = skip the intended-reason check, differential off = skip
fix re-verification, defender off = skip bypass variants) and run every case
under every ablation through `run_benchmark`.

Run one real case through the CLI with recorded answers (used by
`tests/test_e2e_cve.py` for Starlette CVE-2023-29159):

```bash
python -m exhibit_a.cli run --case bench/corpus/starlette-cve-2023-29159 \
  --replay --out runs/case
```

`--case` takes a `case.json` file or its directory and requires `--replay`;
live providers are not wired to the CLI yet. Output is the clone, the ledger,
and one package per proven suspicion (`test_exploit.py`, `fix.patch`,
`verdict.json`, `evidence.json`).

Probe which model serves each role before spending benchmark budget (SPEC
section 14). `bench/probe.py` runs each role's real prompt N times and reports
the schema-valid-JSON rate per role (a miss is any answer that is not valid
JSON, fails the role schema, or errors):

```bash
python -m bench.probe --provider ollama --model llama3.1 --out bench/probe-out
```

Results go to `summary.json` and `summary.md` in the output directory.
