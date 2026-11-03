# T145 verification evidence

Every claim below names the exact command that proves it and the result
observed. Items marked OWNER-RUN need Docker and are produced by
`scripts/verify_closure.sh` in the owner's terminal; their expected
result is stated, never pre-claimed.

## Sandbox: no host execution in any production path

Claim: baseline, exploit, fixed-code and bypass runs go through
`SandboxRunner` in every CLI and benchmark mode; `HostRunner`/`run_oracle`
exist only behind `allow_host_execution=True`, which the CLI never sets.

Evidence (run 2026-11-02, this branch):

```bash
grep -rn "allow_host_execution" src/ bench/*.py
# runner.py:324 allow_host_execution: bool = False (guard in HostRunner)
# pipeline.py:239/257/265 and bench/loop_pipeline.py:307/341: default False,
#   HostRunner constructed only when the flag is explicitly true
# no match sets it to True outside tests
.venv/bin/python -m pytest tests/test_no_host_execution.py tests/test_closure_verification.py -q -m "not docker"
# 15 passed, 7 deselected
```

`tests/test_closure_verification.py::test_no_cli_module_sets_host_execution`
additionally asserts no module under `src/exhibit_a/cli/` contains
`allow_host_execution=True`.

OWNER-RUN (real sandbox proof, one benchmark case, compact + slice):

```bash
sh scripts/verify_closure.sh   # block 2: exhibit-a run --case bench/corpus/starlette-cve-2023-29159 --replay --profile compact --slice
```

Expected: ledger under `/tmp/exhibit-a-verify-run` with `baseline_done`
events and a verdict; the test
`test_docker_cli_replay_corpus_cases_preserve_verdicts_without_host_execution`
in `tests/test_no_host_execution.py` is the Docker form of this claim.

## SCAN

Claim: `exhibit-a scan REPO` prints a `RepoProfile`; `--graph` adds the
AST-only call graph; `--pr-diff BASE..HEAD` adds reach paths. Only a scan
with no repository argument prints a placeholder (that is T146, not here).

Evidence:

```bash
.venv/bin/python -m exhibit_a.cli scan .
# { "commit": "unknown", "language": "python", ... "test_cmd": "pytest", ... }
.venv/bin/python -m exhibit_a.cli scan --graph .
# { "graph": { "build_seconds": 2.422, "entries": [ { "kind": "cli_main", ... } ] } }
.venv/bin/python -m exhibit_a.cli scan --pr-diff HEAD~1..HEAD .
# { "graph": { ... reach paths ... } }
.venv/bin/python -m pytest tests/test_closure_verification.py::test_scan_on_a_repository_prints_a_repo_profile -q
# 1 passed
```

## SLICE

Claim: slicing exists (`graph/slicer.py`), is wired through
`run --slice`, is on by default exactly for `--profile compact` and off
for `standard`, with `--slice`/`--no-slice` overriding.

Evidence:

```bash
grep -n "def _slice" -A 3 src/exhibit_a/cli/run.py
# Whether to slice: --slice / --no-slice win; otherwise on exactly for the compact profile.
.venv/bin/python -m pytest tests/test_closure_verification.py::test_slice_default_follows_profile tests/test_graph_slice.py -q -m "not docker"
# slice default logic passed; the two sandbox-parametrised slice tests
# ERROR at setup without Docker (they need the sandbox) -> OWNER-RUN below
```

OWNER-RUN: `sh scripts/verify_closure.sh` blocks 3-4 (meta replay three
times, then the full suite with Docker), which includes the two
sandbox slice tests.

## Meta replay, three consecutive runs (OWNER-RUN)

```bash
for i in 1 2 3; do .venv/bin/python -m pytest tests/test_meta_replay.py -m docker -q; done
```

No skip, no xfail is added by this branch. The determinism fix they rely
on (dos warm-up, 9 CPU-time samples, replay-only 240s timeout) is
documented in `docs/ci/replay-determinism.md`; thresholds are unchanged.

## CLI and per-repo dashboard (T149)

Claim: `--help` lists scan, run, dashboard, report, verify, doctor,
audit, sarif, reproduce, runs, ledger, trace, advisories with one-line
descriptions, global `-v/--verbose` works, and `exhibit-a dashboard`
run from inside another repository serves that repository's runs.

Evidence:

```bash
.venv/bin/python -m exhibit_a.cli --help
# lists every required subcommand (plus deps, sbom, variants, init, version);
# descriptions are single-line strings in src/exhibit_a/cli/parser.py
.venv/bin/python -m exhibit_a.cli -v --help >/dev/null; echo $?
# 0
cd /tmp/other-repo   # a different repo holding only runs/ from scripts/make_sample_runs.py
/path/to/.venv/bin/python -m exhibit_a.cli dashboard --port 8770 --no-open
# dashboard: serving local: runs on http://127.0.0.1:8770/ (read-only, ^C to stop)
# dashboard: open this one-time link in your browser (it sets a session cookie):
#   http://127.0.0.1:8770/auth?token=...
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8770/index.html
# 200
```

`resolve_source` (dashboard source defaulting) is pinned offline by
`test_dashboard_source_defaults_to_the_callers_runs_folder`: no `runs/`
folder means a clear "no runs found" error, never another repo's data.

## Doc claims corrected in this branch

- README/AGENTS called `--slice` "opt-in, off by default". The code turns
  it on by default under `--profile compact` (`cli/run.py::_slice`), as
  SPEC already said. Wording aligned in README.md, AGENTS.md.
- SPEC's "complete suite of subcommands" omitted `deps`, `sbom`,
  `variants`, `init`, `version`, which the parser provides. List completed.
