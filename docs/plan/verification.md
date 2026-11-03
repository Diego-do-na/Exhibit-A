# T145 verification evidence

Every claim below names the exact command that proves it and the result
observed. Items marked OWNER-RUN need Docker and are produced by
`scripts/verify_closure.sh` in the owner's terminal; their expected
result is stated, never pre-claimed.

## Sandbox: no host execution in any production path

Claim: baseline, exploit, fixed-code and bypass runs go through
`SandboxRunner` in every CLI and benchmark mode; `HostRunner`/`run_oracle`
exist only behind `allow_host_execution=True`, which the CLI never sets.

Evidence (re-run 2026-11-03, task/T144 branch):

```bash
grep -rn "allow_host_execution=True" src/exhibit_a/cli/ | grep -v test-only
# no match: the CLI never sets the switch
python - <<'EOF'  # scripts/verify_closure.sh block 1: AST check
# src/exhibit_a/loop/pipeline.py call-sites: 1
# bench/loop_pipeline.py call-sites: 1
# BAD: none (each sits inside `elif <flag>:`)
EOF
.venv/bin/python -m pytest tests/test_no_host_execution.py tests/test_closure_verification.py -q -m "not docker"
# 15 passed, 7 deselected (docker tests need the daemon)
```

Note: the first version of block 1 (`grep ... | grep -v test-only`)
false-positived on the two guarded constructor calls plus their comments,
so it is now an AST check: a `allow_host_execution=True` keyword is
accepted only inside an `if`/`elif` whose test names the flag without
setting it. `tests/test_closure_verification.py::test_no_cli_module_sets_host_execution`
pins the CLI side.

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

Evidence (re-run 2026-11-03, task/T144 branch):

```bash
.venv/bin/python -m exhibit_a.cli scan .
# { "commit": "unknown", "language": "python", ... "test_cmd": "pytest", ... }
.venv/bin/python -m exhibit_a.cli scan --graph .
# { "graph": { "build_seconds": 1.411, "entries": [ { "kind": "cli_main", ... } ] } }
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

## OWNER-RUN status (2026-11-03: Docker daemon down in this environment)

Blocks 2-4 of `scripts/verify_closure.sh` need Docker and stay pending:

```bash
colima start || open -a Docker   # then: docker info
sh scripts/verify_closure.sh     # blocks 2 (sandbox run), 3 (meta replay x3), 4 (full suite)
```

## Finding for the owner: secret names disagree (out of scope, no change made)

The dashboard onboarding (T144) now says
`gh secret set EXHIBIT_A_API_KEY --env exhibit-a`, per the correction.
But the generator and the Action still say `META_API_KEY`:

- `src/exhibit_a/cli/ext/init.py:41` writes a workflow with
  `api-key: "${{ secrets.META_API_KEY }}"` and prints
  "create the META_API_KEY repository secret";
- `action.yml:38` defaults `api-key` to `META_API_KEY`, while
  `action.yml:261,278` and `README.md:73` use `EXHIBIT_A_API_KEY`.

So a user who follows the dashboard (`exhibit-a init`, then the
`EXHIBIT_A_API_KEY` environment secret) gets a workflow that reads a
different secret. Renaming either side changes the live Action contract;
left untouched for an explicit owner decision.
