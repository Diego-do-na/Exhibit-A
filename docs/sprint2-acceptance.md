Sprint 2 acceptance — full verification and report

Summary
- Tests: 371 passed, 1 failed (see "Failures" below).
- Starlette vulnerable case (CVE-2023-29159): end-to-end sandbox-backed loop produced a proven finding and a packaged fix (red→green verified).
- Starlette fixed case: loop produced a discarded_unproven verdict (no proven finding).
- Benchmark smoke: exercised the real loop over the Starlette corpus cases by running each case end-to-end (see commands).

Exact commands run
- Check Docker/Colima:
  docker info

- Full test suite (venv):
  ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest -q

- Starlette vulnerable case (sandbox-backed loop, replay provider):
  ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m exhibit_a.cli run --case bench/corpus/starlette-cve-2023-29159 --replay --out /tmp/exhibit_a_run_out

- Starlette fixed case (sandbox-backed loop, replay provider):
  ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m exhibit_a.cli run --case bench/corpus/starlette-cve-2023-29159-fixed --replay --out /tmp/exhibit_a_run_out_fixed

Observed outputs (high level)
- pytest:
  371 passed, 1 failed in 79.25s
  Failed test: tests/test_models_config.py::test_meta_provider_is_explicitly_not_built_yet

- Vulnerable case CLI (sample lines):
  run starlette-cve-2023-29159: {"proven": 1, "discarded_unproven": 0, "invalid_test": 0, "flaky": 0, "env_failure": 0} dropped=0
  PACKAGE /private/tmp/exhibit_a_run_out/packages/starlette-staticfiles-prefix fix_verified=True
  ledger /private/tmp/exhibit_a_run_out/ledger.jsonl

- Fixed case CLI (sample lines):
  run starlette-cve-2023-29159-fixed: {"proven": 0, "discarded_unproven": 1, "invalid_test": 0, "flaky": 0, "env_failure": 0} dropped=1
  ledger /private/tmp/exhibit_a_run_out_fixed/ledger.jsonl

What passed
- The vast majority of the test suite (371 tests) passed locally.
- The Starlette vulnerable case ran through the sandbox-backed loop, the exploit was red on the vulnerable code and green after applying the produced patch, and a package containing `test_exploit.py`, `fix.patch`, `verdict.json` and `evidence.json` was written and marked `fix_verified=True`.
- The fixed Starlette case ran through the loop and produced a `discarded_unproven` verdict as expected for the fixed source.
- Docker/Colima was available and functional for sandbox tests.

What failed / open gaps
- tests/test_models_config.py::test_meta_provider_is_explicitly_not_built_yet failed (the test expected a ValueError: \"not built yet\" but none was raised). This indicates a stale test or changed behavior around the Meta provider registration (T031 referenced in the bitacora).
- Several outstanding task-level gaps documented in the bitacora remain relevant:
  - T026/T027: moving the oracle and the Starlette baseline fully into the sandbox is in progress; the current run uses the sandbox-backed runner but some host-side behavior remains noted in task entries.
  - T031: the `test_meta_provider_is_explicitly_not_built_yet` expectation is stale and needs investigation / scope exception.
  - T044: previous removal of vendored Starlette and pinned PyPI install changes are recorded; the replay recordings were not re-recorded after that change (observations in docs/common.md).

Artifacts and locations
- Vulnerable run out dir: /private/tmp/exhibit_a_run_out (packages and ledger.jsonl)
- Fixed run out dir: /private/tmp/exhibit_a_run_out_fixed (ledger.jsonl)
- Pytest output shown in terminal (summary above).

Notes for human review (do NOT change code here)
- I did not modify code to fix failing tests; I recorded results and artifacts for review.
- Next investigation items:
  1. Investigate and either update or fix tests/test_models_config.py::test_meta_provider_is_explicitly_not_built_yet (T031).
  2. Re-record replay.jsonl artifacts if the provider prompts/answers changed after removing the vendored Starlette tree (T044).
  3. If desired, re-run the benchmark harness via `python -m bench` once those items are reconciled.

