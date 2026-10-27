# Exhibit A — agent guide

## Thesis

Exhibit A is a Python 3.11+ security-verification engine that reports only vulnerabilities it can prove: a suspicion becomes a finding only when an exploit test fails on the vulnerable code for the intended oracle-observed reason in an isolated, resource-limited sandbox, then passes after a fix while the baseline and bypass checks remain valid; the CLI, live view, benchmark harness, and model roles are thin surfaces around that proof loop, and a green result means “nothing could be proven,” never “safe.”

Read `SPEC.md` first for the authoritative scope, contracts, proof standard, security model, and non-goals. Before starting any task, read only the last approximately 40 lines of `docs/common.md` and any entries for tasks this task depends on; do not read the whole file. `docs/common.md` is an append-only shared bitacora reconciled with `merge=union`; when done, append exactly one line in the form `- <TID> <agent>: <did>; pending: <left>`.

## Module map

- `src/exhibit_a/schemas/`: Defines and validates the JSON contracts for profiles, suspicions, verdicts, and ledger events.
- `src/exhibit_a/ledger/`: Appends, reads, and projects the JSONL event ledger, the system’s source of truth.
- `src/exhibit_a/models/`: Provides model-role interfaces and replay/provider plumbing for recorded, schema-validated model calls.
- `src/exhibit_a/sandbox/`: Runs untrusted exploit and regression tests in an ephemeral, isolated, resource-limited container with no network or secrets.
- `src/exhibit_a/oracle/`: Observes intended effects and provenance so execution failures count as proof only for the right reason and entry point.
- `src/exhibit_a/loop/`: Currently implements BASELINE → SUSPECT → EXPLOIT → RUN → VERDICT → FIX → VERIFY → PACKAGE; SCAN and SLICE are not built yet, and the CLI scan is a placeholder.
- `src/exhibit_a/live/`: Serves the thin live view and replay stream backed by the ledger, not a separate dashboard product.
- `bench/`: Holds benchmark harnesses, corpora, baselines, ablations, and evaluation data.
- `src/exhibit_a/cli.py`: Exposes the headless engine through the command-line interface.

Supporting directories include `web/` for the plain HTML/JavaScript live view and `tests/` for pytest coverage.

## Current state

The oracle and the Starlette case baseline still run as host child processes, not inside the sandbox; moving them into the sandbox is in progress (tasks T026/T027). Do not assume it is already done.

## Testing

Run the exact project test command:

```bash
~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest
```

Docker or Colima must be running for sandbox tests.

## Hard rules

- Stay inside the scope declared by the task. If work outside scope is required, stop and say so.
- Write every line new during the Meta Global AI Developer Hackathon build period; do not paste or port third-party code into this repository.
- Keep code, comments, and documentation in English.
- Never commit secrets, `.env` files, API keys, or tokens; keys come from environment variables.
- Treat model outputs and PR diffs as untrusted data: validate them against schemas and never execute them outside the sandbox.
- Say “isolated and resource-limited,” never “100% safe.”
- Sandbox tests need Docker. If `docker info` fails, STOP and report it; never skip, ignore or --ignore tests/test_sandbox*.py, and never treat skipped sandbox tests as passing.
- Commit all your work on the task branch before ending the session. Do not push and do not merge: Cauce's finish step does that.
- Keep commits small and clear; do not rewrite history.
- Green tests are required before finishing.
