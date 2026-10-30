# Exhibit A — proof before accusation

Exhibit A is a Python 3.11+ security-verification engine that reports only vulnerabilities it can prove. It runs a tight verification loop (baseline → suspect → exploit → run → verdict → fix → verify) in an isolated and resource-limited sandbox and produces reproducible packages containing exploit tests, fixes, and evidence.

Requirements
- Python 3.11+
- Docker or Colima (must be running for sandbox tests)

Quick install
1. Create and activate a Python 3.11 virtual environment.
2. From the repository root:

```bash
python -m pip install -e '.[dev]'
```

Note: sandbox tests require Docker (or Colima). Start Colima with `colima start` if you use it.

Running the CLI (Starlette benchmark case)

The CLI entry point is `python -m exhibit_a.cli`. The repository includes a benchmark case for the Starlette CVE:

```bash
python -m exhibit_a.cli run --case bench/corpus/starlette-cve-2023-29159 --replay
```

This copies the case tree to `runs/case/clone`, runs the verification loop with the recorded model answers, and writes outputs (ledger, packages) to the `--out` directory (default `runs/case`).

`--replay` is optional. Without it the roles call the provider chosen with `--provider` and `--model` (default `ollama`), so a key or a local model is needed. Under GitHub Actions the engine refuses `--case` without `--replay`. The recordings in `bench/corpus/` are hand-authored (`"model": "hand-authored"`); no Meta-model recording exists yet.

A pull request can be verified with `python -m exhibit_a.cli run --repo <dir> --pr-diff BASE..HEAD`. Exit codes (`docs/reference/cli-exit-codes.md`): 0 nothing proven, 10 a finding proven, 20 run incomplete, 2 usage or input error.

Architecture overview
- `src/exhibit_a/cli/` — CLI package (`run`, `ledger`, `report`, `runs`, `advisories`, `dashboard`; `scan` is still a placeholder).
- `src/exhibit_a/loop/` — core verification loop and orchestration of roles.
- `src/exhibit_a/sandbox/` — isolated, ephemeral runner for exploit/regression tests (no network, no secrets, pinned image, CPU/memory/time limits).
- `src/exhibit_a/oracle/` — observes intended effects and verifies provenance for proof.
- `src/exhibit_a/ledger/` — append-only JSONL event ledger; single source of truth for runs and the live view.
- `src/exhibit_a/models/` — model-role plumbing and replay provider used by benchmark cases.
- `bench/` — benchmark harness, corpora, recorded runs, and case definitions.

Benchmarks and licensing notice

The benchmark corpus includes recorded cases derived from third‑party projects (for example, the Starlette case). Those third‑party projects remain under their original licenses (Starlette: BSD-3). The Exhibit A engine code in this repository was written during the event. Do not assume benchmark content is permissively relicensed by this repo — respect the original project licenses when reusing corpus artifacts.

Security & safety notes
- The sandbox is isolated and resource-limited; do not call it "100% safe."
- Exploit, fixed-code and bypass runs go through the sandbox. The project baseline of a `--case ... --replay` run still executes as a host child process with a scrubbed environment.
- Never commit secrets; API keys must be provided via environment variables.
- Docker/Colima must be available and running for sandbox tests. If `docker info` fails, do not proceed with sandbox runs.

Getting help
- Read `SPEC.md` for the authoritative scope, proof standard, and contracts.
- See `AGENTS.md` for project thesis, module map, and hard rules.

# Exhibit-A
Proof before accusation. An adversarial agent must write an exploit test that actually fails against an isolated clone before any vulnerability is reported. Failing test, then fix, then green, then a permanent regression guard: since A-22 (T078) a finding is `proven` only after the exploit also passes on the fixed code and the baseline still passes, and the package ships the exploit as a regression test. A surviving bypass is reported with `fix_incomplete`. Suspicions that can't be proven are dropped silently and counted.

Declared residual limits of the oracle (`docs/oracle/oracle-provenance.md` section 7). Each is pinned by a strict xfail in `tests/test_oracle_residual.py`:
- R1: in-process introspection of the plugin (FALSE_PROVEN)
- R2: `sitecustomize` in the app tree (FALSE_PROVEN, host path)
- R3: subprocess reads (recall)
- R4: ctypes / native reads (recall)
- R5: dependency monkeypatching by computed names (FALSE_PROVEN)
- R6: obfuscated test-chosen app root (FALSE_PROVEN)

A green result means "nothing could be proven", never "safe".
