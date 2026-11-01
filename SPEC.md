# Exhibit A — SPEC v1

> Proof before accusation.

## 1. Thesis

Security tools drown maintainers in suspicions nobody has time to verify. Exhibit A only
reports what it can **prove**: a suspected vulnerability becomes a finding only when an
exploit test, run in an isolated sandbox, fails for the right reason. The verification
engine is the product. Everything else (CLI, GitHub Action, live view) is a thin surface
on top of it.

A green result means "nothing could be proven", never "safe".

## 2. What the product is

- A headless engine, driven by a CLI and a GitHub Action (`action.yml`, which runs `exhibit-a run --pr-diff`).
- Input: a PR diff (surface 1), a CVE reachability question (surface 2), or a
  dependency-update diff (surface 3, stretch).
- Output: a pull request containing the exploit test, the fix, and the evidence.
  **Nothing merges itself.**
- The live view is a thin viewer of the ledger. It is not a dashboard product.

### Commands

The engine is driven through the `exhibit-a` CLI with the following subcommands:

- `scan`: detect language/framework/dependencies, print `RepoProfile`, compute static call graph (`--graph`), and identify reach paths from diffs (`--pr-diff`).
- `run`: execute the core verification loop on benchmark cases (`--case`) or PR diffs (`--pr-diff`), with cost controls (`--profile {standard,compact}`), static slicing (`--slice`), and provider configuration (`--provider`, `--model`).
- `ledger`: display token, cost, and event totals for a run from its JSONL ledger.
- `trace`: display the chronological sequence of lifecycle steps and outcomes for a run.
- `report`: render a finding package as formatted Markdown or self-contained HTML.
- `runs`: query and print past run history from the index (`runs.jsonl`).
- `advisories`: query OSV advisories for project dependencies (suspicion hint only, not proof).
- `dashboard`: serve the local read-only web dashboard to inspect runs, traces, and proof artifacts.
- `audit`: audit a whole repository by ranking call graph reach paths and running the verification loop against top sink targets.
- `doctor`: verify sandbox container isolation, runtime, capabilities, seccomp filters, and cgroup limits via an ephemeral probe container.
- `reproduce`: re-run a proof bundle in the isolated, resource-limited sandbox against vulnerable and fixed trees with no model call.
- `sarif`: export proven findings from a run directory to SARIF 2.1.0 for GitHub code scanning.
- `verify`: verify a proof bundle offline: check file SHA-256 digests and the attestation manifest signature.

### Non-goals

- Auditing entire dependency repositories.
- Automatic remediation without human review.
- Secrets or configuration scanning.
- Publishing findings on repositories we do not own.
- Claiming a project is "secure" or the sandbox is "100% safe". Say "isolated and
  resource-limited".

## 3. Core loop

```
SCAN -> BASELINE -> SLICE -> SUSPECT -> EXPLOIT -> RUN -> VERDICT -> FIX -> VERIFY -> PACKAGE
```

| Step | What happens |
|---|---|
| SCAN | Detect language, interpreter, dependency manager, test command, framework. |
| BASELINE | Run the project's own tests on a clean clone. Abort if they fail. |
| SLICE | Give each role only the context it needs (not the whole repo). |
| SUSPECT | Adversary proposes suspicions on the attack surface. |
| EXPLOIT | Test writer turns a suspicion into an exploit test. |
| RUN | Execute it in the sandbox; collect oracle events. |
| VERDICT | proven / discarded_unproven / invalid_test / flaky / env_failure. |
| FIX | Fixer proposes a patch (proven findings only). |
| VERIFY | Exploit now passes, baseline still passes, defender tries bypass variants. |
| PACKAGE | Directory/PR with exploit test, patch, evidence. |

Suspicions that cannot be proven are dropped silently **and counted**.

## 4. Proof standard

A finding is `proven` only if all five hold:

1. Baseline tests pass on a clean clone.
2. The exploit test fails on the vulnerable code **and** the oracle saw the intended effect
   (e.g. a canary file outside the allowed directory was read).
3. Provenance: the effect came from application code reached through a real entry point,
   not from the test calling the sink directly.
4. The result is stable across N repeated runs (default 3).
5. After the fix, the exploit passes and the baseline still passes; defender bypass
   variants fail, or the surviving one is reported.

Verdict values: `proven`, `discarded_unproven`, `invalid_test`, `flaky`, `env_failure`.

Decisions (A-22):

- The loop runs FIX / VERIFY / DEFEND before emitting the verdict, so condition 5
  gates every `proven`: exactly one `verdict` event is emitted per suspicion, after
  verification, never before the fix has been checked.
- A stable proof whose fix is not verified (the exploit does not pass on the fixed
  code N times, or the fixed baseline does not pass) is `discarded_unproven` with the
  reason `exploit proven but no verified fix`. An ineffective fix therefore never
  yields `proven`.
- A surviving bypass does not block `proven`: it is reported in
  `bypass_attempts.succeeded` with `verdict=proven` and an explicit `fix_incomplete`
  flag, as condition 5 allows ("or the surviving one is reported").
- Ablations keep their semantics: with `differential` off the exploit is never
  re-run on the fixed code, so a stable proof may still yield `proven`, marked
  ablated by the run flags.
- The `verdict` event payload carries `reason_code` and `effect` alongside the
  reason, without changing the signed oracle-event channel.

Declared residual limits of the oracle (`docs/oracle/oracle-provenance.md` section 7; each is
pinned by a strict xfail in `tests/test_oracle_residual.py`):

- R1: in-process introspection of the plugin (FALSE_PROVEN)
- R2: `sitecustomize` in the app tree (FALSE_PROVEN, host path)
- R3: subprocess reads (recall)
- R4: ctypes / native reads (recall)
- R5: dependency monkeypatching by computed names (FALSE_PROVEN)
- R6: obfuscated test-chosen app root (FALSE_PROVEN)

Path traversal is proven in the loop for the read effect (Starlette case) and for the write
effect (archive extraction, T076, inside the sandbox). The test cannot choose where the app
is rooted: `EXHIBIT_A_CANARY` is not in the test contract, a guard rule rejects canary-derived
paths handed to a call, and the judge requires the canary to be requested through the allowed
directory (T079); R6 is what remains of that.

## 5. Components

- **Scanner**: rule-based, with an optional small-model fallback; always verified by
  execution (it proposes how to run the tests, the sandbox checks that it works).
- **Attack-surface map**: entry points (routes, CLI args, file/URL inputs) and where they
  reach sinks.
- **Context slicing**: per-role context. Metric: tokens per proven finding versus a
  whole-repo baseline.
- **Sandbox/runner**: `run(clone_path, test_path, timeout) -> { outcome, exit_code, stdout,
  stderr, oracle_events[] }`. Ephemeral container: unprivileged, capabilities dropped, no
  network, read-only filesystem except the clone, CPU/memory/pids/time limits, pinned
  image. Never mount the Docker socket or host directories.
- **Oracle**: observes the intended effect (`canary_read`, `canary_write`, `canary_exec`, `canary_sql`) and checks provenance.
- **Roles** behind one `ModelRole` interface: adversary, test writer, fixer, defender.

### Model providers

- `replay`/mock (deterministic, for tests and the demo replay mode)
- `ollama` (plumbing and debugging only)
- Meta Model API, and Meta open-weight models through an inference partner
  (OpenAI-compatible endpoint)
- Baseten (`baseten` provider): comparison and fallback provider speaking OpenAI-compatible
  chat-completions, with mandatory explicit pricing configuration (`src/exhibit_a/models/baseten.py`).
 
Implemented provider registry and factories: `replay`, `ollama`, `openai_compatible`,
`meta`, and `baseten` (see `src/exhibit_a/models/config.py`). The code consumes provider implementations
through an OpenAI-compatible request shape and exposes provider subclasses that
reuse the OpenAI-compatible plumbing.

UNVERIFIED: whether the Meta Model API accepts the `response_format` structured-output
field, the exact base URL, and the model pricing are recorded but remain unverified
(see `src/exhibit_a/models/meta.py` and section 14).

Every model call is recorded and replayable. A cost meter enforces a hard stop below the credit limit.

## 6. Contracts

`repo_profile.json`
```json
{"commit": "", "language": "", "interpreter": "", "dependency_manager": "",
 "install_cmd": "", "test_cmd": "", "framework": "",
 "dependencies": [{"name": "", "version": ""}],
 "baseline": {"passed": 0, "failed": 0, "seconds": 0.0}}
```

`suspicion.json`
```json
{"id": "", "class": "", "location": {"file": "", "line": 0},
 "entry_point": "", "hypothesis": "", "source": ""}
```

`verdict.json`
```json
{"suspicion_id": "", "verdict": "proven",
 "evidence": {"test_path": "", "fails_on": "", "passes_on": "", "runs": 3,
              "oracle": {}, "provenance": {},
              "observed_location": {"file": "", "line": 0, "function": "", "line_source": ""}},
 "fix": {"patch_path": ""},
 "bypass_attempts": {"tried": 0, "succeeded": 0},
 "duplicates": [], "duplicate_of": null}
```

Findings grouping (deduplication): when multiple suspicions prove the same oracle effect through the same entry point and sink call chain, the primary finding records absorbed suspicion IDs in `duplicates`, while duplicate findings record the primary ID in `duplicate_of`. Both fields are omitted from serialized output when empty.

In `evidence` (and `evidence.json`), `observed_location` records where the oracle observed the effect:
- `file`: file path of the observed sink.
- `line`: line number of the observed sink.
- `function`: qualname of the enclosing function/method.
- `line_source`: source text of the observed line at the sink.

`manifest.json` (attestation manifest)
```json
{"schema_version": 1,
 "files": {"evidence.json": "", "fix.patch": "", "test_exploit.py": "", "verdict.json": ""},
 "exhibit_a_version": "", "exhibit_a_commit": "",
 "case_id": "", "repo_commit": null, "diff_hash": null,
 "effect": "", "entry_point": "",
 "oracle_verdict": {"verdict": "proven", "reason": "", "effect": "", "evidence": {}, "fix_verified": true, "fix_incomplete": false},
 "ledger_events": [{"index": 0, "type": ""}],
 "requirements": [],
 "signature": ""}
```

Every finding package carries a signed `manifest.json` produced at packaging time. It binds file SHA-256 digests, engine version/commit, oracle verdict, and supporting ledger event indices under an HMAC-SHA256 signature, allowing offline verification (`exhibit-a verify`) and reproduction in the isolated, resource-limited sandbox (`exhibit-a reproduce`) with no model call.

Event line (ledger):
```json
{"ts": "", "run_id": "", "type": "", "role": "", "model": "",
 "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0, "latency_ms": 0, "payload": {}}
```

Event types: `pr_opened`, `scan_done`, `baseline_done`, `suspicion_raised`,
`exploit_written`, `run_started`, `oracle_event`, `verdict`, `fix_proposed`,
`bypass_attempt`, `bypass_result`, `packaged`.

## 7. Vulnerability classes and effects (v1)

Four concrete oracle effects are implemented and proven by execution with a clear oracle (`Effect = Literal["canary_read", "canary_write", "canary_exec", "canary_sql"]`):

1. `canary_read`: Path traversal (file read outside allowed directory). Realised on Starlette `StaticFiles` (CVE-2023-29159).
2. `canary_write`: Archive extraction / zip-slip (file write outside allowed extraction directory). Realised on `archive-extraction-pathtraversal`.
3. `canary_exec`: Remote command execution, code injection, and unsafe deserialization (process execution or running an executable planted outside the app directory). Realised on `command-injection-shell` and `unsafe-deserialization-pickle`.
4. `canary_sql`: SQL injection (reading a seeded canary table from the application database via dynamic/unparameterized SQL queries). Realised on `sql-injection-login` and `sql-injection-search`.

SSRF is not a v1 class: a faithful effect needs a network, which the isolated, resource-limited sandbox forbids (see `docs/oracle/second-class.md`). Broken authorization without an observable side-effect sink remains out of scope.

## 8. Surfaces

1. **PR diff** (core).
2. **CVE reachability**: does your code actually reach the vulnerable dependency path?
3. **Dependency-update diff** (stretch).

## 9. Ledger and live view

- The ledger is an append-only JSONL event log and the single source of truth. It feeds the
  live view, the benchmark, the cost meter and the audit trail.
- Live view: SSE stream with a replay mode. It shows the diff with suspect lines, a
  timeline, live sandbox output, the red-to-green moment, a wall of accumulated regression
  tests, and the counter of suspicions dropped for lack of proof.

## 10. Security model

- Model API calls happen in the orchestrator, outside the sandbox. The sandbox holds no
  secrets and has no network.
- `.env` and keys are git-ignored. API keys live in environment variables only.
- The PR diff is untrusted data. Model outputs are schema-validated. Models get no tools
  with side effects.
- GitHub Action: fork PRs get no secrets; never use `pull_request_target` to run
  untrusted code with secrets.
- Do not send third-party code to a provider without checking its data terms (free-credit
  terms may allow content to be used for product improvement).

## 11. Evaluation

Every module sits behind a flag so it can be ablated.

- **Corpus**: real CVEs (vulnerable and fixed commits) plus clean diffs.
- **Baseline**: a naive "LLM reports everything".
- **Ablations**: baseline; failing test only; no differential verification; no defender;
  full system.
- **Oracle evaluation set**: true exploits, wrong-reason failures, flaky tests, cheating
  tests.
- Metrics: proven findings, false positives, recall (reported honestly), discarded
  suspicions, tokens and cost per proven finding.

## 12. Scope tiers

**Core**: what the implementation aims to provide. Current status:

- loop: implemented (BASELINE → SUSPECT → EXPLOIT → RUN → VERDICT → FIX → VERIFY → PACKAGE).
- clone sandbox: implemented (hardened Docker runner with image build); tests require Docker.
- baseline check: implemented (runs inside the isolated, resource-limited sandbox via `SandboxRunner`).
- oracle with provenance: implemented (canary + stack-provenance checks).
- differential gating & repeated runs: implemented in the loop (N runs; since A-22/T078 the exploit passing on the fixed code and the fixed baseline passing gate every `proven`, section 4).
- vulnerability classes: four oracle effects realised on corpus cases: path traversal (`canary_read`), archive extraction (`canary_write`), command injection and unsafe deserialization (`canary_exec`), and SQL injection (`canary_sql`); SSRF is not a v1 class.
- PR-diff surface: implemented (T075): `exhibit-a run --pr-diff BASE..HEAD` verifies the changed Python files, exit codes 0/10/20/2 (`docs/reference/cli-exit-codes.md`); the GitHub Action calls it (T082).
- ledger: implemented (append-only JSONL).
- benchmark with ablations: bench corpus and probe tooling present; replay-driven cases work.
- minimal live view: minimal replay-backed live pieces implemented, plus local read-only dashboard (`exhibit-a dashboard`).
- CLI: complete suite of subcommands (`scan`, `run`, `ledger`, `trace`, `report`, `runs`, `advisories`, `dashboard`, `audit`, `doctor`, `reproduce`, `sarif`, `verify`); every CLI mode runs baseline and exploit tests in the isolated, resource-limited sandbox (`SandboxRunner`).
- slicing: AST static call graph slicing (`--slice`), enabled by default with `--profile compact`.
- proof bundles: signed `manifest.json`, offline `verify`, and sandbox `reproduce`.
- findings grouping: deduplication collapses duplicate proofs sharing entry point and sink call chain.
- model providers: Meta (primary) and Baseten (comparison and fallback).

**Should**: CVE reachability, attack-surface map, open-weight models for adversary and test
writer, GitHub Action, replay mode, defender bypass, cost meter, oracle evaluation set.

**Stretch**: dependency-update surface, multimodal bug-report ingestion (SAM 3.1), small-model
scanner, second language adapter, variant analysis, property-based fuzzing, mutation check,
severity from evidence, SARIF/Checks API, triage memory.

Language for v1: Python (pytest).

### Gates

- End of Oct 28: the loop closes red-to-green on a real CVE.
- Oct 31: oracle evaluation done; cut surface 2 if it fails.
- Nov 2: feature freeze.
- Nov 3: demo video, README, X post.
- Nov 4: buffer. Submission deadline 9:00 PM ET (8:00 PM Mexico City).

## 13. Extension points

`VulnClass`, `LanguageAdapter`, `Surface`, `ModelRole`. A runner contract plus a language
adapter is what allows a second language later.

## 14. Open decisions

- Final three vulnerability classes.
- First target project and CVE.
- Whether Meta's API is OpenAI-compatible with structured outputs (reported, **unverified**:
  check dev.meta.ai). Pricing of Muse Spark models is also unverified.
- Provider data terms.
- Whether multimodal ingestion is built.
Resolved / updated:

- First target project and CVE: resolved — the first real-case exercised end-to-end is
  Starlette `StaticFiles` path traversal (CVE-2023-29159), see `docs/design/first-cve.md` and the
  `bench/corpus/starlette-cve-2023-29159` case. The test package produced by the run is
  validated by `tests/test_e2e_cve.py`.

- Vulnerability classes: resolved — four oracle effects realised across corpus cases: path traversal read (`canary_read`), archive extraction write (`canary_write`), command injection and unsafe deserialization (`canary_exec`), and SQL injection (`canary_sql`).

- Provider shape: resolved — the implementation uses an OpenAI-compatible request shape
  with provider factories and provider subclasses for Meta and Baseten (`src/exhibit_a/models/config.py`,
  `src/exhibit_a/models/meta.py`, `src/exhibit_a/models/baseten.py`). HOWEVER, Meta endpoint specifics,
  the `response_format` structured-output support, and the pricing table remain UNVERIFIED and must be checked
  against `dev.meta.ai` before relying on them.

Still open / UNVERIFIED:
- Which specific Meta model serves each role (to be decided by measurement and gating).
- Provider data terms and full pricing confirmation.
- Whether multimodal ingestion is built.

## 15. Hackathon rules compliance

- Built entirely during the build period (Oct 27 - Nov 4); every line written new; the git
  history shows it.
- Public repository.
- The demo shows only what was built during the event.
- Results and demo come from Meta models: **true for the two vulnerable corpus cases.** With
  `--profile compact`, `muse-wonder-1.0` answered every role and both the Starlette CVE and the
  archive-extraction case ended `proven` with a verified fix, for US$0.17 in total
  (`bench/corpus/*/recordings/meta-muse-wonder-1.0-compact.*`, `docs/bench/meta-run.md`); the
  recordings replay offline. The earlier standard-profile run of all three cases proved nothing
  and is kept as recorded. The `replay.jsonl` files in the Starlette cases remain hand-authored.
- Never commit keys or tokens.
