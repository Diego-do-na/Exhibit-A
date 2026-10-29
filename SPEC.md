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

Declared residual limits of the oracle (`docs/oracle-provenance.md` section 7; each is
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
- **Oracle**: observes the intended effect and checks provenance.
- **Roles** behind one `ModelRole` interface: adversary, test writer, fixer, defender.

### Model providers

- `replay`/mock (deterministic, for tests and the demo replay mode)
- `ollama` (plumbing and debugging only)
- Meta Model API, and Meta open-weight models through an inference partner
  (OpenAI-compatible endpoint)
 
Implemented provider registry and factories: `replay`, `ollama`, `openai_compatible`, and
`meta` (see `src/exhibit_a/models/config.py`). The code consumes provider implementations
through an OpenAI-compatible request shape and exposes a `MetaProvider` subclass that
reuses the OpenAI-compatible plumbing.

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
              "oracle": {}, "provenance": {}},
 "fix": {"patch_path": ""},
 "bypass_attempts": {"tried": 0, "succeeded": 0}}
```

Event line (ledger):
```json
{"ts": "", "run_id": "", "type": "", "role": "", "model": "",
 "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0, "latency_ms": 0, "payload": {}}
```

Event types: `pr_opened`, `scan_done`, `baseline_done`, `suspicion_raised`,
`exploit_written`, `run_started`, `oracle_event`, `verdict`, `fix_proposed`,
`bypass_attempt`, `bypass_result`, `packaged`.

## 7. Vulnerability classes (v1)

Three classes, chosen by what can be proven by execution with a clear oracle:

1. Broken authorization (access to another user's resource).
2. Path traversal (read effect: a canary file outside the allowed directory is read) and
   archive extraction / zip-slip (write effect: a canary file outside the extraction
   directory is written). SSRF is not a v1 class: a faithful effect needs a network, which
   the sandbox forbids (see `docs/second-class.md`).
3. A simple warm-up class: reflected XSS or SQL injection.

Final choice is an open decision (section 14).

Status update: path traversal (read) is implemented in the loop and exercised by the
project's first real-case corpus entry (Starlette `StaticFiles` path traversal,
CVE-2023-29159). Archive extraction (write) runs through the loop and the sandbox (T076,
`canary_write` effect) on a synthetic corpus case (`bench/corpus/archive-extraction-pathtraversal`),
not on a real CVE. Broken authorization and the warm-up class are in scope for v1 but are
not realised.

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
- baseline check: implemented (local/host baseline runner present; some corpus cases still run baseline as a host child process).
- oracle with provenance: implemented (canary + stack-provenance checks).
- differential gating & repeated runs: implemented in the loop (N runs; since A-22/T078 the exploit passing on the fixed code and the fixed baseline passing gate every `proven`, section 4).
- vulnerability classes: path traversal (read) and archive extraction (write, synthetic case) realised; broken authorization and the warm-up class are not, and SSRF is not a v1 class.
- PR-diff surface: implemented (T075): `exhibit-a run --pr-diff BASE..HEAD` verifies the changed Python files, exit codes 0/10/20/2 (`docs/cli-exit-codes.md`); the GitHub Action calls it (T082).
- ledger: implemented (append-only JSONL).
- benchmark with ablations: bench corpus and probe tooling present; replay-driven cases work.
- minimal live view: minimal replay-backed live pieces implemented.
- CLI: `run` takes a benchmark case (`--replay` or live) or `--pr-diff`, with `--provider`/`--model`; `scan` is still a placeholder. The `--case` baseline still runs as a host child process.

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
  Starlette `StaticFiles` path traversal (CVE-2023-29159), see `docs/first-cve.md` and the
  `bench/corpus/starlette-cve-2023-29159` case. The test package produced by the run is
  validated by `tests/test_e2e_cve.py`.

- Provider shape: resolved — the implementation uses an OpenAI-compatible request shape
  with provider factories and a `MetaProvider` subclass that delegates to the
  OpenAI-compatible client (see `src/exhibit_a/models/config.py` and
  `src/exhibit_a/models/meta.py`). HOWEVER, Meta endpoint specifics, the `response_format`
  structured-output support, and the pricing table remain UNVERIFIED and must be checked
  against `dev.meta.ai` before relying on them.

Still open / UNVERIFIED:
- Final three vulnerability classes (path traversal read and archive-extraction write realised; broken authorization and the warm-up class not realised).
- Which specific Meta model serves each role (to be decided by measurement and gating).
- Provider data terms and full pricing confirmation.
- Whether multimodal ingestion is built.

## 15. Hackathon rules compliance

- Built entirely during the build period (Oct 27 - Nov 4); every line written new; the git
  history shows it.
- Public repository.
- The demo shows only what was built during the event.
- Results and demo come from Meta models: **pending, not yet true.** The only recordings in
  the repository are hand-authored (`"model": "hand-authored"` in both Starlette `replay.jsonl`
  files), no Meta-model recording or `docs/meta-run.md` exists, and the Meta endpoint is
  UNVERIFIED (section 14). Do not claim it until a live Meta run is recorded.
- Never commit keys or tokens.
