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

- A headless engine, driven by a CLI and (later) a GitHub Action.
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

**All benchmark and demo numbers must come from Meta models.** Every model call is recorded
and replayable. A cost meter enforces a hard stop below the credit limit.

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
2. Path traversal or SSRF (canary file / canary server).
3. A simple warm-up class: reflected XSS or SQL injection.

Final choice is an open decision (section 14).

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

**Core**: the loop, clone sandbox, baseline check, oracle with provenance, differential
verification, repeated runs, 3 vulnerability classes, PR-diff surface, ledger, benchmark
with ablations, minimal live view, CLI.

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
- Which Meta model serves each role (decided by measurement).
- Whether Meta's API is OpenAI-compatible with structured outputs (reported, **unverified**:
  check dev.meta.ai). Pricing of Muse Spark models is also unverified.
- Provider data terms.
- Whether multimodal ingestion is built.

## 15. Hackathon rules compliance

- Built entirely during the build period (Oct 27 - Nov 4); every line written new; the git
  history shows it.
- Public repository.
- The demo shows only what was built during the event.
- Results and demo come from Meta models.
- Never commit keys or tokens.
