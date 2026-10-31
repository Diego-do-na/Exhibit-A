# GitHub Action

Run Exhibit A on every pull request and use it as a **required status check**
that turns red only when a finding is `proven`.

The check is real: on a pull request the Action runs `exhibit-a run --pr-diff
BASE..HEAD` (T075, wired by T082) with the `provider` and `model` inputs passed as
`--provider`/`--model`. It also fails, never passes, when the engine is incomplete
(exit 20), rejects its input (exit 2), exits unexpectedly, or produces no verdicts
(`status: not_run`, `surface_ran: false`). Only a risk-gate skip of a docs/tests-only
change is green without a run.

A green check means **"nothing could be proven"**. It never means the change is
safe: the engine may not have reached the vulnerable path, or the run may have
been skipped by the risk gate. The job summary always states which of these
happened (`status`).

Security design and its reasons: [github-action-security.md](github-action-security.md).

## Files

| Path | What it is |
|---|---|
| `action.yml` | Composite action: install, risk gate, `exhibit-a run`, summary, PR comment, ledger artifact, gate. |
| `.github/workflows/exhibit-a.yml` | Hardened workflow template (opt-in via a repository variable). |
| `src/exhibit_a/ci/summary.py` | Ledger to result JSON, step-summary Markdown and PR comment. Pure functions. |
| `src/exhibit_a/ci/gate.py` | Rule-based risk gate from `git diff --name-only`. |
| `tests/test_ci_summary.py`, `tests/test_ci_gate.py` | Unit tests (no Docker, no network). |

## How a run goes

1. `actions/setup-python`, then Exhibit A is installed into a private venv from
   the action's own pinned checkout (never from the PR).
2. **Risk gate**: `git diff --name-only BASE...HEAD` is classified low, medium
   or high (rules below). Low risk (docs/tests only) skips the exploit run
   unless `risk-gate: "false"`.
3. **Run**: `exhibit-a run --repo <dir> --pr-diff <base>..<head> --out <tmp>
   --provider <provider> [--model <model>]` under `timeout
   <max-runtime-minutes>m` (exit codes in `docs/reference/cli-exit-codes.md`: 0 ran with
   nothing proven, 10 proven, 20 incomplete, 2 usage error). Exit 20, 2 or any
   unexpected code fails the check immediately; only 0, 10 and the timeout
   codes continue to the summary. This is the only step that sees the API key
   (never on the `case:` path, which runs replay-only with no key exported).
   Afterwards every output file is searched for the key; a hit deletes the
   output and fails the job, so nothing is published.
4. **Summary**: `python -m exhibit_a.ci.summary build` reads `ledger.jsonl` and
   writes `result.json`, `summary.md` (also appended to `$GITHUB_STEP_SUMMARY`)
   and `comment.md`, and sets the step outputs.
5. **Comment** (optional): one PR comment, found by a hidden marker
   (`<!-- exhibit-a:pr-comment v1 -->`) **and** the bot author, is updated in
   place; a human comment quoting the marker is never edited.
6. **Artifact**: `ledger.jsonl`, `result.json`, `summary.md` only. Not the clone,
   not the logs, not the diff.
7. **Gate**: exit 1 if `fail-on: proven` and at least one suspicion's latest
   `verdict` event is `proven`. A missing result (an earlier step crashed) and
   `status: not_run` also fail, even with `fail-on: never`, because then nothing
   was verified.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `provider` | `meta` | Provider for every role (`replay`, `ollama`, `openai_compatible`, `meta`). See Requires. |
| `model` | `""` | Model id for every role. See Requires. |
| `api-key` | `""` | Pass `${{ secrets.EXHIBIT_A_API_KEY }}` from a protected environment. |
| `api-key-env` | `META_API_KEY` | Variable the provider reads the key from (`MetaProvider` default). |
| `profile` | `standard` | Prompt profile passed to `--profile` (`standard` or `compact`). |
| `fail-on` | `proven` | `proven` or `never` (report only). |
| `working-directory` | `.` | Directory to analyse; must stay inside the workspace. |
| `max-runtime-minutes` | `30` | Hard wall-clock limit for the engine (1 to 360). |
| `budget-usd` | `""` | Passed to `--budget-usd` (hard cost stop). Strongly recommended. |
| `base-sha` | PR base SHA | Base commit of the diff; needs `fetch-depth: 0`. |
| `head-sha` | PR head SHA | Head commit of the diff. |
| `case` | `""` | Run a benchmark `case.json` instead of the PR diff (smoke test). |
| `replay` | `false` | Replay recorded model calls (with `case`). |
| `risk-gate` | `true` | `false` runs exploits even for docs/tests-only PRs. |
| `comment` | `false` | Post/update the PR comment (needs `pull-requests: write`). |
| `comment-author` | `github-actions[bot]` | Only this author's marker comment is updated. |
| `github-token` | `github.token` | Used only by the comment step. |
| `sarif` | `true` | Upload proven findings to GitHub Code Scanning as SARIF (needs `security-events: write`). |
| `python-version` | `3.11` | Python for the engine. |
| `artifact-name` | `exhibit-a-ledger` | Artifact name. |
| `artifact-retention-days` | `14` | Artifact retention. |

## Outputs

`status`, `proven`, `dropped`, `discarded-unproven`, `invalid-test`, `flaky`,
`env-failure`, `risk`, `result-json` (path on the runner).

`status` is one of:

| status | Meaning |
|---|---|
| `completed` | Baseline passed and every raised suspicion got a verdict. |
| `aborted` | Baseline failed, or suspicions were raised but not all judged. |
| `timed_out` | `max-runtime-minutes` hit (engine exit 124/137). |
| `not_run` | No ledger events: the engine crashed before any step ran. Fails the check (never a passing default). |
| `skipped` | The risk gate skipped the exploit run. |

Only `proven` changes the check colour. If you also want `aborted`,
`timed_out` or `not_run` to block merging, add a step after the action:

```yaml
- if: steps.exhibit.outputs.status != 'completed' && steps.exhibit.outputs.status != 'skipped'
  run: exit 1
```

## Result JSON (`schema_version: "1"`)

```json
{
  "schema_version": "1",
  "run_id": "...",
  "status": "completed",
  "skipped_reason": "",
  "engine_exit": 1,
  "proven": 1,
  "verdicts": {"proven": 1, "discarded_unproven": 2, "invalid_test": 0, "flaky": 0, "env_failure": 0},
  "suspicions_raised": 3,
  "dropped": 2,
  "findings": [{"suspicion_id": "...", "reason": "...", "fix_verified": true, "package": "packages/..."}],
  "flags": {"naive": false, "oracle": true, "differential": true, "defender": true},
  "ablated": false,
  "risk": {"risk": "medium", "should_run_exploits": true, "reasons": {"src/app.py": "medium: application code"}},
  "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0
}
```

Only `verdict` ledger events count; text in other events that says "proven" is
ignored. The latest verdict per suspicion wins. `ablated: true` means the run
used benchmark ablation flags and does not meet the full proof standard.

## Risk gate

`exhibit_a.ci.gate.RULES` is an ordered, data-driven table; the first matching
rule decides a path, the highest risk decides the PR:

- **high**: `.github/workflows/*`, `.github/actions/*`, `action.yml`;
  dependency manifests and lock files (`requirements*.txt`, `pyproject.toml`,
  `setup.py`, `poetry.lock`, `uv.lock`, ...); `Dockerfile*`, compose files;
  any path under a sensitive directory (`auth`, `security`, `crypto`,
  `secrets`, `permissions`, `sandbox`, `oracle`, `middleware`, `.github`, ...).
- **low**: documentation (`docs/`, `*.md`, `*.rst`, `LICENSE`) and tests
  (`tests/`, `test_*.py`, `*_test.py`, `conftest.py`).
- **medium**: everything else.

`should_run_exploits(risk)` is false only for low. An empty diff is low.

**Future merge point**: a separate task owns a richer triage module
(`src/exhibit_a/triage/`). When it lands, `ci/gate.py` should delegate
`classify` to it and keep the `Classification` / `should_run_exploits`
interface so `action.yml` does not change. This task deliberately does not
create `triage/`.

## What the Action does today

- **PR runs** (the default): the Action passes the validated 40-hex `BASE..HEAD`
  SHAs to `exhibit-a run --pr-diff` with `--provider "$provider"` and, when set,
  `--model "$model"`. The engine verifies the changed regular Python files of the
  diff through the sandbox-backed loop (bounded file count and size) and writes
  `ledger.jsonl` and `result.json` to `--out`.
- **Exit codes** (`docs/reference/cli-exit-codes.md`): `0` the diff ran and nothing was
  proven (this includes a diff with no runnable Python files), `10` at least one
  finding was proven, `20` the run was incomplete (timeout, environment failure or
  model error), `2` usage or input error (for example an unsupported provider or a
  malformed `BASE..HEAD`). The Action continues to the summary on `0` and `10` and
  on the `timeout` codes 124/137; `20`, `2` and any other code fail the check at
  once, so a crash never looks green.
- **Provider and model**: `provider` (default `meta`) and `model` are honoured. The
  Meta endpoint, structured-output support and pricing are still UNVERIFIED
  (`SPEC.md` section 14), and no Meta-model run has been recorded, so choose the
  provider deliberately and set `budget-usd`.
- **`case:` smoke test**: `case:` + `replay: "true"` runs a benchmark case end to end
  (e.g. `bench/corpus/starlette-cve-2023-29159`), which is the way to smoke-test the
  Action on a runner with Docker. `case:` without `replay: "true"` is refused, and no
  key is exported on the `case:` path.
- **Not done**: an internal `--max-runtime` deadline (the `timeout` wrapper kills the
  process instead, so no final ledger event is written); `ci/gate.py` does not yet
  delegate to `src/exhibit_a/triage/`.

## Setup in GitHub (step by step)

1. **Pin the action.** In `.github/workflows/exhibit-a.yml`, replace
   `diego-do-na/Exhibit-A@TODO-pin-full-commit-sha` with the full 40-character
   SHA of a reviewed commit (add the version as a trailing comment).
2. **Environment.** Settings, Environments, New environment, name `exhibit-a`:
   - Required reviewers: add at least one trusted maintainer (enable "Prevent
     self-review" if available).
   - Deployment branches and tags: leave "No restriction". PR runs use
     `refs/pull/N/merge`, which branch filters would block; the reviewer
     approval is the gate.
3. **Secret.** In that environment (not repository-wide), add
   `EXHIBIT_A_API_KEY`: a dedicated key used only for this, with a hard spend
   cap set at the provider.
4. **Enable.** Settings, Secrets and variables, Actions, Variables: add the
   repository variable `EXHIBIT_A_ENABLED` = `true`. Until then both jobs are
   skipped.
5. **Actions policy.** Settings, Actions, General:
   - Workflow permissions: "Read repository contents and packages permissions".
     When `sarif: true` is enabled (the default), the calling workflow job also requires
     `security-events: write` permissions so results can be uploaded to GitHub Code Scanning.
   - Fork pull request workflows: require approval for all outside collaborators.
   - Allowed actions: restrict to `actions/*` and `diego-do-na/Exhibit-A@*`;
     if offered, enable "Require actions to be pinned to a full-length commit SHA".
6. **CODEOWNERS.** Require owner review for `.github/workflows/` (and, in the
   Exhibit A repository, `action.yml`).
7. **Open one PR** so the checks appear, approve the `exhibit-a` deployment,
   and confirm the run.
8. **Required checks.** Settings, Rules (or Branches), on the default branch:
   require status checks `exhibit-a / verify` **and** `exhibit-a / fork-guard`.
   Both are needed: a skipped job reports success, so `verify` alone would let
   fork PRs pass unanalysed.

Caveat: if `EXHIBIT_A_ENABLED` is later removed, both jobs skip and the
required checks pass. Treat the variable as part of the protected setup.

## Limits

- Fork PRs are not analysed (see the security doc).
- Each same-repository PR run waits for a reviewer's approval.
- Docker must be available on the runner (it is on `ubuntu-latest`).
- The engine's own limits apply: path traversal (read) and archive extraction (write) are the realised classes, and the oracle has declared residual limits R1-R6 (see `SPEC.md` and `docs/oracle/oracle-provenance.md` section 7). A green check means nothing could be proven, not that the change is safe.
