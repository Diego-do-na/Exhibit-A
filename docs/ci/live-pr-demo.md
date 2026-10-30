# Live pull-request demo: runbook

This is the one procedure to run the GitHub Action on real pull requests. It uses the demo
app in `examples/action-demo/` and two prepared changes: one that introduces a provable
path traversal (the check should go **red**) and one harmless refactor (the check should stay
**green**, meaning "nothing could be proven", never "safe").

Until the steps below are done the workflow does nothing: both jobs stay skipped unless the
repository variable `EXHIBIT_A_ENABLED` is `true`. This procedure was prepared and tested
without running on GitHub, so the first run is the first real test of the Action end to end.

## What the workflow does on this repository

- Triggers only for same-repository pull requests that change `examples/action-demo/**`.
  Fork PRs are not analysed: the `fork-guard` job fails them with a notice.
- Builds a throwaway repository whose root is `examples/action-demo`, containing only the
  base and head versions of that directory, and analyses that. The engine stages the whole
  working directory and runs its baseline on it, so this keeps this repository's own tests
  and sources out of the run. Files changed elsewhere in the same PR are not analysed.
- Runs `exhibit-a run --pr-diff ... --provider meta --model muse-wonder-1.0 --profile compact`
  with `--budget-usd 1` and a 20-minute limit, after a required-reviewer approval of the
  `exhibit-a` environment.

## 1. One-time setup (GitHub)

All names below are exact; values are yours and never go in the repository.

1. **Merge the task branch into `main`** and note the merged commit:
   `git rev-parse origin/main`.
2. **Pin the Action.** In `.github/workflows/exhibit-a.yml` replace
   `diego-do-na/Exhibit-A@TODO-pin-full-commit-sha` with the 40-character SHA from step 1
   (commit it to `main`). It must be a commit that contains the `profile` input.
   Do not use `./`: that would run the `action.yml` of the pull request itself.
3. **Create the environment** `exhibit-a` (Settings, Environments) and add yourself as a
   required reviewer. Restrict deployment branches if you like; the demo PRs come from
   branches of this repository.
4. **Add the secret** to that environment, name `EXHIBIT_A_API_KEY`, value your Meta Model
   API key. From a terminal, which prompts for the value so it never lands in shell history
   or the repo: `gh secret set EXHIBIT_A_API_KEY --env exhibit-a`.
5. **Set the repository variable** `EXHIBIT_A_ENABLED` to `true`:
   `gh variable set EXHIBIT_A_ENABLED --body true`.
6. Optional: in branch protection mark `exhibit-a / verify` and `exhibit-a / fork-guard`
   as required checks.

## 2. Create the two branches

From a clean checkout of this repository with `main` up to date:

```bash
scripts/action-demo.sh
```

It creates the local branches `demo/path-traversal` and `demo/harmless-refactor` from `main`
by applying the patches, then prints the exact commands to publish them. It never pushes,
never calls GitHub and never reads a secret. It refuses to run on a dirty tree, when `main`
has no demo app, or when a demo branch already exists (delete it with `git branch -D`).
`BASE_BRANCH` and `DEMO_PREFIX` override the defaults.

## 3. Open the two pull requests

Run the commands the script printed (they need the `gh` CLI logged in):

```bash
git push -u origin demo/path-traversal
gh pr create --base main --head demo/path-traversal --title "..." --body "..."

git push -u origin demo/harmless-refactor
gh pr create --base main --head demo/harmless-refactor --title "..." --body "..."
```

For each PR, open the pending `Exhibit A` run (Actions tab) and approve the `exhibit-a`
environment. The job starts only after that.

## 4. What each check should show

| PR | Expected check | Comment and summary | Why |
|---|---|---|---|
| `demo/path-traversal` | red, `exhibit-a / verify` failed | `Status: completed`, `proven: 1` or more, a "Proven findings" table | the patch removes the containment check, so a request for `../outside.txt` reads outside the shelf |
| `demo/harmless-refactor` | green | `Status: completed`, `proven: 0` | behaviour is unchanged; "nothing could be proven" does not mean the code is safe |

The engine is a model-driven search, so a run can differ: the traversal PR can come back
green if the model never raises the suspicion (a miss, not a proof of safety), and any PR
goes red with an error if the run is incomplete (timeout, Docker or model failure). Re-run
the job (Actions, "Re-run all jobs") before drawing conclusions, and report both outcomes.

## 5. How to read the comment and the artifact

- **PR comment** (one per PR, updated in place on each push, found by a hidden marker and
  the `github-actions[bot]` author): headline, `Status`, suspicions raised / proven / dropped
  without proof, the risk gate, tokens and cost, a verdict table
  (`proven`, `discarded_unproven`, `invalid_test`, `flaky`, `env_failure`) and, if anything is
  proven, a table with the suspicion id, whether the fix was verified and the oracle's reason.
- **Job summary** (the run page): the same text.
- **Artifact** `exhibit-a-ledger` (14 days): `ledger.jsonl` (every event of the run, the
  source of truth), `result.json` (machine-readable summary, `schema_version` 1) and
  `summary.md`. Download it and inspect the ledger:
  `python -m json.tool < result.json`, then `grep '"type": "verdict"' ledger.jsonl`.
  It contains no clone and no logs. The Action also scans every output for the API key
  before uploading and refuses to publish if it finds it.

## 6. Disable it afterwards

- Fast: set the variable to anything but `true`, or delete it:
  `gh variable delete EXHIBIT_A_ENABLED`. Both jobs are skipped again.
- Thorough: also delete the secret (`gh secret delete EXHIBIT_A_API_KEY --env exhibit-a`),
  delete the `exhibit-a` environment, and close the two PRs without merging
  (`gh pr close <number> --delete-branch`). Never merge `demo/path-traversal`.
- Rotate the Meta API key if you ever pasted it anywhere other than the `gh secret set` prompt.

## 7. Expected cost

The run is capped: `--budget-usd 1` is a hard stop on model spend, `--profile compact`
bounds each answer, and the job has a 20-minute limit. For scale, the compact profile cost
about US$0.31 for the whole benchmark corpus (`docs/bench/bench.md`). One demo PR is a single
file, so expect well under US$1 per run, but that is an estimate: it has not been measured
on GitHub. Each run also uses GitHub-hosted runner minutes (a few minutes on a public
repository, which are free; check your plan for a private one). Re-runs and new pushes to
a PR spend again; a new push cancels the superseded run.
