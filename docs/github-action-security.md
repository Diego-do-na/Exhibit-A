# GitHub Action: security model

The Action runs a security tool on untrusted code (the pull request) with a
paid API key nearby. Each control below says what it is, where it is
enforced, and why. The exploit and baseline tests themselves run in the
engine's isolated, resource-limited Docker sandbox (no network, no secrets,
see `sandbox.md`); this document covers the CI layer around it.

## Controls

| Control | Enforced in | Why |
|---|---|---|
| Trigger is `pull_request`, never `pull_request_target` | workflow `on:` | `pull_request_target` runs in the base repository's context with secrets and a write token; checking out the PR head there hands both to untrusted code. |
| Same-repository PRs only | `verify` job `if:` | Fork PRs are out of scope (below). |
| Failing `fork-guard` job | workflow | A skipped job reports success to branch protection; without a failing twin, fork PRs would pass the required check silently. |
| Protected `environment: exhibit-a` with required reviewers | `verify` job | The key is an environment secret, released only after a human approves this run, after looking at the PR (including any change to workflows). |
| `permissions: {}` at the top; job gets `contents: read` and `pull-requests: write` (comment only) | workflow | Least privilege for `GITHUB_TOKEN`. Drop `pull-requests: write` when `comment: "false"`. The fork guard gets none. |
| `persist-credentials: false` | `actions/checkout` | The token is not left in `.git/config` for later steps or PR code to read. |
| Key only in one step | `action.yml` "Run Exhibit A" | The key is an input materialised only in that step's environment, copied to the provider's variable and unset under its input name. Other steps, including the comment and upload steps, never have it. It is never printed. |
| Leak scan before publishing | `action.yml` "Run Exhibit A" | After the run every output file is searched for the key (pattern passed via a file descriptor, not argv). A hit deletes the output, fails the job, and skips summary, comment and artifact. |
| Minimal artifact | `action.yml` upload | Only `ledger.jsonl`, `result.json`, `summary.md`: no clone, diff, or logs. |
| Third-party actions pinned by full commit SHA | `action.yml`, workflow | Tags are mutable; a SHA is not. Pins verified with `git ls-remote` on 2026-10-29: `actions/checkout` v7.0.1 `3d3c42e5aac5ba805825da76410c181273ba90b1`, `actions/setup-python` v7.1.0 `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0`, `actions/upload-artifact` v7.0.2 `cf430e030ddbb5b0abf93d22962f4752f3646cd9`. The Exhibit A action itself is a **TODO placeholder** in the template: pin it to a reviewed commit SHA. |
| Never `uses: ./` in the template | workflow | `./` runs the `action.yml` from the PR head, which the PR author controls. |
| Engine installed from the action's checkout | `action.yml` | The PR cannot change the code that judges it. Nothing from the PR is installed or executed on the host; the Action reads it only with `git diff --no-ext-diff --no-textconv`. |
| No `${{ }}` inside scripts | `action.yml` | Inputs reach bash through `env:` only, and are validated (enums, integers, variable-name regex, workspace-contained path), so a crafted input cannot inject shell. |
| Untrusted text escaped | `ci/summary.py` | Suspicion ids and reasons come from models reading the PR. HTML, Markdown links, table pipes, newlines and `@mentions` are neutralised; the comment marker is stripped so model text cannot hijack the comment. |
| Comment updated only if bot-authored | `ci/summary.py` `find_marker_comment` | A human comment that quotes the marker is never overwritten. |
| Timeouts | job `timeout-minutes: 45`, step `timeout <max-runtime-minutes>m` | Bounded runner time and cost. |
| Cost cap | `budget-usd` input, provider-side cap | The engine's cost meter stops the run; a dedicated key with a hard spend limit at the provider is the backstop. |
| Concurrency | `concurrency: exhibit-a-<PR>`, `cancel-in-progress: true` | A new push cancels the superseded run instead of paying twice. |
| Opt-in variable | `vars.EXHIBIT_A_ENABLED` | The template is inert until the environment and secret exist. |

## Why fork PRs are out of scope

GitHub does not give secrets to `pull_request` runs from forks, so the engine
would have no model key. The ways around that (`pull_request_target`,
`workflow_run` passing artifacts to a privileged job, a self-hosted runner)
all put a secret and untrusted code in the same trust domain, or need a
second, carefully isolated pipeline. That is not worth the risk for this
release. Fork PRs get a red `fork-guard` check and a summary saying nothing
was verified; a maintainer reviews them by hand (or, after review, pushes the
branch into the base repository so `verify` runs).

## Dedicated, capped key

Use a key created only for this workflow, stored only as an environment
secret, with a provider-side spend limit and alerting. If it leaks, the blast
radius is one capped budget, and rotating it touches nothing else. Check the
provider's data terms before sending third-party code (SPEC.md section 10).

## Residual risks (stated, not solved)

- **Reviewer approval is the real gate.** A same-repository PR can change
  workflow files; GitHub runs the PR's version of the workflow. The approver
  must look at `.github/` changes before approving (the risk gate marks them
  high). CODEOWNERS on `.github/` helps.
- **Host-side engine steps.** The engine process has the key in its
  environment. Case runs install pinned requirements with `pip` on the host
  and, in replay mode, run the case baseline in a scrubbed host child process
  (only `PATH`/`PYTHONPATH`). Exploit tests and live-mode baselines run in
  the sandbox, which never receives the key.
- **Leak scan is literal.** It finds the key verbatim, not encoded or split.
  The sandbox having no network and no key is the main control; the scan is
  a backstop.
- **Skipped means success.** If `EXHIBIT_A_ENABLED` is removed, both
  required checks skip and pass.
- **Green is not safe.** `not_run`, `skipped`, `aborted` and `timed_out`
  are green under `fail-on: proven`; the summary says so, and
  `github-action.md` shows how to block on them.
