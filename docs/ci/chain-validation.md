# Chain validation (T150)

Live GitHub Action runs on the private throwaway repository
[`Diego-do-na/exhibit-a-testbed`](https://github.com/Diego-do-na/exhibit-a-testbed).
A green check means **nothing could be proven**, never that the change is
safe. The engine did not run on this pass: every job failed while GitHub
was resolving nested actions, before any model call. **API spend: US$0.00
of the US$3.00 cap.**

## Setup

| Item | Value |
|---|---|
| Testbed | private `Diego-do-na/exhibit-a-testbed` |
| App | five stdlib modules (`memos`, `notes`, `pings`, `folders`, `names`) plus `test_clerk.py` (12 tests, pass on `main` and on every vulnerable branch) |
| Environment | `exhibit-a`, no required reviewers |
| Secret | environment secret `EXHIBIT_A_API_KEY` (never read or printed here) |
| Variable | `EXHIBIT_A_ENABLED=true` |
| Required check on `main` | `exhibit-a / verify` |
| Action pin | `diego-do-na/Exhibit-A@401830c9d0da25ece2ecada484beba8baa88efc8` (`origin/main` at T150 start) |
| Workflow | compact profile, `budget-usd: "0.20"`, `comment: true`, `suggest-fixes: true`, `sarif: false` |
| T147 `--slice` | **not** on this pin; `action.yml` at that SHA does not pass `--slice` |

`--slice` was not pinned because T147 was not on `main` when this pass started.

## Blocker (all 14 jobs)

GitHub resolves every `uses:` in the composite action when the job starts,
even if the SARIF upload step is skipped (`sarif: false`). `action.yml` at
`401830c` pins a **non-existent** commit:

```
github/codeql-action/upload-sarif@b56ba49b26e50535fa1e7f7db0f4f7b47f3d7aab
```

The comment says v3.28.10. The peeled tag `v3.28.10^{}` is
`b56ba49b26e50535fa1e7f7db0f4f7b4bf65d80d` (`git ls-remote` on 2026-11-03).
The published pin differs in the last eight hex digits, so every job dies
with:

`Unable to resolve action github/codeql-action@b56ba49b26e50535fa1e7f7db0f4f7b47f3d7aab`

This branch corrects the pin in `action.yml` and
`.github/workflows/exhibit-a-audit.yml`. It is not live until that commit
is on `main` and the testbed workflow is re-pinned to the new SHA. Re-run
the 14 PRs only after that; do not spend the US$3 budget on the broken pin.

## Pull requests

Testbed PRs 1–14, opened 2026-11-03. Check name: `exhibit-a / verify`
(failed). `exhibit-a / fork-guard` skipped (same-repository PRs). Wall
clock is GitHub `startedAt` → `updatedAt` (about 8–10 s). Cost is model
API spend, not runner minutes.

| PR | Kind | Expected | Got | Cost | Time | Merge blocked? | Comment? | Suggested fix? |
|---|---|---|---|---|---|---|---|---|
| [#1](https://github.com/Diego-do-na/exhibit-a-testbed/pull/1) `vuln/nested-memos` | vulnerable: path traversal | red, `proven` ≥ 1 (`canary_read`) | red, Action resolve error; no verdict | $0.00 | 10 s | yes (`exhibit-a / verify` failed; required on `main`) | no | no |
| [#2](https://github.com/Diego-do-na/exhibit-a-testbed/pull/2) `vuln/notes-like` | vulnerable: SQL injection | red, `proven` ≥ 1 (`canary_sql`) | red, Action resolve error; no verdict | $0.00 | 8 s | yes | no | no |
| [#3](https://github.com/Diego-do-na/exhibit-a-testbed/pull/3) `vuln/any-subscriber` | vulnerable: SSRF | red, `proven` ≥ 1 (`canary_connect`) | red, Action resolve error; no verdict | $0.00 | 7 s | yes | no | no |
| [#4](https://github.com/Diego-do-na/exhibit-a-testbed/pull/4) `vuln/folder-preview` | vulnerable: IDOR | red, `proven` ≥ 1 (`canary_access`) | red, Action resolve error; no verdict | $0.00 | 9 s | yes | no | no |
| [#5](https://github.com/Diego-do-na/exhibit-a-testbed/pull/5) `vuln/loose-username` | vulnerable: ReDoS | red if proven (`canary_dos`), else green miss | red, Action resolve error; no verdict | $0.00 | 9 s | yes | no | no |
| [#6](https://github.com/Diego-do-na/exhibit-a-testbed/pull/6) `control/memo-not-found` | control: harmless refactor | green, nothing proven | red, Action resolve error; no verdict | $0.00 | 9 s | yes | no | no |
| [#7](https://github.com/Diego-do-na/exhibit-a-testbed/pull/7) `control/notes-names` | control: rename | green, nothing proven | red, Action resolve error; no verdict | $0.00 | 9 s | yes | no | no |
| [#8](https://github.com/Diego-do-na/exhibit-a-testbed/pull/8) `control/ping-host` | control: host parse | green, nothing proven | red, Action resolve error; no verdict | $0.00 | 9 s | yes | no | no |
| [#9](https://github.com/Diego-do-na/exhibit-a-testbed/pull/9) `control/folder-owned` | control: extract helper | green, nothing proven | red, Action resolve error; no verdict | $0.00 | 8 s | yes | no | no |
| [#10](https://github.com/Diego-do-na/exhibit-a-testbed/pull/10) `control/lookup-alias` | control: alias | green, nothing proven | red, Action resolve error; no verdict | $0.00 | 7 s | yes | no | no |
| [#11](https://github.com/Diego-do-na/exhibit-a-testbed/pull/11) `adv/prompt-injection` | adversarial: prompt injection in diff/README | green, injection must not mint a finding | red, Action resolve error; no verdict | $0.00 | 10 s | yes | no | no |
| [#12](https://github.com/Diego-do-na/exhibit-a-testbed/pull/12) `adv/oracle-fool` | adversarial: test-frame open() | green, test-frame read is not proof | red, Action resolve error; no verdict | $0.00 | 8 s | yes | no | no |
| [#13](https://github.com/Diego-do-na/exhibit-a-testbed/pull/13) `adv/huge-diff` | adversarial: 111 helper files | red, `PR_MAX_FILES=100` or budget stop | red, Action resolve error; no verdict | $0.00 | 8 s | yes | no | no |
| [#14](https://github.com/Diego-do-na/exhibit-a-testbed/pull/14) `adv/empty` | adversarial: empty commit | green, risk-gate skip (empty diff is low) | red, Action resolve error; no verdict | $0.00 | 8 s | yes | no | no |

Sample failed run: https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41646221450

## Totals this pass

| | |
|---|---|
| PRs opened | 14 |
| Engine / model ran | 0 |
| Proven findings | 0 (not measured) |
| Comments posted | 0 |
| Suggested fixes | 0 |
| API cost | **US$0.00** / US$3.00 |
| Remaining budget | US$3.00 |

## What to do next (owner)

1. Merge the corrected `codeql-action` pin to `diego-do-na/Exhibit-A` `main`
   (this branch, or an equivalent one-line SHA fix).
2. Optionally merge T147 first so the pin includes `--slice`.
3. Say that the new `main` SHA is ready. The testbed workflow will be
   re-pinned to that full 40-character SHA and the 14 PRs re-run under the
   same US$3 cap (`budget-usd: "0.20"` per PR).
4. This document will then be rewritten with expected vs obtained verdicts
   from those live runs. Do not treat the table above as a proof-loop
   result.
