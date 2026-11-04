# Exhibit A video recording runbook

This runbook records the three-minute demo in `docs/video/script.md`. Prefer
recorded GitHub results and replay data. Do not start a new paid model run
while recording unless the owner explicitly approves it.

## Pre-flight checklist

- [ ] Docker or Colima is running and responsive; sandbox tests must not be
      treated as passing when Docker is unavailable.
- [ ] The worktree and browser are on the intended Exhibit A commit.
- [ ] The desktop is clean: no personal folders, notifications, private
      documents, mail, or unrelated applications visible.
- [ ] Browser zoom is 110–125%; use night mode consistently for the capture.
- [ ] Close all personal tabs. Keep only the testbed PR, the dashboard, and
      the Exhibit A repository pages needed for the shot.
- [ ] Confirm the GitHub account is the demo account and the repository is the
      intended private testbed.
- [ ] Never show `META_API_KEY`, `EXHIBIT_A_API_KEY`, `GH_TOKEN`, environment
      settings, shell history, or any secret-bearing terminal output.
- [ ] Check that the one-time dashboard link is available. It contains a
      session token; show only the browser page after opening it.
- [ ] Record at 1920×1080 or 2560×1440, with system audio off unless narration
      is being captured separately.
- [ ] Keep the browser address bar visible only when the URL is part of the
      scene; crop or blur one-time tokens.

## Evidence and cost guardrails

The video uses the live pass documented in
[`docs/ci/chain-validation.md`](../ci/chain-validation.md). It recorded
US$0.0629 for PR #1 and US$0.0056 for the control PR #6, for US$0.0685 total.
The other control and adversarial PRs used US$0.00. The dashboard is read-only
and does not make model calls. The compact benchmark references in the script
are recorded offline numbers, not new spend.

The testbed pass is deliberately shown honestly: PRs #2–#5 are green misses
because the compact Action run sliced for `canary_read`; they are not evidence
that SQL injection, SSRF, IDOR, or ReDoS are safe. The recorded compact
benchmark headline is 29 reported, 25 true positives, 4 false positives, 0
false accusations, 15 discarded, 140 calls, and US$2.2727 cost.

## Scene commands and URLs

Run commands from the repository root unless stated otherwise. The commands
below are display-safe; they do not print secret values.

| Scene | Action | Exact command or URL | Estimated API cost |
|---|---|---|---:|
| Hook | Open the recorded vulnerable PR and place the alert comparison card beside it. | `https://github.com/Diego-do-na/exhibit-a-testbed/pull/1` | US$0.00 new spend |
| Thesis | Show the proof contract and CLI surface. | `sed -n '1,90p' SPEC.md` then `PYTHONPATH=src python -m exhibit_a.cli run --help` | US$0.00 |
| Live demo | Open the PR, expand the failed check, then show the bot comment and review suggestion. | `gh pr view 1 --repo Diego-do-na/exhibit-a-testbed --web` | US$0.0629 recorded |
| Live demo | If the Actions page is needed, open the exact recorded run. | `https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41650269331` | US$0.00 new spend |
| Control | Show the harmless refactor and its green result. | `https://github.com/Diego-do-na/exhibit-a-testbed/pull/6` | US$0.0056 recorded |
| Adversarial | Show prompt injection and test-frame reads being ignored. | `https://github.com/Diego-do-na/exhibit-a-testbed/pull/11` and `https://github.com/Diego-do-na/exhibit-a-testbed/pull/12` | US$0.00 recorded |
| Dashboard | Start the read-only GitHub-backed dashboard. | `exhibit-a dashboard --source github:Diego-do-na/exhibit-a-testbed` | US$0.00 |
| Dashboard | Use the one-time `http://127.0.0.1:<port>/auth?token=...` link printed by the command; do not record the token in a terminal close-up. | Browser URL printed at launch | US$0.00 |
| Numbers | Show the recorded chain totals and benchmark rows. | `sed -n '145,170p' docs/ci/chain-validation.md` then `sed -n '35,42p' docs/bench/bench.md` | US$0.00 |
| Closing | Return to the proof comment and repository landing page. | `https://github.com/Diego-do-na/Exhibit-A` | US$0.00 |

### Dashboard capture

Use the real GitHub source, not synthetic sample data:

```bash
exhibit-a dashboard --source github:Diego-do-na/exhibit-a-testbed
```

The command uses the local `gh` authentication already configured on the
machine. It reads artifacts through `gh`, serves on `127.0.0.1`, and prints a
one-time browser link. Open the link once, select PR #1, show the proof trace,
then select **Economics**. The Economics page must show the recorded run and
spend; if a field is not in the ledger the matching card is hidden.

## Failure handling while recording

1. **The page is loading or the check is queued:** stop the narration, keep the
   capture paused, and wait. Do not refresh repeatedly or open personal tabs.
2. **GitHub returns an authentication or permission error:** stop the take.
   Re-authenticate outside the recording area with `gh auth status`; never
   print or paste a token. If access cannot be restored, use the recorded run
   URL and mark the take as recorded evidence.
3. **The dashboard cannot start or the port is busy:** stop the process with
   `Ctrl-C`, then use an approved port without exposing unrelated processes:
   `exhibit-a dashboard --source github:Diego-do-na/exhibit-a-testbed --port 8771`.
   If the one-time link still cannot be opened, show the documented dashboard
   screenshots and label the shot as offline/recorded; do not claim a live
   dashboard.
4. **Docker or Colima is unavailable:** do not run a sandbox verification.
   Record the failure as an environment issue and use the already-recorded
   GitHub result. Never call skipped sandbox tests passing.
5. **The PR result differs from the script:** stop and capture the actual
   result only if it can be explained from the ledger. Otherwise use the
   recorded URL. A green miss is never narrated as safety.
6. **A model call or API spend would be required:** stop and obtain owner
   approval. The planned recording budget is US$0.0685 from the existing live
   pass; do not exceed it casually.
7. **A secret, personal tab, or private path appears:** stop the take, close
   the exposure, and discard that recording segment. Never blur after the fact
   if the secret was readable.

## Final review before publishing

- [ ] The subtitles match the scene timing and do not say “safe” for a green
      result.
- [ ] The words “isolated and resource-limited” are used; “100% safe” is not.
- [ ] PR #1 visibly shows the red check, proof comment, suggested fix, and
      **Commit suggestion** control.
- [ ] The control and adversarial scenes show no false `proven`.
- [ ] The dashboard shows real recorded spend and hides cards whose fields
      the ledger does not hold.
- [ ] The chain limitation and green misses are included in narration or
      captions.
- [ ] No key, token, personal folder, personal tab, or shell secret appeared.
