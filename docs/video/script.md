# Exhibit A — three-minute video script

The recording is 16:9, English, and cut to the scene boundaries below. Use the
recorded GitHub results; do not imply that a green check means safe.

| Scene | Time | What is on screen (exact command or URL) | Narration | Caption |
|---|---:|---|---|---|
| Hook | 0:00–0:20 | Split screen. Left: a scanner card reading `47 alerts`. Right: PR [#1](https://github.com/Diego-do-na/exhibit-a-testbed/pull/1), with the red `exhibit-a / verify` check and `1 proven`. | “Most security scanners give you a backlog of alerts. Exhibit A takes a narrower position: one finding is worth more than a wall of suspicions when it comes with a reproducible proof.” | `47 alerts` → `1 proven finding` |
| Thesis | 0:20–0:42 | Show `SPEC.md` at the proof loop, then a terminal with `exhibit-a run --help`. | “A model can raise a suspicion, but it cannot declare a vulnerability. Exhibit A writes an exploit, runs it in an isolated and resource-limited sandbox, checks the intended oracle effect and provenance, verifies the fix, and tests bypasses. A green result means nothing could be proven—not safe.” | `SUSPICION → EXPLOIT → ORACLE → FIX → VERIFY` |
| Live demo: vulnerable PR | 0:42–1:35 | Open [testbed PR #1](https://github.com/Diego-do-na/exhibit-a-testbed/pull/1). Show the red check, the bot comment with `proven: 1`, the `canary_read` evidence, the suggested fix, then the GitHub review menu with **Commit suggestion**. | “Here is a real pull request that removes containment from a memo lookup. The required check is red because the exploit reaches the application entry point and reads the canary outside the allowed directory. The comment shows the observed effect and provenance, not just a pattern match. Exhibit A proposes a small fix; the maintainer still owns the review, and GitHub can commit that suggestion with the normal **Commit suggestion** control.” | `red check` · `canary_read` · `fix verified` |
| Control and adversarial PRs | 1:35–1:58 | Open [PR #6](https://github.com/Diego-do-na/exhibit-a-testbed/pull/6), then [PR #11](https://github.com/Diego-do-na/exhibit-a-testbed/pull/11) and [PR #12](https://github.com/Diego-do-na/exhibit-a-testbed/pull/12). | “The control PR is green and does not accuse. Prompt-injection text in a diff does not mint a finding, and a test-frame `open()` is not application provenance. The proof gate is what stops both ordinary noise and adversarial theater.” | `green = nothing could be proven` |
| Local dashboard | 1:58–2:28 | Terminal: `exhibit-a dashboard --source github:Diego-do-na/exhibit-a-testbed`<br>Open the one-time localhost URL; select PR #1 and the **Economics** view. | “The local dashboard is a read-only viewer of the ledger. This is the real GitHub source: PR runs, the proof trace, the finding, and Economics with recorded model spend. It does not invent a provider or budget when the ledger did not record one.” | `ledger-backed · read-only · Economics` |
| Numbers and limits | 2:28–2:47 | Show `docs/ci/chain-validation.md` totals, then `docs/bench/bench.md` compact rows. | “In the live chain, fourteen PRs produced one proven path traversal, zero control accusations, zero adversarial false proven results, and US$0.0685 in API spend. The other four vulnerable testbed PRs were green misses because this compact run was sliced for `canary_read`; that is a documented product limitation, not a safety claim. In the recorded benchmark table, the compact profile reports 29 findings, including 25 true positives and 4 false positives, with 15 suspicions discarded across 140 calls.” | `real evidence · honest misses · no safety claim` |
| Closing | 2:47–3:00 | Return to PR #1 evidence, then show `github.com/Diego-do-na/Exhibit-A`. | “Exhibit A is proof before accusation: execute the claim, observe the intended effect, verify the repair, and show the evidence. Nothing merges itself, and nothing proven here should be mistaken for a claim that the project is safe.” | `Proof before accusation.` |

## Number provenance

- The `47 alerts` card is a visual hook, not a repository benchmark measurement.
- The live-chain numbers are from `docs/ci/chain-validation.md`: 14 PRs, 1
  proven finding, 0 control accusations, 0 adversarial false proven results,
  13 comments, 1 suggested fix, and US$0.0685 API spend.
- The recorded compact benchmark headline is 29 reported, 25 true positives,
  4 false positives, 0 false accusations, 15 discarded, 140 calls, and
  US$2.2727 cost. If the generated result changes before recording, replace
  the affected value with `pending` rather than estimating.
- The dashboard's per-run example is recorded as US$0.062884 in
  `docs/design/dashboard-api.md`; display the UI's recorded precision.
