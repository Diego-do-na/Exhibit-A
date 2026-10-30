# Cost controls: the compact profile

With reasoning models almost all of the cost is **output**: reasoning tokens are billed as
output, and output costs five times input on Muse Wonder (US$4 / 1M input, US$20 / 1M output,
dev.meta.ai Models page, 2026-10-29). Input format (JSON or plain text) barely matters; what
matters is how much the model writes. `--profile compact` attacks exactly that.

```bash
exhibit-a run --case bench/corpus/<case> --provider meta --model muse-wonder-1.0 \
  --profile compact --budget-usd 1
```

## What `--profile compact` changes

| Control | Standard | Compact |
|---|---|---|
| Suspicions per file | unbounded | at most 3, most likely first |
| Free text (`hypothesis`, `source`, names) | unbounded | bounded by the schema (`maxLength`) |
| Fixer answer | whole files (`files[].content`) | search/replace edits (`edits[].find/replace`) |
| Bypass variants | unbounded | at most 3 |
| Reasoning effort | provider default (`max` on Meta) | `minimal` |
| Output-token ceiling per call | none | adversary 6000, test writer 8000, fixer 6000, defender 10000 |
| Prompt layout | instructions first | source first, instructions after |
| Proof contract in test prompts | the two environment variables only | where the canary is for the case's effect, what to assert, what is forbidden, which packages are installed (`test_contract`) |

`--reasoning-effort` and `--max-output-tokens` override the profile defaults for any profile.
A call cut by the ceiling fails with a clear `ProviderError`, never with a half answer.

The fixer's edits are untrusted model output: an edit may only change an existing regular
file of the clone (no new files, no symlinks, no `..` or absolute paths), its `find` text
must occur exactly once, and the resulting files then go through the same containment and
size checks as whole-file fixes (`VerificationLoop._edits_to_files`, then `_apply_fix`).

## What it does not change

The standard prompts and schemas are frozen (`tests/test_compact_profile.py` pins their
hash): every replay key hashes role, prompt and schema, so the recorded runs, including the
Meta recordings, keep replaying. For the same reason `--profile compact --replay` is refused.

## What is measured and what is not

Measured on 2026-10-29 against the live API (`/v1/responses`, muse-wonder-1.0, one short
prompt, one sample per level): output tokens 2139 at `max`, 1542 at `medium`, 1203 at `low`,
778 at `minimal`, so `minimal` wrote 64% fewer tokens than the default on that prompt.

Not yet measured:

- whether `/v1/chat/completions` (the endpoint this provider uses) honours the
  `reasoning_effort` field; the Meta playground documents the effort on `/v1/responses`;
- the cost per case with `--profile compact` on the corpus;
- whether the compact profile proves the same cases. A cheaper run that stops proving things
  is not cheaper. Compare verdicts and cost per case against `docs/meta-run.md` before
  making any claim.
