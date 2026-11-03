# Exhibit A ledger artifact schema

This is the contract for the GitHub Actions artifact named `exhibit-a-ledger`
(overridable with the Action input `artifact-name`). The dashboard GitHub
source (`--source github:<owner/repo>`) downloads that zip and reads it in
memory. A green Action check means **nothing could be proven**, never that
the change is safe. Files in the artifact are untrusted (model output and
PR-influenced text): validate them, never execute them outside the isolated
and resource-limited sandbox.

The zip is the only object the dashboard sees for a CI run. If a field the
dashboard needs is not a **top-level** zip entry or a field of top-level
`result.json`, the dashboard must treat it as **not recorded** (`""` / `null`),
never invent a number.

## Zip layout

`actions/upload-artifact` packs the files listed below. Every entry is at the
**zip root**. Nested paths (`packages/<id>/fix.patch`, `report/result.json`)
are not read: `GitHubSource.read_artifact_zip` / `read_artifact_texts` only
open top-level names.

| Entry | Required | Cap the dashboard already applies | What it is |
|---|---|---|---|
| `ledger.jsonl` | yes | 8 MiB file, 256 KiB/line, 20_000 events | Source of truth: one JSON `Event` per line. |
| `result.json` | yes | 256 KiB | CI projection plus facts the ledger cannot hold. |
| `summary.md` | no | 64 KiB (text) | Job-summary Markdown. Display only, never executed. |
| `results.sarif` | no | not read by the dashboard | SARIF 2.1.0 of proven findings; omitted when `sarif` is false or generation failed. |
| `fix.patch` | no | 64 KiB (text) | Verified unified diff of the first proven finding. |
| `test_exploit.py` | no | 64 KiB (text) | Packaged Python exploit test of that finding. |
| `test_exploit.js` | no | 64 KiB (text) | Same for a JavaScript finding. |
| `test_exploit.ts` | no | 64 KiB (text) | Same for a TypeScript finding. |
| `graph-summary.json` | no | 64 KiB (text) | Compact static-graph summary when a `scan_done` event exists. |

Omitted optional files mean "not recorded". A skipped risk-gate run still
uploads `ledger.jsonl` (possibly empty) and `result.json` with
`status: "skipped"`.

**Never in the zip:** the clone, runner logs, `pr.diff`, API keys, the
environment secret, `comment-payload.json`, raw GitHub API responses.

## `ledger.jsonl`

Append-only JSONL. Each line validates as `exhibit_a.schemas.Event`
(`src/exhibit_a/schemas/events.py`). Fields on every event:

| Field | Type | Notes |
|---|---|---|
| `ts` | string | ISO-8601 timestamp. |
| `run_id` | string | Engine run id (PR runs: `pr-<12 hex of HEAD>`). |
| `type` | enum | `pr_opened`, `scan_done`, `baseline_done`, `suspicion_raised`, `exploit_written`, `run_started`, `oracle_event`, `verdict`, `fix_proposed`, `bypass_attempt`, `bypass_result`, `packaged`. |
| `role` | string | `adversary`, `test_writer`, `fixer`, `defender`, or `""` for engine events. |
| `model` | string | Model id that produced this event, or `""`. **No provider.** |
| `tokens_in` | int ≥ 0 | Prompt tokens charged on this event. |
| `tokens_out` | int ≥ 0 | Completion tokens charged on this event. |
| `cost_usd` | float ≥ 0 | Model cost charged on this event. |
| `latency_ms` | int ≥ 0 | |
| `payload` | object | Event-specific; model text lives here. Untrusted. |

The dashboard recomputes verdict counts, totals, and `costs.by_role` from
these lines. The ledger is the source of truth; `result.json` must not
contradict it.

`scan_done` payloads the graph summary is built from:

- `status: "sliced"` — `source_file`, `paths[]` (`path`, `entry_point`,
  `entry_kind`, `changed`, `vuln_class`, `confidence`), `slice`.
- `status: "nothing_reachable"` — `effect`, `reason`, `changed`,
  `changed_outside_functions`, `unreached`, `entries`, `paths_to_other_sinks`,
  `graph` (`GraphStats`: `files`, `nodes`, `edges`, `resolved`, `external`,
  `unresolved`), `build_seconds`.
- `status: "not_applicable"` — no changed source files of the run language.
- `status: "no_suspicions"` — adversary returned nothing usable.
- `status: "findings_grouped"` — duplicate proofs of one effect.

Reachability is a proposal, not proof. Only a `verdict` of `proven` after
sandboxed execution is a finding.

## `result.json`

`schema_version` is `"1"`. Additive keys below do not bump the version.
`exhibit_a.ci.summary.build_result` writes the CI projection; the Action
then merges dashboard fields the ledger cannot hold. Extra keys are
ignored by today's dashboard `_Result` parser (`extra="ignore"`) until
the dashboard owner aligns with this document.

### Written by `ci.summary` (already on every run)

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | `"1"` | Layout version. |
| `run_id` | string | Same as the ledger's run id. |
| `status` | enum | `completed`, `aborted`, `timed_out`, `not_run`, `skipped`. |
| `skipped_reason` | string | Risk-gate skip text, else `""`. |
| `engine_exit` | int or null | Exit code of `exhibit-a run` (0, 10, 20, 2, 124, 137). |
| `proven` | int | Unique proven findings (duplicates of one effect grouped). |
| `proven_raw` | int | Proven verdicts before grouping. |
| `duplicates` | int | `proven_raw - proven`. |
| `verdicts` | object | Raw counts keyed by `proven`, `discarded_unproven`, `invalid_test`, `flaky`, `env_failure`. |
| `suspicions_raised` | int | |
| `dropped` | int | Judged suspicions that are not unique proven findings. |
| `findings` | array | Proven findings: `suspicion_id`, `reason`, `fix_verified`, `package` (e.g. `packages/<slug>`), optional `facts`, `hypothesis`, `duplicates`. |
| `flags` | object | Loop ablation flags. |
| `ablated` | bool | True when flags are not the full proof standard. |
| `risk` | object or null | `{risk, should_run_exploits, reasons}` from `ci.gate`. |
| `tokens_in` | int | Sum of ledger `tokens_in` for this run. **Cost per run (tokens).** |
| `tokens_out` | int | Sum of ledger `tokens_out`. |
| `cost_usd` | float | Sum of ledger `cost_usd`, rounded to 6 decimals. **Cost per run (USD).** |
| `surface_ran` | bool | False means the verification surface did not run. |

A result file cannot override ledger verdicts: the dashboard recomputes
counts from events and only trusts `engine_exit`, `risk`, `skipped_reason`,
and the additive keys below from this file.

### Merged by the Action (dashboard gaps)

These keys are missing from a ledger-only artifact and from Action runs
uploaded before this contract. After this contract they are always present
on `result.json` when the summary step succeeded.

| Field | Type | When empty | Dashboard use |
|---|---|---|---|
| `provider` | string | `""` if the `provider` input is empty | `run.provider` / detail `provider`. Ledger events have no provider. |
| `model` | string | `""` if the `model` input is empty **and** no event recorded a model | First-class model id for the run. Distinct names on events still appear in `tokens_by_role[].models` and in the ledger. |
| `tokens_by_role` | object | `{}` when no role was charged | Per-role `{tokens_in, tokens_out, cost_usd, events, models[]}`. Keys are `adversary`, `test_writer`, `fixer`, `defender`. Roles with zero events are omitted, not zero-filled. |
| `discussion_url` | string | `""` when no review suggestion was posted | HTML URL of the review-suggestion discussion, **not** the pull-request page. |
| `graph_summary` | object or null | `null` when the ledger has no usable `scan_done` | Same object as `graph-summary.json`. |

`discussion_url` shape, when set:

```
https://github.com/<owner>/<repo>/pull/<n>#discussion_r<id>
https://github.com/<owner>/<repo>/pull/<n>#pullrequestreview-<id>
https://github.com/<owner>/<repo>/pull/<n>#issuecomment-<id>
```

Only that repository's current pull request is recorded. A URL that does
not match is dropped (the field stays `""`). This is the thread GitHub
returns as `html_url` after `suggest-fixes` posts a verified hunk. It is
not synthesized from `owner/repo` + PR number; that PR page is a different
link.

`tokens_by_role` example (testbed run 41650269331 shape):

```json
{
  "adversary": {
    "tokens_in": 774,
    "tokens_out": 215,
    "cost_usd": 0.007396,
    "events": 1,
    "models": ["muse-wonder-1.0"]
  },
  "test_writer": {
    "tokens_in": 819,
    "tokens_out": 178,
    "cost_usd": 0.006836,
    "events": 1,
    "models": ["muse-wonder-1.0"]
  },
  "fixer": {
    "tokens_in": 831,
    "tokens_out": 202,
    "cost_usd": 0.007364,
    "events": 1,
    "models": ["muse-wonder-1.0"]
  },
  "defender": {
    "tokens_in": 1037,
    "tokens_out": 1857,
    "cost_usd": 0.041288,
    "events": 1,
    "models": ["muse-wonder-1.0"]
  }
}
```

Totals `tokens_in`, `tokens_out`, `cost_usd` on `result.json` remain the
run sums (including engine events with no role). Per-role figures only
count events that name a model role.

**Still not recorded** in this artifact (leave `null` / `"not recorded"`):

- `budget_usd` — the Action passes `--budget-usd` to the engine; the cap
  itself is not stored in the ledger or this zip.
- `base_sha` — PR-diff runs do not emit `pr_opened` with `base` /
  `base_sha`.

## `fix.patch` and the exploit test

Copied from the first proven finding's package directory
(`result.json` `findings[0].package`, else the first `packages/*` dir
that has the file) to the zip root. Read as capped UTF-8 text only.
Never applied and never executed on the runner after packaging, and
never executed by the dashboard.

| File | Present when |
|---|---|
| `fix.patch` | At least one proven finding has a verified fix (`fix_verified: true`). |
| `test_exploit.py` | That package wrote a Python exploit. |
| `test_exploit.js` / `test_exploit.ts` | Same for JS/TS. |

The dashboard today maps:

- `fix.patch` → `artifacts.fix_patch`
- `test_exploit.py` → `artifacts.exploit_test`

JS/TS exploit names are included so a later dashboard read can pick them
up; until then they stay unused. Missing files must surface as `null`,
not as an empty patch or a placeholder test.

## `graph-summary.json`

Written when any `scan_done` payload is usable. Same JSON is copied onto
`result.json` `graph_summary`. Compact on purpose: it is not the full AST
graph (no `nodes[]` / `edges[]`). GitHub-source runs have no code tree, so
this is the graph the dashboard can show without rebuilding.

```json
{
  "schema_version": "1",
  "available": true,
  "status": "sliced",
  "effect": "canary_read",
  "reason": "",
  "stats": {
    "files": 3,
    "nodes": 12,
    "edges": 8,
    "resolved": 6,
    "external": 1,
    "unresolved": 1
  },
  "build_seconds": 0.04,
  "entries": ["App.handle_request"],
  "changed": ["memos:App.handle_request"],
  "paths": [
    {
      "path": "App.handle_request -> read_text",
      "entry_point": "App.handle_request",
      "entry_kind": "http",
      "changed": "memos:App.handle_request",
      "vuln_class": "path_traversal",
      "confidence": "high"
    }
  ],
  "paths_to_other_sinks": 0,
  "source_file": "memos.py"
}
```

| Field | When missing |
|---|---|
| `available` | Always `true` in this file (the file is omitted when there is no summary). |
| `status` | `""` |
| `effect` | `""` when the payload has none |
| `reason` | `""` |
| `stats` | `{}` when the payload has no `graph` / `GraphStats` (a `sliced` event has paths, not stats) |
| `build_seconds` | `null` |
| `entries` | `[]` |
| `changed` | `[]` |
| `paths` | `[]` |
| `paths_to_other_sinks` | `null` |
| `source_file` | `""` |

If the file is absent, `result.json` `graph_summary` is `null` and the
dashboard graph views stay `"not recorded"` / `available: false` for
GitHub-source runs that have no local tree.

## `summary.md` and `results.sarif`

`summary.md` is the job-summary Markdown (headline, counts, cost, verdict
table). Display only.

`results.sarif` is produced when `sarif: true` (default) and uploaded to
code scanning separately. The ledger artifact keeps a copy when the file
exists. The dashboard does not parse SARIF.

## Trust and limits

| Rule | Detail |
|---|---|
| Untrusted | Every byte: model text, suspicion ids, reasons, patch, exploit, graph labels, `html_url`. |
| Never execute | `fix.patch` and `test_exploit.*` are read as text. The dashboard does not apply or run them. Reproduction is `exhibit-a reproduce` in the isolated and resource-limited sandbox. |
| No secrets | The engine step scans `$OUT/run` and `$OUT/report` for the API key and deletes the output on a hit, before this zip is assembled. |
| Caps | Dashboard: ledger 8 MiB, result 256 KiB, proof text 64 KiB, zip 24 MiB / 64 entries. Oversized entries are refused or skipped; a run that fails ledger/result validation is unreadable as a whole. |
| Top-level only | Nested zip entries are ignored. |

## Dashboard mapping (for the dashboard owner)

| Need | Where in this zip | Today's dashboard behaviour to change |
|---|---|---|
| Fix patch | top-level `fix.patch` | `read_artifact_texts` already looks for this name; Action runs were missing the file. |
| Exploit test | top-level `test_exploit.py` (or `.js` / `.ts`) | Same; only `.py` is in `PROOF_TEXT_NAMES`. |
| Tokens in/out per role | `result.json` `tokens_by_role` **or** sum ledger events by `role` | Already derived from the ledger; the result object is the CI copy. |
| Model | `result.json` `model` and ledger `model` | Already derived from events (`run.models`). |
| Provider | `result.json` `provider` | Always `""` today because the ledger has no provider. Read this key. |
| Cost per run | `result.json` `cost_usd` (also sum of ledger `cost_usd`) | Already derived. |
| Review-suggestion discussion URL | `result.json` `discussion_url` | Today synthesized as `https://github.com/<repo>/pull/<n>` from repo+PR. Prefer the artifact field when it is a non-empty GitHub discussion/review URL; otherwise keep `"not recorded"`. Do not invent a PR-page stand-in for a missing discussion. |
| Graph summary | `graph-summary.json` / `result.json` `graph_summary` | `/api/runs/<id>/graph` and `/codegraph` return `available: false` for GitHub-source runs (no tree). Use this summary when present; still do not rebuild a full AST graph from it. |

Wording: missing, null, or empty → **"not recorded"** (API) / **"not available"** (UI). Never `0` as a stand-in. A run with `proven == 0` reads **"nothing could be proven"**, never "safe".
