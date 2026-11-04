# Dashboard API

The dashboard server (`src/exhibit_a/dashboard/server.py`) is a read-only
viewer on `127.0.0.1`: every endpoint is `GET`, every figure is derived only
from the run ledger and the run artifacts (both validated with schemas), and
nothing is ever executed. The ledger is the single source of truth; the CI
`result.json` only contributes facts the ledger cannot hold (engine exit
code, risk gate, skip reason).

Data rule: a field the ledger and artifacts do not record is returned as
`""` (strings) or `null` (numbers/objects) and the UI hides that card.
Nothing is estimated or invented. In particular:

- `provider` is the `result.json` artifact's provider (or the `pr_opened`
  payload), `""` when both are silent: ledger events record `role` and
  `model` but older runs have no provider.
- `budget_usd` comes from `result.json` / the `pr_opened` payload when the
  engine recorded the cap; it is `null` on older runs and the budget card
  is hidden.
- `base_sha` is `""` unless a `pr_opened` event (or `result.json`) carries
  `base`/`base_sha`; older Action ledgers record none, so the base-commit
  card is hidden.
- `artifacts.fix_patch` / `artifacts.exploit_test` are `null` unless the run
  folder or artifact carries `fix.patch` / `test_exploit.py`. The Action
  artifact (`action.yml`) uploads `ledger.jsonl`, `result.json`,
  `summary.md` and `results.sarif` only, so Action runs omit those cards.
  Artifact texts are read as capped text and never executed.
- See `docs/ci/artifact-schema.md` for the files the Action zip may contain.
  Any field it does not list stays empty at the API and hidden in the UI.

All examples below are real responses produced from a local run folder whose
ledger mirrors Action run `41650269331` of
`github:Diego-do-na/exhibit-a-testbed` (1 proven `canary_read` in
`memos.py`, model `muse-wonder-1.0`, total US$0.062884 over 3461/2452
tokens). Long strings and lists are trimmed and marked `[trimmed]`; the live
responses carry the full values within the documented display caps
(`model.MAX_STRING`, `MAX_ITEMS`, `MAX_DEPTH`).

## `GET /api/info`

Source label and kind, artifact name (GitHub source only) and the budget cap
(`null` when the run did not record a cap), plus the display caps.

```json
{
  "source": "local: tmp-apidoc",
  "source_kind": "local",
  "artifact": null,
  "budget_usd": null,
  "stages_note": "nothing could be proven is not safe",
  "effect_schema": ["… canary_read / canary_write / canary_exec / canary_sql …"]
}
```

For `--source github:Diego-do-na/exhibit-a-testbed`, `source_kind` is
`"github"` and `artifact` is `"exhibit-a-ledger"`.

## `GET /api/runs?page=&per_page=`

Run rows, newest first (`per_page` capped at 100). Each row carries the run
identity (`run_id`, `ledger_run_id`, `repo`, `pr`, `commit`/`head_sha`,
`base_sha`, `discussion_url`, `branch`, `title`), the verdict counts, the
files touched, the distinct recorded `models`, the `provider` (`""`: not
recorded), totals (`tokens_in`, `tokens_out`, `cost_usd`), timing
(`started_at`, `duration_s`) and the one-line `headline` ("PROVEN: …" or
"NOT PROVEN: nothing could be proven", never "safe").

```json
{
  "run_id": "run-memos",
  "ledger_run_id": "pr-b30106f658c3",
  "repo": "",
  "pr": "",
  "commit": "",
  "head_sha": "",
  "base_sha": "",
  "discussion_url": "",
  "branch": "",
  "title": "",
  "models": ["muse-wonder-1.0"],
  "provider": "",
  "started_at": "2026-11-03T14:05:01Z",
  "duration_s": 15.0,
  "status": "completed",
  "proven": 1,
  "verdicts": {"proven": 1, "discarded_unproven": 0, "invalid_test": 0, "flaky": 0, "env_failure": 0},
  "suspicions_raised": 1,
  "files_touched": ["memos.py"],
  "tokens_in": 3461,
  "tokens_out": 2452,
  "cost_usd": 0.062884,
  "headline": "PROVEN: 1 proven finding"
}
```

For the GitHub source the same run reports `repo`
`"Diego-do-na/exhibit-a-testbed"`, `pr` `"1"`, `head_sha`
`"b30106f658c37804bd29bfe9758c417ea7cda3e1"` and `discussion_url`
`"https://github.com/Diego-do-na/exhibit-a-testbed/pull/1"`. When
`result.json` carries a review-thread URL for that repo and PR
(artifact-schema.md), `discussion_url` is the thread URL instead; `provider`
is the artifact's provider (`""` when the artifact is silent).

## `GET /api/runs/<id>`

The run detail: `run` (the row above), `stages` (the eight loop stages with
reach counts and durations), `proven` (each with its `evidence`: fails-on /
effect / provenance frames / fix / exploit test / passes-on-fixed / bypass /
CWE / severity), `discarded` (each with `verdict`, the ledger's `reason`
plus `reason_code` and `effect`, so `env_failure`, `flaky` and
`invalid_test` keep the recorded explanation), `costs`, the `trace`,
`provider` (the artifact's, `""` when silent), `budget_usd` (`null`),
`artifacts` and `graph_summary` (validated `graph-summary.json`, `null`
when the run folder or artifact does not carry one).

```json
{
  "costs": {
    "by_role": {
      "adversary": {"cost_usd": 0.007396, "tokens_in": 774, "tokens_out": 215, "events": 1, "models": ["muse-wonder-1.0"]},
      "test_writer": {"cost_usd": 0.006836, "tokens_in": 819, "tokens_out": 178, "events": 1, "models": ["muse-wonder-1.0"]},
      "fixer": {"cost_usd": 0.007364, "tokens_in": 831, "tokens_out": 202, "events": 1, "models": ["muse-wonder-1.0"]},
      "defender": {"cost_usd": 0.041288, "tokens_in": 1037, "tokens_out": 1857, "events": 1, "models": ["muse-wonder-1.0"]}
    },
    "by_model": {
      "muse-wonder-1.0": {"cost_usd": 0.062884, "tokens_in": 3461, "tokens_out": 2452, "events": 4, "roles": ["…"]},
    }
  },
  "provider": "",
  "budget_usd": null,
  "artifacts": {"fix_patch": "--- a/memos.py\n+++ b/memos.py\n@@ good fix\n", "exploit_test": "def test_traversal():\n    pass\n"}
}
```

A discarded suspicion keeps its recorded reason:

```json
{"id": "S1", "verdict": "env_failure", "reason": "sandbox could not start", "reason_code": "sandbox_unreachable", "effect": "canary_read"}
```

## `GET /api/runs/<id>/events?from=&limit=`

Bounded event views in ledger order (`limit` capped at 500): `seq`, `ts`,
`type`, `stage`, `role`, `model`, `tokens_in`/`tokens_out`, `cost_usd`,
`latency_ms`, a one-line `summary` and the bounded `payload`.

```json
{
  "seq": 3, "ts": "2026-11-03T14:05:03Z", "type": "suspicion_raised", "stage": "SUSPECT",
  "role": "adversary", "model": "muse-wonder-1.0",
  "tokens_in": 774, "tokens_out": 215, "cost_usd": 0.007396, "latency_ms": 0,
  "summary": "Suspicion path-traversal-1: path_traversal at memos.py:34",
  "payload": {"suspicion": {"id": "path-traversal-1", "class": "path_traversal", "location": {"file": "memos.py", "line": 34}}}
}
```

## `GET /api/runs/<id>/replay?speed=&from=`

Server-Sent Events replay of the finished ledger (`step` frames in ledger
order, then `done`; speed clamped to 64x). Same event views as above.

## `GET /api/runs/<id>/trace`

The ordered, suspicion-grouped step list (`trace_to_dict`), with per-step
and total cost and time as summed in `Ledger.totals`.

## `GET /api/runs/<id>/costs`

Just the `costs` block of the run detail (`by_role` with models, `by_stage`,
`by_model`).

## `GET /api/runs/<id>/graph`

The small entry-to-sink path subgraph for the run (AST-only, never run):
`nodes`, `edges`, `paths` (proven), `effects`, `entry_points`, `stats`.
`{"available": false, "reason": …}` when the run archive has no local code
tree (for example a GitHub-source run).

## `GET /api/runs/<id>/codegraph`

The whole repository as a graph (files, functions/methods, sinks), with the
PR diff `changed` nodes, reach paths (proposals) and proven paths (observed
by the oracle), plus `changed_source` and `stats`.

## `GET /api/trends?limit=`

Verdict counts of the most recent runs (capped at 200), oldest first:

```json
{"points": [{"run_id": "run-memos", "started_at": "2026-11-03T14:05:01Z", "status": "completed", "proven": 1, "discarded_unproven": 0, "invalid_test": 0}], "limit": 50, "total": 1}
```

Only the loop's verdict values (`proven`, `discarded_unproven`,
`invalid_test`) are plotted.

## `GET /api/repos`

One summary per repository (`id`, `name`, `runs`, `proven`, `last_run`,
run-order `trend`, `severity_mix`), most recently active first, plus
`runs_considered` / `runs_total`.

## `GET /api/benchmark`

Aggregates of `bench/results/*.json` (newest file) for the Exhibit-A repo
only: per-system counts and sums over measured `per_target` rows plus the
capped target list. Any other source gets `available: false` with reason
`"no benchmark data for this source"`; the corpus evaluation describes the
Exhibit-A benchmark, not that source.

```json
{
  "available": true, "file": "2026-11-01.json",
  "systems": [{"system": "Exhibit A, compact profile", "targets": 32,
    "reported": 29, "true_positives": 25, "false_positives": 4,
    "precision": 0.8621, "recall": 0.68, "cost_usd": 2.27}],
  "targets": [{"target": "starlette-cve-2023-29159", "reported": 1, "cost_usd": 0.11}]
}
```

## `GET /api/repos/<id>`

One repository's headline metrics across its runs, its recent pull requests
and its most serious proven findings. Numbers are counts or sums of
recorded run data; rates are exact divisions, never estimates:

```json
{
  "metrics": {
    "runs": 1, "proven": 1, "root_causes": 1, "suspicions_raised": 1,
    "exploits_written": 1, "fixes_verified": 1, "fixes_bypassed": 0, "discarded": 0,
    "proven_rate": 1.0, "cost_usd": 0.062884, "cost_per_run": 0.062884, "cost_per_proven": 0.062884,
    "tokens_in": 3461, "tokens_out": 2452, "median_duration_s": 15.0
  },
  "budget_usd": null,
  "cost_by_role": {
    "defender": {"cost_usd": 0.041288, "tokens_in": 1037, "tokens_out": 1857, "events": 1, "models": ["muse-wonder-1.0"]}
  },
  "cost_by_model": {
    "muse-wonder-1.0": {"cost_usd": 0.062884, "tokens_in": 3461, "tokens_out": 2452, "events": 4, "roles": ["…"]}
  }
}
```

`run_series` is chronological (oldest first) with per-run `cost_usd`,
`cumulative_cost_usd`, `proven`, `effects_breakdown` and `by_role`, which is
what the Economics page draws. `proven_rate`, `cost_per_run` and
`cost_per_proven` are `null` when their denominator is zero ("not
recorded", not zero spend). `pull_requests` rows carry the same identity
fields as `/api/runs` rows (`head_sha`, `base_sha`, `discussion_url`,
`models` included).
