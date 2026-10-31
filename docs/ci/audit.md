# Repository audit

`exhibit-a audit` answers "what is already wrong in main?" for a team that
already verifies pull requests. It builds the static call graph of a whole
repository (`exhibit-a scan --graph`), ranks every entry-point-to-sink path,
groups paths by sink, and runs the normal verification loop (the same code
path `exhibit-a run --slice` uses: `VerificationLoop` with a `SlicePlan`) on
the top targets until `--budget-usd` or `--max-targets` is reached. Then it
writes `audit.json` and `audit.md`: targets tried, proven findings with
packages, and untried paths listed honestly.

A green audit means **"nothing could be proven"**, never safe. Unproven
suspicion is dropped silently and counted; untried targets stay listed.

## Usage

```bash
# Rank only: no model call, no spending, no key needed.
exhibit-a audit --repo <dir> --list-only

# Prove the top targets (compact profile, small budget).
exhibit-a audit --repo <dir> --budget-usd 2 --max-targets 10 --profile compact
```

`--list-only` prints one line per sink group (sink, effect, file, path count,
best path) and writes `audit.json`. A full run writes `audit.json`,
`audit.md`, `ledger.jsonl`, and `packages/` under `--out` (default
`audit-out`), and prints a one-line JSON summary.

## Ranking

Targets are sink groups, ranked by their best path:

1. Sink severity by effect: `canary_exec`/`canary_sql` first, then
   `canary_write`, then `canary_read`. Sinks with no provable effect are never
   targets.
2. Path length: fewer hops first.
3. Entry-point exposure: network-reachable (`asgi`, `wsgi`, `route_decorator`,
   `route_table`, `django_view`, `request_handler`) first, then `declared`,
   then `cli_main`.
4. Fewer unresolved hops, higher confidence, then deterministic name order.

## Budget

All targets share one `CostMeter`. The meter is checked before each target
starts, so the budget is never exceeded by more than one model call: a target
already running may be the call that spends past it, and the next target does
not start. When the budget is spent the audit stops with `stopped: budget`;
when the cap is hit first it stops with `stopped: max_targets`. Every ranked
target that was never attempted stays in `untried` (and in `audit.md` under
"Untried paths"), most important first.

## Nightly/weekly workflow

`.github/workflows/exhibit-a-audit.yml` runs on a weekly schedule and on
manual dispatch, with the compact profile and a small budget (`--budget-usd 2
--max-targets 10`). It is inert unless the repository variable
`EXHIBIT_A_ENABLED` is `'true'`, runs in the `exhibit-a` environment, has no
`pull_request` trigger so it never runs on forks, and uploads `audit.md`
(plus `audit.json`) as an artifact and `results.sarif` to code scanning when
the SARIF export succeeds.
