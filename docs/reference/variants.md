# Variant hunting (`exhibit-a variants`)

When Exhibit A proves a bug, the same mistake often sits on other paths: another route
calling the same unsafe helper, or a sibling handler that copied the pattern. `exhibit-a
variants` reads a finished run, asks the static call graph where else that mistake may be,
and runs the normal verification loop on each candidate. The listing needs no model and no key.

A candidate is a proposal from the graph. Reachability is not exploitability. A candidate
becomes a finding only when the loop proves it in the isolated, resource-limited sandbox under
the same proof standard as any other finding (SPEC section 4). No proven variant means nothing
could be proven, never that the code is safe.

## Usage

```bash
exhibit-a variants --run-dir RUN --repo CLONE --list-only
exhibit-a variants --run-dir RUN --repo CLONE --max 5 --budget-usd 2 --provider meta --model muse-wonder-1.0 --profile compact
```

| Flag | Meaning |
| --- | --- |
| `--run-dir RUN` | A finished run's output directory (the one with `packages/`). |
| `--repo CLONE` | The clone the run proved against. Default: `RUN/clone` (what `run --case` stages). |
| `--max N` | At most N candidates listed per finding, and at most N loop runs in total (default 5). |
| `--budget-usd X` | Hard cost limit shared by every candidate (see below). |
| `--list-only` | Only list candidates: no model, no key, no sandbox, nothing spent. |
| `--provider`, `--model` | Model backend for every role, as for `exhibit-a run`. |
| `--profile standard\|compact` | Prompt profile of the loop (default `standard`). |
| `--baseline TEST` | Baseline test in the clone. Default: `test_baseline.py` if present, else `.`. |
| `--requirement PKG` | A pinned package the sandbox installs (repeatable). |
| `--sql-db FILE` | The app's SQLite database, for `canary_sql` findings. |
| `--entry-point NAME` | Declared entry point (repeatable). It replaces detection; the proven entry point is always kept. |

Exit codes: 0 when the listing or the hunt completed (whatever it proved), 2 for a usage
error (missing run directory or clone, `--max` below 1, a non-positive budget).

## What a proven finding contributes

Only the oracle's facts are used, never the model's text. For each package of
`RUN/packages/` whose `verdict.json` says `proven` and that is not a duplicate of another
proof, `evidence.json` `facts` gives:

- the effect (`canary_read`, `canary_write`, `canary_exec`, `canary_sql`, ...);
- the chain of admitted application frames, entry point first, sink caller last;
- the observed location, including the sink call the graph placed on that line
  (`observed_location.sink_call`, e.g. `builtins.open`).

A proof without those facts (no admitted frames) cannot be placed on the graph. It is
listed under `skipped_packages` with the reason, never guessed.

The frames are matched to graph nodes by qualified name and file. The sink rule is the
catalog rule (`src/exhibit_a/graph/catalog.py`) of the proven sink call: same effect, same
rule (for example every open-like call, or every `subprocess` call).

## Candidates

Three kinds, all from `src/exhibit_a/graph/variants.py`:

1. `same_sink_function`: another entry point reaches the function that made the proven sink
   call. Two routes into one unsafe helper: route A was proven, route B is listed. Each
   other entry point is its own candidate.
2. `same_sink_rule`: another call site of the same sink rule whose argument is not a
   constant, reached from its best-ranked entry point (`other_entries` counts the rest).
3. `similar_caller`: a `same_sink_rule` site whose function is structurally similar to the
   proven sink caller (the `ast` node-type sequences match at a ratio of at least 0.6) and
   takes the sink argument from the same parameter positions. A copied handler.

Never listed:

- a call whose data arguments are all constants (`open("static/about.html")`,
  `open("static/" + "logo.svg", "rb")`, `subprocess.run(["ls", "-l"], check=True)`). The mode
  position of an open-like call and option keywords (`mode`, `encoding`, `check`, `timeout`,
  ...) do not count as data. A call whose data the graph did not keep (a method on a computed
  value such as `Path(x).read_text()`) is not shown to be constant, so it stays listed;
- a sink handed over as a callback (a `ref` edge): there is no call site to argue about;
- anything that repeats a proven path: the same entry point and sink function as any
  finding of the run.

Ranking: kind (`same_sink_function`, then `similar_caller`, then `same_sink_rule`),
reachable before unreachable, higher similarity, resolved before name-only sinks,
entry-point exposure (network entries first, as in `exhibit-a audit`), fewer hops, fewer
unresolved hops, then names for determinism. A call site no entry point reaches is listed
(`runnable: false`) but never run.

The parameter-flow check is a small intra-function approximation over `ast`: a name is
carried by a parameter when it is bound (assignment, augmented or annotated assignment,
walrus, `for` target, `with ... as`) from an expression that mentions a carried name. It
is not a taint analysis: it can miss flows through calls, containers and attributes. That
costs recall or labels, never a false proof: the label only orders candidates.

## Proving candidates

Without `--list-only`, each runnable candidate, best first, runs through the normal loop
with the graph's entry point and a slice of the candidate's path. This is the code path of
`exhibit-a run --slice`, imported and not copied: `graph.slicer.make_plan`,
`loop.pipeline.VerificationLoop(slice_plan=...)`, roles from `cli.run._live_roles` and the
sandbox runner from `cli.run._sandbox_runner_cls`. The oracle judges every suspicion with the
graph path's entry point, never with the model's `entry_point` text, so a model cannot
widen what the oracle accepts. Baseline, exploit, fixed-code and bypass runs all go through
the sandbox.

One cost meter is shared by every candidate and checked before each one starts. Like
`exhibit-a audit`, the budget is passed by at most the one model call that crossed it; the
candidates after that are listed as `not_run: budget`.

A variant proof that shows the same effect through the same admitted frames as an original
finding (`findings.dedupe.proof_key`) is that finding again: it is reported as
`same_as_original` and not counted as a variant.

## Outputs

- `RUN/variants/<n>/`: the loop's output for candidate `n` (`ledger.jsonl`, `packages/`,
  `work/`) and `variant.json` (the candidate and its outcome).
- `RUN/variants.json` (schema version 1):

| Key | Meaning |
| --- | --- |
| `mode` | `list-only` or `run`. |
| `findings[]` | One per proven finding: `finding_id`, `package`, effect, entry point, sink function, line and call, the frame chain, the matched graph nodes, `rule`, `considered`, `listed`, `constant_sites_skipped`, `note`, and `candidates[]`. |
| `findings[].candidates[]` | `n`, `variant_of` (the original finding id), `kinds`, `entry_point`, `path`, `sink_node`, `sink_target`, `sink_line`, `source_file`, `runnable`, `similarity`, `param_flow`, `status`. |
| `variants[]` | Every candidate run: `n`, `variant_of`, `original_package`, `run_id`, `dir`, `status`, `proven[]`. |
| `proven_variants[]` | Every proven variant that is a new finding: `variant_of`, `original_package`, `suspicion_id`, `package` (under `variants/<n>/`), `entry_point`, `sink_function`, `observed_location`, `fix_verified`, `fix_incomplete`, `distinct_from_original`. |
| `skipped_packages[]` | Packages not used, with the reason. |
| `stopped`, `budget_usd`, `spent_usd` | `completed`, `budget`, `max` or `list-only`; the cap and what was spent. |

Statuses: `listed` (list-only), `proven_variant`, `same_as_original`, `nothing_proven`,
`aborted: ...` (for example the baseline did not pass), `budget_exceeded`, `error: ...`,
`not_run: budget`, `not_run: max`, `not_run: no entry point reaches the call site`.

## Example

A synthetic app with two routes into one unsafe helper and two constant-argument opens
(`tests/test_variants.py`, `TWO_ROUTES`). The run was produced by the normal loop with a
scripted provider and a fake runner (`original_run` in that test file), and proved the
traversal through `route_a`:

```text
$ exhibit-a variants --run-dir run --repo repo --list-only
finding V1 [canary_read] route_a -> read_file (app.py:17, builtins.open)
  1. [same_sink_function] route_b -> [read_file] -> builtins.open (line 17)
     entry point: route_b  file: app.py  status: listed
  2 same-rule call(s) with only constant arguments not listed
listed 1 candidate variant(s) for 1 proven finding(s); a candidate is not a finding until the loop proves it
wrote run/variants.json
```

`route_b` is listed as a variant of the proven finding; the `about` and `logo` handlers open
constant paths and are not.

## Limits

- The graph is static: dynamic dispatch, monkeypatching and framework magic it cannot
  resolve cost recall (see `docs/design/code-graph.md`).
- The structural comparison and the parameter flow are heuristics that order and label
  candidates; they never decide a verdict.
- Candidates are searched per run, not across runs, and only for findings of that run.
- The reach search keeps at most 8 entry points per call site (`MAX_ENTRY_CHAINS` in
  `src/exhibit_a/graph/reach.py`), nearest first.
- Live-model cost and recall of the hunt are unmeasured here: the tests use a scripted
  provider and a fake runner.
