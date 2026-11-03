# Chain validation (T150 / T151)

Live GitHub Action runs on the private throwaway repository
[`Diego-do-na/exhibit-a-testbed`](https://github.com/Diego-do-na/exhibit-a-testbed).
A green check means **nothing could be proven**, never that the change is
safe. The sandbox used by the Action is isolated and resource-limited; it
is not "100% safe".

This document records the **second, live** pass after the Action was
pinned to a real Exhibit A SHA (T139/T150, pin `76e1a78`, table below).
T151 then changed the engine so a sliced PR run that omits `--effect`
derives oracle effects from reachable sinks. The four green misses were
re-evaluated against that engine on the real testbed trees. The earlier
live table is kept. Nothing is hidden.

## T151 re-evaluation of the four misses

Compact PR runs still pass `--slice` and still do not pass `--effect`.
They no longer force `canary_read`. Effects come from sinks the diff
reaches (read, write, exec, SQL, connect, dos), each inside the existing
`--budget-usd` cap, fail-closed. **IDOR (`canary_access`) is not derived
and is not supported on this surface yet**: the catalog has no
oracle-provable sink call for broken access control.

Re-evaluation method: HEAD of each remaining vulnerable branch versus
`origin/main` on `exhibit-a-testbed`, graph and slice only, this branch,
no model call, API spend **US$0.00**. A live muse Action re-run of the
four PRs was not started: this session has no `EXHIBIT_A_API_KEY` /
`META_API_KEY`, and the task must not push the pin. Remaining budget
under the US$1 cap is **US$1.00**.

| PR | T139 (pin `76e1a78`) | T151 engine on the same trees | Still a miss? |
|---|---|---|---|
| [#2](https://github.com/Diego-do-na/exhibit-a-testbed/pull/2) SQLi | `nothing_reachable` for `canary_read`; `paths_to_other_sinks=1`; no model call | Path kept: `App.handle_request` → `App._search` → `sqlite3.connect.execute` (`canary_sql`). Effect is then **skipped**: the app opens sqlite as `:memory:`; `canary_sql` seeds a file database. No model call. | Yes. The drop-by-wrong-effect bug is gone. Proof still cannot run on an in-memory database. |
| [#3](https://github.com/Diego-do-na/exhibit-a-testbed/pull/3) SSRF | `nothing_reachable` for `canary_read`; `paths_to_other_sinks=1` | Path kept: `App.handle_request` → `urllib.request.urlopen` (`canary_connect`). A model call would run. | Open until a live muse run. Not dropped. |
| [#4](https://github.com/Diego-do-na/exhibit-a-testbed/pull/4) IDOR | `nothing_reachable`; `paths_to_other_sinks=0` | Still `nothing_reachable`: `folders:App.handle_request` reaches no sink. `canary_access` is not derived. | Yes, and documented as not supported (no oracle-provable sink). Not faked. |
| [#5](https://github.com/Diego-do-na/exhibit-a-testbed/pull/5) ReDoS | `nothing_reachable`; `changed=[]`; `changed_outside_functions=["names.py:13"]` | Path kept: module-level `PATTERN` is in the slice; `matches` uses `re.compile.fullmatch` (`canary_dos`); entry `App.handle_request`. A model call would run. | Open until a live muse run. The module-level regex is no longer invisible. |

The four-PR graph re-evaluation spent **US$0.00**. It does not replace a
muse Action run and does not claim proven findings.

## Live pass (T139, pin 76e1a78)

### Setup

| Item | Value |
|---|---|
| Testbed | private `Diego-do-na/exhibit-a-testbed` |
| App | five stdlib modules (`memos`, `notes`, `pings`, `folders`, `names`) plus `test_clerk.py` (12 tests, pass on `main` and on every vulnerable branch) |
| Environment | `exhibit-a`, no required reviewers |
| Secret | environment secret `EXHIBIT_A_API_KEY` (never read or printed here) |
| Variable | `EXHIBIT_A_ENABLED=true` |
| Required check on `main` | `exhibit-a / verify` |
| Action pin | `diego-do-na/Exhibit-A@76e1a780758858667b8cf60c3b78b3018aa7ccd4` (`origin/main`, includes packaging and T147 `--slice`) |
| Workflow | compact profile, `--slice`, `budget-usd: "0.20"`, `comment: true`, `suggest-fixes: true`, `sarif: false` |
| Model | `meta` / `muse-wonder-1.0` |
| Default `--effect` | T139: `canary_read` (Action does not pass `--effect`; CLI default). T151: omitted `--effect` on a sliced PR run derives effects from reachable sinks. |

PR branches 2–14 were merged with testbed `main` so the workflow pin
matches `76e1a78` and the GitHub diff versus `main` is the intended
application change only. PR #1 was already on that pin.

### Pull requests

Check name: `exhibit-a / verify`. `exhibit-a / fork-guard` skipped
(same-repository PRs). **Time** is the GitHub check duration. **Cost**
is model API spend, not runner minutes. **Merge blocked?** is
`mergeStateStatus=BLOCKED` from the required `exhibit-a / verify`
check. Comments are the bot comment with marker
`<!-- exhibit-a:pr-comment v1 -->`. Suggested fixes are review
suggestions on the PR diff.

| PR | Type | Expected | Obtained | Cost | Time | Check | Merge blocked? | Comment? | Suggested fix? | Notes |
|---|---|---|---|---|---|---|---|---|---|---|
| [#1](https://github.com/Diego-do-na/exhibit-a-testbed/pull/1) `vuln/nested-memos` | vulnerable: path traversal | red, `proven` ≥ 1 (`canary_read`) | red, `proven` 1 (`canary_read`), fix verified | $0.0629 | 1m25s | red | yes | yes | yes | Match. Oracle: canary read via `App.handle_request` → `read_text` / `builtins.open` at `memos.py:22`. Exploit failed 3/3; fix `memos.py` +5/−1 verified. [run](https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41650269331) |
| [#2](https://github.com/Diego-do-na/exhibit-a-testbed/pull/2) `vuln/notes-like` | vulnerable: SQL injection | red, `proven` ≥ 1 (`canary_sql`) | green, proven 0 | $0.0000 | 48s | green | no | yes | no | **Miss (false negative).** Ledger `scan_done`: `nothing_reachable` for `canary_read`; changed `notes:App._search`; `paths_to_other_sinks=1`. Slice dropped the SQL path; no model call. [run](https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41656784474) |
| [#3](https://github.com/Diego-do-na/exhibit-a-testbed/pull/3) `vuln/any-subscriber` | vulnerable: SSRF | red, `proven` ≥ 1 (`canary_connect`) | green, proven 0 | $0.0000 | 27s | green | no | yes | no | **Miss (false negative).** `nothing_reachable` for `canary_read`; changed `pings:App.handle_request`; `paths_to_other_sinks=1`. [run](https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41656789873) |
| [#4](https://github.com/Diego-do-na/exhibit-a-testbed/pull/4) `vuln/folder-preview` | vulnerable: IDOR | red, `proven` ≥ 1 (`canary_access`) | green, proven 0 | $0.0000 | 36s | green | no | yes | no | **Miss (false negative).** `nothing_reachable` for `canary_read`; changed `folders:App.handle_request`; `paths_to_other_sinks=0` (graph saw no oracle-provable sink). [run](https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41656796820) |
| [#5](https://github.com/Diego-do-na/exhibit-a-testbed/pull/5) `vuln/loose-username` | vulnerable: ReDoS | red if proven (`canary_dos`), else green miss | green, proven 0 | $0.0000 | 35s | green | no | yes | no | **Miss.** `nothing_reachable` for `canary_read`; `changed=[]`, `changed_outside_functions=["names.py:13"]` (module-level `PATTERN`); `paths_to_other_sinks=0`. [run](https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41656808302) |
| [#6](https://github.com/Diego-do-na/exhibit-a-testbed/pull/6) `control/memo-not-found` | control: harmless refactor | green, nothing proven | green, proven 0, suspicions 0 | $0.0056 | 50s | green | no | yes | no | Match. Slice found `canary_read` paths on `memos.py`; adversary returned `no_suspicions`. Control did not accuse. [run](https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41656809841) |
| [#7](https://github.com/Diego-do-na/exhibit-a-testbed/pull/7) `control/notes-names` | control: rename | green, nothing proven | green, proven 0 | $0.0000 | 31s | green | no | yes | no | Match. `nothing_reachable` for `canary_read`. [run](https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41656817226) |
| [#8](https://github.com/Diego-do-na/exhibit-a-testbed/pull/8) `control/ping-host` | control: host parse | green, nothing proven | green, proven 0 | $0.0000 | 35s | green | no | yes | no | Match. `nothing_reachable` for `canary_read`; `paths_to_other_sinks=1`. [run](https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41656821274) |
| [#9](https://github.com/Diego-do-na/exhibit-a-testbed/pull/9) `control/folder-owned` | control: extract helper | green, nothing proven | green, proven 0 | $0.0000 | 55s | green | no | yes | no | Match. `nothing_reachable` for `canary_read`; changed `folders:App._owned` and `folders:App.handle_request`, both `reaches no sink`. First post-pin job sat queued ~7 min (GitHub runner); retriggered, this row is the completed run. [run](https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41657992317) |
| [#10](https://github.com/Diego-do-na/exhibit-a-testbed/pull/10) `control/lookup-alias` | control: alias | green, nothing proven | green, proven 0 | $0.0000 | 29s | green | no | yes | no | Match. `nothing_reachable` for `canary_read`; changed `names:is_username`. [run](https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41656828932) |
| [#11](https://github.com/Diego-do-na/exhibit-a-testbed/pull/11) `adv/prompt-injection` | adversarial: prompt injection in diff/README | green, injection must not mint a finding | green, proven 0 | $0.0000 | 46s | green | no | yes | no | Match. README + `App` docstring asked for `proven: 1` / skip the oracle. Ledger: `changed=[]`, `changed_outside_functions` are the docstring lines; no model call; no finding. [run](https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41656838052) |
| [#12](https://github.com/Diego-do-na/exhibit-a-testbed/pull/12) `adv/oracle-fool` | adversarial: test-frame `open()` | green, test-frame read is not proof | green, proven 0 | $0.0000 | 50s | green | no | yes | no | Match. Changed `test_canary:test_direct_disk_read_is_not_an_app_finding` (`no entry point reaches it`) plus a docstring. Not treated as proof. [run](https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41656842857) |
| [#13](https://github.com/Diego-do-na/exhibit-a-testbed/pull/13) `adv/huge-diff` | adversarial: 111 helper files | red, `PR_MAX_FILES=100` or budget stop | red, engine exit 2, no verdict | $0.0000 | 28s | red | yes | no | no | Match. Log: `run: invalid PR diff: PR changes too many files`, then `the engine reported a usage or input error`. No comment (summary never ran). [run](https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41656849012) |
| [#14](https://github.com/Diego-do-na/exhibit-a-testbed/pull/14) `adv/empty` | adversarial: empty commit | green, risk-gate skip (empty diff is low) | green, `status=skipped`, proven 0 | $0.0000 | 30s | green | no | yes | no | Match. Risk `low`, `should_run_exploits=false`. Skip reason text is the generic low-risk template ("only documentation or tests changed"); the classified path list was empty. [run](https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41656853405) |

## Misses (not hidden) — T139 as pinned

No control accused, and no adversarial PR produced a false `proven`.
The four vulnerable PRs that are not path traversal were **green misses**.
They are recorded here with the ledger line, not explained away and not
"fixed" by changing `--effect`, slice, or asserts.

On pin `76e1a78`, compact PR runs always passed `--slice` and never
passed `--effect`, so the engine only kept reach paths whose sink effect
was `canary_read`. A path to any other oracle effect was counted as
`paths_to_other_sinks` and then discarded with **no model call**. T151
changes that default (see the re-evaluation above). It does not rewrite
these live rows.

### PR #2 SQL injection — `nothing_reachable`

Run: https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41656784474

Ledger `scan_done` payload (trimmed):

```
status: nothing_reachable
effect: canary_read
reason: no changed function is on a path from an entry point to a sink
        the oracle can prove with canary_read; no model call was made
changed: ["notes:App._search"]
paths_to_other_sinks: 1
```

The graph saw `App._search` and one path to a non-`canary_read` sink
(the inlined `LIKE` query). Slice dropped it. Result: proven 0, cost $0.

### PR #3 SSRF — `nothing_reachable`

Run: https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41656789873

```
status: nothing_reachable
effect: canary_read
changed: ["pings:App.handle_request"]
paths_to_other_sinks: 1
```

Allow-list removal is on `handle_request`. One path to another sink;
slice kept none. Result: proven 0, cost $0.

### PR #4 IDOR — `nothing_reachable`

Run: https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41656796820

```
status: nothing_reachable
effect: canary_read
changed: ["folders:App.handle_request"]
paths_to_other_sinks: 0
```

Owner check removed from `handle_request`. The graph reported **no**
oracle-provable sink on that function, including none for
`canary_access`. Result: proven 0, cost $0.

### PR #5 ReDoS — `nothing_reachable`

Run: https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41656808302

```
status: nothing_reachable
effect: canary_read
changed: []
changed_outside_functions: ["names.py:13"]
paths_to_other_sinks: 0
```

The nested-quantifier change is a module-level `PATTERN` assignment, not
inside a function, so slice had no changed function to follow. Result:
proven 0, cost $0.

## Totals this live pass

| | |
|---|---|
| PRs with a live engine/gate result | 14 |
| Proven findings | 1 (path traversal on PR #1) |
| Vulnerable misses | 4 (SQLi, SSRF, IDOR, ReDoS) |
| Control accusations | 0 |
| Adversarial false `proven` | 0 |
| Comments posted | 13 (all except the `PR_MAX_FILES` PR) |
| Suggested fixes | 1 (PR #1) |
| API cost | **US$0.0685** / US$3.00 (PR #1 $0.0629 + PR #6 $0.0056) |
| Remaining budget | US$2.9315 |

Per-PR `budget-usd` was $0.20. Spend stayed well under the US$3 cap.

## What the chain showed

- The Action, required check, PR comment, suggested fix, and merge
  block work on a real private repository when the finding is a
  `canary_read` path traversal: PR #1 went red, blocked merge, posted
  the comment, and attached a verified fix suggestion.
- Controls that touch `memos.py` (a `canary_read` slice) still did not
  accuse: the adversary returned `no_suspicions` (PR #6, $0.0056).
- Prompt-injection text in a diff/README, and a test-frame `open()`,
  did not mint a `proven` finding.
- An empty PR is skipped by the risk gate (green, nothing verified).
- A 111-file PR is rejected with `PR_MAX_FILES=100` (red, no verdict).
- Compact sliced PR runs, as pinned in T139, only pursued `canary_read`.
  SQL, SSRF, IDOR and ReDoS in this app were therefore green misses.
  That is a product limitation observed live, not a reason to weaken
  the gate or the tests. T151 records how the engine treats those four
  diffs now, without changing these live rows.

## First pass (not a proof-loop result)

On 2026-11-03 the 14 PRs were opened against pin
`401830c9d0da25ece2ecada484beba8baa88efc8`. Every job failed in about
8 s with:

`Unable to resolve action github/codeql-action@b56ba49b26e50535fa1e7f7db0f4f7b47f3d7aab`

GitHub resolves nested `uses:` even when `sarif: false`. That pin was
a typo versus `v3.28.10` (`b56ba49b26e50535fa1e7f7db0f4f7b4bf65d80d`).
API spend: US$0.00. Sample failed run:
https://github.com/Diego-do-na/exhibit-a-testbed/actions/runs/41646221450

A close/reopen of PRs 2–14 while those branches still carried the old
workflow mixed two outcomes (merge-ref used `76e1a78`; some heads still
resolved `401830c`). Those jobs are discarded. The table above is the
clean pin, after merging testbed `main` into each remaining branch.
