# Local dashboard (A-15)

> The UI described below was replaced by the final dashboard design. The server, API and
> security model still apply; the pages, their files and how to edit them are documented in
> [web/dashboard/README.md](../../web/dashboard/README.md).

A read-only page on `127.0.0.1` that shows what Exhibit A proved over time. It
is a viewer of recorded runs, not a separate product: every number on it comes
from a run's ledger (the single source of truth, SPEC.md section 9), and the
CI result JSON only adds facts the ledger cannot hold (engine exit code, risk
gate, skip reason).

A run with nothing proven reads **"nothing could be proven"**, never "safe".

## Launch

```bash
python scripts/make_sample_runs.py runs-sample          # SYNTHETIC sample runs
PYTHONPATH=src python -m exhibit_a.dashboard --source local:runs-sample
```

The terminal prints a one-time link such as
`http://127.0.0.1:8765/auth?token=…`. Open it once in your browser: it sets a
session cookie and takes you to the dashboard. The link stops working after
that first use; restart the dashboard to get a new one (for example after
closing the browser, since the cookie lasts for the browser session).

Options:

| Flag | Meaning |
|---|---|
| `--source local:<dir>` | A directory of run folders (see below). |
| `--source github:<owner/repo>` | Runs whose ledger artifact lives in GitHub Actions, read through your own `gh` CLI. |
| `--port N` | Port on 127.0.0.1 (default 8765; 0 picks a free one). There is no host option. |
| `--artifact NAME` | Artifact name for the GitHub source (default `exhibit-a-ledger`, as in `action.yml`). |
| `--web DIR` | Directory holding the UI (default `web/dashboard` of the checkout). |
| `--verbose` | Log method, path and status of each request (never query strings). |

For the GitHub source, `gh auth login` first (or set `GH_TOKEN` in the
environment `gh` sees). The dashboard never reads, stores or prints the token.

## Data sources

Both implement one interface, `RunSource` (`src/exhibit_a/dashboard/sources.py`):
`list_runs() -> [RunRef]` and `load_run(id) -> RunData` (validated events of one
run id plus the CI result, or an `error` and no events).

### `LocalRunsSource`

```
runs/
  runs.jsonl            optional index (read when present, never required)
  <run-folder>/
    ledger.jsonl        required
    result.json         optional, as written by `python -m exhibit_a.ci.summary build`
```

- Run folders are discovered by scanning; folder names must match
  `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` and must not be symlinks.
- `runs.jsonl` (being built by another task in `src/exhibit_a/ledger/index.py`)
  is read tolerantly: each JSON object line may name its folder with `dir`,
  `path` or `run_id` and may carry `repo`, `pr`, `commit`/`head_sha`, `branch`,
  `started_at`/`ts` and `synthetic`. Lines that are not objects, point outside
  the directory, or name a missing folder are ignored. When the index format
  lands, adjust `LocalRunsSource._index` if its keys differ.
- Without an index, repo/PR/commit come from the run's `pr_opened` event when
  present. Runs from `exhibit-a run` on a corpus case have no `pr_opened`, so
  those columns show "—".
- A ledger that holds several run ids is narrowed to the result's `run_id`, else
  to the last event's run id (the same rule as `ci/summary.py`).

### `GitHubSource`

- Listing: one call, `gh api --method GET repos/<repo>/actions/artifacts -f
  name=<artifact> -f per_page=100`. Expired artifacts are skipped; for re-runs
  the newest artifact of a workflow run wins. Cached for 60 seconds.
- Loading a run: `gh api repos/<repo>/actions/runs/<id>` (commit, branch, PR
  number) and `gh api repos/<repo>/actions/artifacts/<artifact-id>/zip`. The
  zip arrives on stdout and is read **in memory**; only the top-level
  `ledger.jsonl` and `result.json` entries are opened. Nothing is written to disk.
- Loaded runs are cached in memory (LRU, 128 runs); failures are not cached, so
  the next view retries.
- Runs list rows load each run on the visible page (20 by default), and the
  trends view loads the 50 most recent runs, so the first view of a large
  repository makes one `gh` round trip per run.

## Information architecture (two levels)

The dashboard organizes navigation into two explicit levels:

1. **Repository level** (default `#/`):
   - **Sidebar switcher**: Repository selector on top of the sidebar (`GET /api/repos`).
   - **Sidebar menu**:
     - `Home` (`#/` or `#/repo/<repo_id>`)
     - `Pull requests` (`#/runs` or `#/repo/<repo_id>/runs`)
     - `Findings` (`#/findings` or `#/repo/<repo_id>/findings` — whole repository)
     - `Code graph` (`#/dependencies` or `#/repo/<repo_id>/graph` — whole repository)
     - `Benchmark` (`#/benchmark` and `#/trends`)
   - No "Current run" widget is shown at the repository level.
2. **Pull request level** (activated when opening a run/PR at `#/run/<run_id>`):
   - **Sidebar back link**: Back arrow returning to the repository (`#/repo/<repo_id>` or `#/`).
   - **Sidebar menu**:
     - `Summary` (`#/run/<run_id>`)
     - `Process` (`#/run/<run_id>/process` and `#/replay/<run_id>`)
     - `Findings` (`#/run/<run_id>/findings` and `#/run/<run_id>/finding/<finding_id>`)
     - `Code graph` (`#/run/<run_id>/graph`)
   - **Breadcrumb**: Always renders `repo / PR / section` (or `repo / section` at repository level).

**Top bar**:
- The Home is the complete, cumulative history of the repository since its first run, never filtered by date; KPIs sum all runs.
- **Metadata columns**: Small-caps labels with monospace values for:
  - `LAST UPDATE`: timestamp of the most recent PR run ingested (`max(started_at)` formatted in UTC, or `"not available"`).
  - `SOURCE`: `info.source` (or `"not available"`).
  - `PR RUNS`: number of pull request runs covered (`metrics.runs` / `runs.length`, or `"not available"`).
- Sequence / run-order charts use the chronological order of PR runs on the x-axis (`PR #`, short commit SHA, or run order) with the timestamp only as a secondary label. Per-PR detail lives inside each PR report.
- A `Synthetic sample data` badge is shown whenever any loaded run has `synthetic == true`.

## Data contracts (grounding rule)

Every number, label, sentence, and chart in the UI comes from a named field of real data from the four allowed sources:
1. Run ledger events (`pr_opened`, `scan_done`, `baseline_done`, `suspicion_raised`, `exploit_written`, `run_started`, `oracle_event`, `verdict`, `fix_proposed`, `bypass_attempt`, `bypass_result`, `packaged` with their payloads, timestamps, role, model, tokens, and cost).
2. Run summary and CI gate classification built by the server (`verdicts`, `proven`, highest proven `severity`, `cwe`, `effect`, `risk` and path `reasons` from `src/exhibit_a/ci/gate.py`, `cost_usd`, `duration_s`, `commit`, `branch`, `pr`, `title`, `synthetic`).
3. Code graph endpoints (`/api/runs/<id>/codegraph` and `/api/runs/<id>/graph`).
4. Benchmark results in `bench/results/*.json` (`bench/results/2026-11-01.json`), corpus manifests (`bench/corpus/*/case.json`), corpus recordings (`bench/corpus/*/recordings/*.json`), and `docs/bench/bench.md`.

**Missing value rule**: When a field is missing, null, or empty, the UI displays the exact text `"not available"`, never `0` and never a placeholder number.

### Repository level widgets

| Widget | Endpoint | Exact field(s) | Formula (if any) | Missing state |
|---|---|---|---|---|
| Repository switcher | `GET /api/repos` | `repos[].id`, `repos[].name`, `repos[].runs`, `repos[].proven`, `repos[].synthetic` | None (sorted by `last_run.started_at` descending) | `"not available"` |
| Top bar: Last update | `GET /api/repos/<id>` / `GET /api/runs` | `pull_requests[].started_at` / `runs[].started_at` | `max(started_at)` of the most recent PR run ingested | `"not available"` |
| Top bar: Source | `GET /api/info` | `source` | Direct string | `"not available"` |
| Top bar: PR runs covered | `GET /api/repos/<id>` / `GET /api/runs` | `metrics.runs` / `runs.length` | Cumulative count of PR runs covered (`N PR runs`) | `"not available"` |
| KPI: Proven findings | `GET /api/repos/<id>` | `metrics.proven`, `metrics.root_causes`, `pull_requests[].proven` | `sum(r.proven)` across all repository runs | `"not available"` |
| KPI: Fixes verified | `GET /api/repos/<id>` | `metrics.fixes_verified`, `pull_requests[].fixes_verified` | Cumulative count of proven findings where `passes_on_fixed.fix_verified == true` and `bypass.succeeded == 0` | `"not available"` |
| KPI: Fixes defeated by bypass | `GET /api/repos/<id>` | `metrics.fixes_bypassed`, `pull_requests[].fixes_bypassed` | Cumulative count of proven findings where `bypass.succeeded > 0` | `"not available"` |
| KPI: Discarded suspicions | `GET /api/repos/<id>` | `metrics.discarded`, `pull_requests[].dropped` | `sum(r.dropped)` across all repository runs | `"not available"` |
| KPI: Total cost | `GET /api/repos/<id>` | `metrics.cost_usd`, `metrics.tokens_in`, `metrics.tokens_out`, `pull_requests[].cost_usd` | `sum(r.cost_usd)` formatted in USD; subtext `sum(tokens_in + tokens_out)` | `"not available"` |
| KPI: Median run duration | `GET /api/repos/<id>` | `metrics.median_duration_s`, `pull_requests[].duration_s` | Median of non-null `duration_s` values across all repository runs | `"not available"` |
| Chart: Proven findings per PR run (stacked by effect) | `GET /api/repos/<id>` | `pull_requests[].pr`, `pull_requests[].commit`, `pull_requests[].started_at`, `pull_requests[].effects` | Ordered oldest-to-newest by PR run (`PR #` / commit on x-axis, date as secondary label); stacked by `effect` | `"not available"` |
| Chart: Verification funnel | `GET /api/repos/<id>` | `metrics.{suspicions_raised, exploits_written, proven, fixes_verified, fixes_bypassed}` | Cumulative counts across all repository runs (`bypass_resistant = fixes_verified`) | `"not available"` |
| Chart: Verdict outcome donut | `GET /api/repos/<id>` | `pull_requests[].verdicts.{proven, discarded_unproven, invalid_test, flaky, env_failure}` | `total = sum(counts)`, `share_pct = round(count * 100 / total, 1)` | `"not available"` |
| Chart: Hot files heatmap (`file x PR run`) | `GET /api/repos/<id>` | `pull_requests[].files_touched[]`, `top_findings[].file`, `pull_requests[].pr` | Matrix of touched/finding files × PR runs in run order | `"not available"` |
| Chart: Cost & tokens per PR run by role | `GET /api/repos/<id>` | `role_costs[]` (`run_id`, `pr`, `by_role.{adversary, test_writer, fixer, defender}.{cost_usd, tokens_in, tokens_out, events}`) | Ordered by PR run on x-axis, stacked per role | `"not available"` |
| Chart: Time per stage | `GET /api/repos/<id>` | `stage_durations[]` (`stage`, `seconds`, `events`) | Sum of stage durations derived from ledger event timestamps and `latency_ms` | `"not available"` |
| Chart: Severity & CWE distribution | `GET /api/repos/<id>` | `top_findings[]` (`cwe`, `severity`, `effect`, `occurrences`) | Cumulative count of proven findings per `(cwe, severity)` | `"not available"` |
| Pull requests filter panel + sortable table | `GET /api/repos/<id>` / `GET /api/runs` | `run_id`, `pr`, `title`, `branch`, `commit`, `status`, `highest_severity`, `effects[]`, `cwes[]`, `risk`, `duration_s`, `cost_usd`, `proven`, `dropped` | Left row border coloured by `highest_severity` (neutral when `proven == 0`); client sort & filter on exact fields | `"not available"` per missing cell |
| Repository Findings table | `GET /api/repos/<id>` | `top_findings[]`, `all_findings[]` (`run_id`, `finding_id`, `class`, `severity`, `cwe`, `effect`, `file`, `line`, `fix_status`, `pr`, `started_at`, `occurrences`) | Sorted by severity rank then fix status then recency | `"not available"` |
| Repository Code graph | `GET /api/runs/<latest_run_id>/codegraph` | `available`, `nodes[]`, `edges[]`, `reach_paths[]`, `proven_paths[]`, `stats` | Force-directed layout (`ForceGraph`) over AST nodes and edges | `reason` or `"not available"` |

### Pull request level widgets (`#/run/<run_id>`)

| Widget | Endpoint | Exact field(s) | Formula (if any) | Missing state |
|---|---|---|---|---|
| Indicator 1: Proven severity gauge | `GET /api/runs/<id>` | `run.highest_severity`, `run.proven`, `proven[]` | Highest severity among `proven` findings (`low`, `medium`, `high`, `critical`). When `proven == 0`, neutral `"Nothing proven"` state with copy `"nothing could be proven; this is not evidence of safety"` (never green, never `"safe"`). | `"Nothing proven"` / `"not available"` |
| Proven severity: "How this level was built" | `GET /api/runs/<id>` | `proven[].id`, `proven[].evidence.effect.type`, `proven[].evidence.cwe`, `proven[].evidence.severity`, `proven[].evidence.passes_on_fixed.fix_verified`, `proven[].evidence.bypass.succeeded` | One row per proven finding; footer `"Highest of N proven findings = <SEVERITY>"` | `"No proven findings in this run"` |
| Indicator 2: Change risk (CI gate) | `GET /api/runs/<id>` | `gate.level` (`run.risk`), `gate.should_run_exploits`, `gate.reasons[]` (`path`, `risk`, `rule`) | `exhibit_a.ci.gate.classify(changed_paths)` on `pr.diff` paths (or `result.json` `risk`) | `"not available"` |
| Change risk: "How this level was built" | `GET /api/runs/<id>` | `gate.reasons[].path`, `gate.reasons[].risk`, `gate.reasons[].rule` | Exact path-to-rule mapping from `src/exhibit_a/ci/gate.py` (`CI workflow or action definition`, `dependency manifest or lock file`, `container definition`, `file in a sensitive directory`, `documentation`, `test code`, `application code`) | `"not available"` |
| PR Details key-value panel | `GET /api/runs/<id>` | `run.{repo, pr, branch, commit, started_at, duration_s, cost_usd, status, synthetic}` | Direct fields; sandbox label fixed to `"isolated and resource-limited"` | `"not available"` |
| Proven findings list & detail | `GET /api/runs/<id>` | `proven[].{id, class, file, line, entry_point, hypothesis, reason, evidence}` | 5-part proof standard checklist from `evidence.{fails_on_vulnerable, effect, provenance, passes_on_fixed, bypass, fix}` + empty `data-slot="knowledge-sheet"` | `"not available"` |
| Discarded suspicions list | `GET /api/runs/<id>` | `discarded[].{id, class, file, line, entry_point, verdict, reason}` | Grouped or listed with the ledger's own `verdict` and `reason` text | `"not available"` |
| Process: 8-stage timeline | `GET /api/runs/<id>` | `stages[].{name, reached, count, duration_s, first_ts, description}` | One-sentence plain-English explanation from `SPEC.md` section 3 + event count + elapsed `duration_s` from ledger timestamps | `"not available"` |
| Process: Per-suspicion swimlanes | `GET /api/runs/<id>` | `swimlanes[]` (`id`, `class`, `file`, `line`, `stages_reached[]`, `stopped_at`, `verdict`, `reason`) | Derived from ledger events bearing `suspicion_id` | `"not available"` |
| Process: Model roles breakdown | `GET /api/runs/<id>` | `costs.by_role.{adversary, test_writer, fixer, defender}.{events, tokens_in, tokens_out, cost_usd}` | Summed per role from ledger events | `"not available"` |
| Process: Animated replay & event stream | `GET /api/runs/<id>/events`, `GET /api/runs/<id>/replay` | `events[].{seq, ts, type, stage, role, model, cost_usd, latency_ms, summary, payload}` | Populated by default at full run completion (`N / N events`); user-paced replay (`Play`, `Step`, `Reset`, speed `1x..8x`) highlights stages and oracle observations | `"not available"` |
| PR Code graph + "What this PR changes" panel | `GET /api/runs/<id>/codegraph` | `nodes[]`, `edges[]`, `reach_paths[]`, `proven_paths[]`, `changed_source`, `stats` | Filters nodes with `changed == true` (`file`, `function`, `method`), lists their callers and callees from `edges[]`, and highlights proven paths | `"not available"` |

### Benchmark widgets (`#/benchmark`)

| Widget | Endpoint | Exact field(s) | Formula (if any) | Missing state |
|---|---|---|---|---|
| System precision & recall bars + table | `GET /api/benchmark` | `systems[]` (`system`, `reported`, `true_positives`, `false_positives`, `false_accusations`, `precision`, `recall`, `discarded`, `calls`, `cost_usd`, `live_usd`, `model_wall_s`) | Aggregated from `bench/results/2026-11-01.json` `per_target` rows where `measured == true` (matching `docs/bench/bench.md` headline rows) | `"not available"` |
| Class-label mismatch note | `GET /api/benchmark` | `label_mismatches[]` (`case`, `ground_truth_class`, `proven_effect`, `verdict`, `reason`) | Identifies the 4 vulnerable cases in `bench/results/2026-11-01.json` where `reported > 0`, `false_positives > 0`, `false_accusations == 0`, and `recordings/meta-muse-wonder-1.0-compact.json` has `verdict == "proven"` | `"not available"` |
| Case × vulnerability-class outcome matrix | `GET /api/benchmark` | `matrix.cases[]`, `matrix.classes[]`, `matrix.cells[]` (`case`, `vuln_class`, `effect`, `cwe`, `outcome`, `reported`, `tp`, `fp`, `discarded`, `cost_usd`, `calls`) | Joined from `bench/results/2026-11-01.json` and `bench/corpus/*/case.json` + `recordings/meta-muse-wonder-1.0-compact.json` | `"not available"` |
| Cost per case against model calls | `GET /api/benchmark` | `per_case[]` (`target`, `calls`, `cost_usd`, `reported`, `discarded`, `model_wall_s`) | Direct fields from `bench/results/2026-11-01.json` for `Exhibit A, compact profile` | `"not available"` |
| Discard reasons breakdown | `GET /api/benchmark` | `discard_reasons[]` (`verdict`, `reason_code`, `count`, `cases[]`) | Counted across non-proven verdicts in `bench/corpus/*/recordings/meta-muse-wonder-1.0-compact.json` | `"not available"` |
| Vulnerability class coverage & "Not covered yet" | `GET /api/benchmark` | `coverage.covered[]`, `coverage.not_covered_yet[]`, `coverage.unclaimed_by_design[]` | Derived from `CWE_TABLE` and `bench/corpus/*/case.json` (as in `bench/coverage_matrix.py`) | `"not available"` |

### Expand-to-modal contract (every chart)

Every chart card includes an expand button opening a modal dialog containing:
1. Enlarged interactive chart with **zoom and pan** (mouse wheel, `+` / `-` / `Reset` buttons, double-click, keyboard `+`, `-`, `0`, arrow keys).
2. **`HOW TO READ THIS`**: Fixed template describing the axes, units, and colour/pattern encoding of that chart type.
3. **`WHAT STANDS OUT`**: Fixed deterministic templates filled strictly from the numbers shown in the chart:
   - `"Total across shown items: <total> (<unit>)."`
   - `"Largest item: <max_label> with <max_value> of <total> (<share>%)."`
   - `"Smallest non-zero item: <min_label> with <min_value> of <total> (<min_share>%)."`
   - `"Zero-value items: <zero_count> of <item_count>."`
4. **`THE NUMBERS`**: Exact tabular view of every series/slice shown in the chart (`Label`, `Count / Value`, `Share %`), where every cell equals the corresponding number in the API response.

## API (all GET, all under the session cookie)

| Endpoint | Returns |
|---|---|
| `/api/info` | source label |
| `/api/repos` | repository summaries (`id`, `name`, `runs`, `proven`, `last_run`, `trend`, `severity_mix`), most recently active first |
| `/api/repos/<id>` | repository detail: `repo`, `metrics`, `pull_requests`, `top_findings`, `all_findings`, `funnel`, `verdict_totals`, `hot_files`, `role_costs`, `stage_durations`, `cwe_distribution` |
| `/api/runs?page=&per_page=` | rows, newest first; `per_page` capped at 100 |
| `/api/runs/<id>` | detail view-model (`run`, `gate`, `stages`, `swimlanes`, `proven`, `discarded`, `costs`, `trace`, `graph`) |
| `/api/runs/<id>/events?from=&limit=` | bounded event views; `limit` capped at 500 |
| `/api/runs/<id>/replay?speed=&from=` | SSE: `step` frames in ledger order, then `done`; speed capped at 64× |
| `/api/runs/<id>/graph` | AST entry-to-sink path subgraph for the run |
| `/api/runs/<id>/codegraph` | full repository AST graph (`file`, `function`, `method`, `sink`) with PR diff changes and proven paths |
| `/api/trends?limit=` | verdict counts of the most recent runs (capped at 200), oldest first |
| `/api/benchmark` | real benchmark evaluation from `bench/results/*.json`, corpus recordings, and coverage matrix |

## Threat model

**Assets.** The contents of your run ledgers and CI results (private code
paths, suspicions, exploit reasons), and, for the GitHub source, the
authority of your `gh` login.

**Trust boundaries.** Everything read from a ledger, a result file, an index
or GitHub is untrusted: ledgers contain model output, and anyone who can open a
pull request influences what a run records. The browser is trusted only after
it presents the session cookie; any other web page open in the same browser is
hostile.

| Threat | Mitigation |
|---|---|
| Another machine on the network reads the dashboard | Binds `127.0.0.1` only; there is no option to bind anything else. |
| A malicious web page reads the API from your browser (cross-site read) | Every `/api/` request needs the session cookie, which is `HttpOnly` and `SameSite=Strict`, so cross-site requests do not carry it. No CORS headers are ever sent, so a foreign origin cannot read responses. Requests with `Sec-Fetch-Site` other than `same-origin`/`none`, or a foreign `Origin`, are refused. |
| DNS rebinding (an attacker's hostname resolving to 127.0.0.1) | Strict `Host` check on every request, static files included: only `127.0.0.1:<port>` and `localhost:<port>`. A rebound page sends its own hostname and gets 421; it also cannot burn the bootstrap token. |
| Another local user or process guesses the session | Bootstrap token and session are separate 256-bit `secrets.token_urlsafe` values per launch, compared in constant time. The bootstrap token works once. |
| Bootstrap token leaks through the URL | One-time use; `Referrer-Policy: no-referrer`; request logs drop query strings; the page is never framed. Residual: the token stays in browser history and the terminal scrollback, but is dead after its first use. |
| XSS from hostile ledger content (script tags, `javascript:` URLs, event handlers) | The client renders every string with `textContent`/`createTextNode`; `innerHTML` and other HTML sinks are never used (tested statically and in a real browser with a hostile fixture). Links are limited to internal `#/` routes and `https://github.com/` (run links are built from the validated repo and numeric run id, never taken from data). CSP `default-src 'self'` with no inline script or style, `object-src 'none'`, `base-uri 'none'`, `form-action 'none'`, `frame-ancestors 'none'`. JSON is served as `application/json` with `nosniff`. |
| Malformed or oversized data (memory exhaustion, parser crashes, misleading partial runs) | Caps: ledger 8 MiB, line 256 KiB, 20,000 events, result 256 KiB, index 2 MiB, 1,000 runs, artifact zip 24 MiB with 64 entries and per-entry uncompressed caps checked on the actual bytes read, `gh` stdout 24 MiB / stderr 16 KiB; JSON with NaN/Infinity or excessive nesting is rejected; displayed strings, lists and nesting are truncated. Every line must validate as an `Event`; the result file must match the schema of the fields used. A run that fails any check is shown as **unreadable as a whole**, never partially, because dropping one `verdict` line could turn a proof into "nothing could be proven". |
| Path tricks in the local source | Run ids are validated by regex; folders and files are opened without following symlinks (`O_NOFOLLOW`), must be regular files (FIFOs refused without blocking), and index entries cannot point outside the directory. Static files come from a fixed whitelist. |
| Command injection through the GitHub source | `gh` is started with a fixed argv list, never a shell; the repo must match `owner/name` (no `..`), the artifact name a strict pattern, and run/artifact ids are integers. `gh` runs with a timeout and output caps, prompts disabled. Error text is truncated and token-shaped strings are redacted. |
| The dashboard changes state | GET only (everything else is 405); no endpoint writes files; the GitHub source reads artifacts in memory. The only process-wide state is the in-memory cache. |
| Secrets in logs | Requests are not logged by default; `--verbose` logs method, path and status only. The session value is never printed. |

**Out of scope / residual risks.**

- A local attacker running as your user can read your browser profile, your
  terminal or the ledgers directly; the dashboard does not defend against that.
- Malicious software on the machine can connect to `127.0.0.1` but still needs
  the token or session; the token is printed to your terminal.
- `localhost` is accepted in the `Host` header; if your system resolves
  `localhost` to something other than loopback, use the printed `127.0.0.1`
  link (the bootstrap link always uses it).
- The GitHub source trusts your `gh` binary and its configuration.
- The sandbox that produced the runs is isolated and resource-limited; this
  dashboard does not change or assess that boundary.

## Tests

`tests/test_dashboard_sources.py`, `tests/test_dashboard_model.py`,
`tests/test_dashboard_server.py`, `tests/test_dashboard_xss.py` (helpers in
`tests/test_dashboard_support.py`, hostile fixture in
`tests/fixtures/dashboard/hostile/`). Handler tests drive the real handler over
an in-memory request (like `tests/test_live.py`), so they need no socket. The
browser XSS test needs Node with Playwright and Chromium; it skips with an
explicit reason when they are missing. GitHub tests use a fake `gh` callable or
a fake `gh` executable on `PATH`; nothing touches the network or a token.

`scripts/make_sample_runs.py` writes ten **synthetic** runs (labelled in
`pr_opened`, the index and a README): the Starlette `StaticFiles` traversal
(CVE-2023-29159, `canary_read`) proven and fixed, the archive extraction
traversal (`canary_write`) proven and with an incomplete fix bypassed by a
defender variant, an aborted baseline, a risk-gate skip, flaky and env_failure
verdicts, and history for the trends chart.

## Requires (outside this task's scope)

1. **`exhibit-a dashboard` subcommand (T072).** Wire it in `src/exhibit_a/cli/`
   as a thin wrapper: `exhibit-a dashboard --source local:<dir>|github:<owner/repo>
   [--port N] [--artifact NAME] [--verbose]`, delegating to
   `exhibit_a.dashboard.server.main(argv)` with the same flags. Do not add a
   host flag.
2. **Packaging the UI.** `web/dashboard/` sits outside the `src/` package, so a
   wheel install (not an editable checkout) would not ship it; `--web` covers
   that today. To ship it, move the UI under `src/exhibit_a/dashboard/web/` (or
   add package data in `pyproject.toml`) and point `default_web_dir` at it.
3. **`runs.jsonl` contract.** When `src/exhibit_a/ledger/index.py` lands, confirm
   its key names (`dir`/`run_id`, `repo`, `pr`, `commit`, `branch`,
   `started_at`) or adjust `LocalRunsSource._index`.
4. **Repo/PR/commit in real runs.** The loop does not emit `pr_opened` for CLI
   corpus runs; once the PR-diff surface exists, emitting `repo`, `pr`,
   `commit` and `branch` in `pr_opened` (or in `result.json`) fills those
   columns for local runs.
5. **Ignoring generated samples.** If users generate sample runs inside the checkout
   (`runs-sample/`), consider ignoring that path.
