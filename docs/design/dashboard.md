# Local dashboard (A-15)

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

## Views

- **Runs**: status, headline, repo, PR/commit, risk gate, proven count,
  duration (first to last ledger event), cost (sum of `cost_usd`), paginated,
  newest first. Phone widths turn rows into cards.
- **Run detail**: the verdict timeline BASELINE → SUSPECT → EXPLOIT → RUN →
  VERDICT → FIX → VERIFY → PACKAGE with event counts per stage; for each proven
  finding the evidence: red (the exploit failed on the vulnerable code in N of N
  runs, with the oracle events), the effect type (`canary_read` or
  `canary_write`, derived from the open mode, plus path and mode), green (the
  exploit passed on the fixed code, the baseline still passed, the fix was
  verified), the defender bypass variants (an incomplete fix is called out), and
  the oracle's provenance chain (call stack with the entry point and admitted
  app frames marked); then the discarded suspicions with their verdict and
  reason; then the raw ledger events, paginated.
- **Trends**: per-run stacked bars of `proven`, `discarded_unproven` and
  `invalid_test` over time (hover or focus for the exact counts, plus `flaky`
  and `env_failure`), with a table view below.
- **Replay**: streams a finished ledger step by step over Server-Sent Events,
  paced by `exhibit_a.live.replay.Replayer` (imported, not modified), with
  play/pause, single step, restart and speed. Nothing is re-executed.

Dark and light follow `prefers-color-scheme`. No build step, no CDN, no web
fonts: the page works offline.

### Mapping events to stages

| Stage | Events |
|---|---|
| BASELINE | `baseline_done` without `suspicion_id` / `on` |
| SUSPECT | `suspicion_raised` |
| EXPLOIT | `exploit_written` |
| RUN | `run_started`, `oracle_event` on the vulnerable code |
| VERDICT | `verdict` |
| FIX | `fix_proposed` |
| VERIFY | `run_started`/`oracle_event` with `on: fixed` (or `after_fix`), `baseline_done` on the fixed code, `bypass_attempt`, `bypass_result` |
| PACKAGE | `packaged` |

Status and counts come from `exhibit_a.ci.summary.build_result`, so the
dashboard and the PR comment cannot disagree. The latest verdict per
suspicion wins, as there.

## API (all GET, all under the session cookie)

| Endpoint | Returns |
|---|---|
| `/api/info` | source label |
| `/api/runs?page=&per_page=` | rows, newest first; `per_page` capped at 100 |
| `/api/runs/<id>` | detail view-model |
| `/api/runs/<id>/events?from=&limit=` | bounded event views; `limit` capped at 500 |
| `/api/runs/<id>/replay?speed=&from=` | SSE: `step` frames in ledger order, then `done`; speed capped at 64× |
| `/api/trends?limit=` | verdict counts of the most recent runs (capped at 200), oldest first |

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
