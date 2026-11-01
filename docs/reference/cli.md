# Exhibit A CLI Reference

Exhibit A is a security-verification engine driven through the command-line interface. Baseline, exploit, fixed-code, and bypass tests run in an isolated, resource-limited sandbox without network access or host secrets. A green result means "nothing could be proven", never "safe".

## Exit codes

The CLI uses standard exit codes across all commands:

- `0`: Success / nothing could be proven (clean baseline, no provable exploit, or successful verification).
- `1`: Runtime error or verification failure (e.g. invalid manifest signature or unhandled exception).
- `2`: Command-line usage error or invalid arguments.
- `10`: Finding proven (in `exhibit-a run` and `exhibit-a reproduce`).
- `20`: Run incomplete (in `exhibit-a run` and `exhibit-a reproduce`; e.g., baseline tests failed or sandbox unavailable).

See docs/reference/cli-exit-codes.md for detailed exit code definitions.

## Main command: `exhibit-a --help`

```text
usage: exhibit-a [-h]
                 {scan,run,ledger,trace,report,runs,advisories,dashboard,audit,doctor,reproduce,sarif,verify} ...

Exhibit A skeleton CLI: proof before accusation.

positional arguments:
  {scan,run,ledger,trace,report,runs,advisories,dashboard,audit,doctor,reproduce,sarif,verify}
    scan                Print the RepoProfile of a repository (a placeholder
                        without one), optionally with its call graph and reach
                        paths.
    run                 Run the core loop (wired for benchmark cases via
                        --case).
    ledger              Print totals for one run id from a ledger file.
    trace               Print the ordered steps one run took, from its ledger.
    report              Render a finding package as Markdown or HTML.
    runs                Print the table of past runs.
    advisories          Look up OSV advisories (hint, not proof).
    dashboard           Serve the optional local dashboard.
    audit               Audit a whole repository: rank graph reach paths and
                        prove the top targets.
    doctor              Verify the effective isolation and limits of a sandbox
                        probe container.
    reproduce           Re-run a proof bundle in the sandbox with no model
                        call.
    sarif               Export proven findings from a run directory to SARIF
                        2.1.0 for code scanning.
    verify              Check a proof bundle offline: file hashes and manifest
                        signature.

options:
  -h, --help            show this help message and exit

Exit codes: 0 success; 1 runtime error; 2 usage or input error.
```

## exhibit-a scan

Analyzes repository structure, dependencies, frameworks, static call graph reachability, and PR diff impact.

### Help output

```text
usage: exhibit-a scan [-h] [--graph] [--graph-out FILE]
                      [--pr-diff BASE..HEAD] [--entry-point NAME]
                      [--lang {auto,python,javascript,typescript}]
                      [repo]

positional arguments:
  repo                  Repository to scan. Without it, a RepoProfile
                        placeholder is printed.

options:
  -h, --help            show this help message and exit
  --graph               Add a summary of the static call graph (entry points,
                        sinks, sizes).
  --graph-out FILE      With --graph, also write the whole graph as JSON to
                        FILE.
  --pr-diff BASE..HEAD  Add the reach paths (entry -> changed function ->
                        sink) of the commits' changes.
  --entry-point NAME    Declared entry point (Class.method); repeatable.
                        Declared names replace detection.
  --lang {auto,python,javascript,typescript}
                        Repository language (default: auto-detect from
                        package.json, tsconfig.json, case.json language and
                        file extensions). Also selects the static call graph
                        builder.
```

### Example

```bash
exhibit-a scan . --graph --pr-diff main..HEAD
```

Scan the current repository, compute the static call graph, and determine reachable paths from entry points to sinks for code modified between `main` and `HEAD`.

See docs/design/code-graph.md for details on graph construction and reachability.

## exhibit-a run

Executes the core verification loop over benchmark cases or pull-request diffs inside an isolated, resource-limited sandbox.

### Help output

```text
usage: exhibit-a run [-h] [--case CASE] [--pr-diff BASE..HEAD] [--out OUT]
                     [--repo REPO] [--diff DIFF] [--recording RECORDING]
                     [--effect {canary_read,canary_write,canary_exec,canary_sql,canary_connect,canary_dos,canary_redirect,canary_access}]
                     [--replay] [--provider PROVIDER] [--model MODEL]
                     [--lang {auto,python,javascript,typescript}]
                     [--profile {standard,compact}] [--slice | --no-slice]
                     [--reasoning-effort {minimal,low,medium,high,max}]
                     [--max-output-tokens N] [--budget-usd BUDGET_USD]

options:
  -h, --help            show this help message and exit
  --case CASE           Benchmark case.json (or its directory) to run the loop
                        on.
  --pr-diff BASE..HEAD  Run the proof loop on source files changed between two
                        commits (Python, JavaScript, TypeScript).
  --out OUT             Output directory for the clone, ledger and packages
                        (default: runs/case).
  --repo REPO           Path to the target clone.
  --diff DIFF           Path to the PR diff file.
  --recording RECORDING
                        Replay recording for a PR-diff run (also read from
                        EXHIBIT_A_REPLAY_RECORDING).
  --effect {canary_read,canary_write,canary_exec,canary_sql}
                        Oracle effect to prove in PR-diff mode (default:
                        canary_read).
  --replay              Replay recorded model calls instead of calling a
                        provider.
  --provider PROVIDER   Model provider to use for every role (overrides
                        EXHIBIT_A_PROVIDER).
  --model MODEL         Model name to use for every role (overrides
                        EXHIBIT_A_MODEL).
  --lang {auto,python,javascript,typescript}
                        Case language (default: auto — the case.json language,
                        else detected from the staged clone). Routes baseline,
                        exploit, fix and verify through the matching sandbox
                        and oracle.
  --profile {standard,compact}
                        Prompt profile. 'compact' bounds every answer, asks
                        the fixer for search/replace edits, and defaults to
                        --reasoning-effort minimal plus per-role output caps,
                        to cut cost. 'standard' (default) matches the recorded
                        replays.
  --slice, --no-slice   Build the static call graph first: when no changed
                        function is on a path from an entry point to a sink,
                        record that and make no model call; otherwise send the
                        adversary only the functions on those paths and judge
                        with the graph's entry point, never the model's. On by
                        default with --profile compact, off with the standard
                        profile; --slice / --no-slice override.
  --reasoning-effort {minimal,low,medium,high,max}
                        Reasoning effort sent to chat-completions providers
                        (default: provider default; minimal with --profile
                        compact).
  --max-output-tokens N
                        Output-token ceiling per model call (default: none;
                        per-role caps with --profile compact).
  --budget-usd BUDGET_USD
                        Hard cost limit in USD for this run.
```

### Example

```bash
exhibit-a run --case bench/corpus/starlette-cve-2023-29159 --replay
```

Run the complete verification loop on the Starlette CVE benchmark case in an isolated, resource-limited sandbox using recorded replay responses without making live model API calls.

See docs/reference/cli-exit-codes.md for exit codes, docs/bench/cost-controls.md for `--profile compact`, and docs/reference/providers.md for model provider configuration.

## exhibit-a ledger

Computes and prints token usage, latency, financial costs, and event counts for a specific run from the append-only JSONL ledger.

### Help output

```text
usage: exhibit-a ledger [-h] [--ledger LEDGER] run_id

positional arguments:
  run_id           Run id to total up.

options:
  -h, --help       show this help message and exit
  --ledger LEDGER  Path to the append-only JSONL ledger (default:
                   ledger.jsonl).
```

### Example

```bash
exhibit-a ledger run-20261029-123456 --ledger runs/case/ledger.jsonl
```

Display aggregate token counts, execution duration, and USD costs for run `run-20261029-123456` from `runs/case/ledger.jsonl`.

The ledger is the single source of truth for all run metrics and verdicts.

## exhibit-a trace

Prints chronological lifecycle events, tool calls, and outcomes of a verification run from the ledger.

### Help output

```text
usage: exhibit-a trace [-h] [--ledger LEDGER] [--json] run_id

positional arguments:
  run_id           Run id whose steps to print.

options:
  -h, --help       show this help message and exit
  --ledger LEDGER  Path to the append-only JSONL ledger (default:
                   ledger.jsonl).
  --json           Print JSON instead of text.
```

### Example

```bash
exhibit-a trace run-20261029-123456 --ledger runs/case/ledger.jsonl
```

Print the ordered sequence of verification stages and decisions recorded for run `run-20261029-123456`.

Pass `--json` to output machine-readable trace records.

## exhibit-a report

Renders a packaged finding directory as formatted Markdown or standalone HTML with escaped code snippets.

### Help output

```text
usage: exhibit-a report [-h] [--format {md,html}] [--out FILE] package_dir

positional arguments:
  package_dir

options:
  -h, --help          show this help message and exit
  --format {md,html}
  --out FILE
```

### Example

```bash
exhibit-a report runs/case/packages/finding-1 --format md --out report.md
```

Generate a GitHub-flavored Markdown report from finding package `runs/case/packages/finding-1` and save it to `report.md`.

Supports `--format md` and `--format html`.

## exhibit-a runs

Queries and prints past run summaries from the run index file.

### Help output

```text
usage: exhibit-a runs [-h] [--index INDEX] [--json]

options:
  -h, --help     show this help message and exit
  --index INDEX
  --json
```

### Example

```bash
exhibit-a runs --index runs.jsonl
```

Print a formatted ASCII table showing past runs, statuses, costs, and verdict counts recorded in `runs.jsonl`.

Pass `--json` to output raw JSON objects per run.

## exhibit-a advisories

Queries OSV for known vulnerabilities matching package dependencies (used as suspicion hints, never proof).

### Help output

```text
usage: exhibit-a advisories [-h] [--requirements FILE] [--pyproject FILE]
                            [--offline FIXTURE] [--json]

options:
  -h, --help           show this help message and exit
  --requirements FILE
  --pyproject FILE
  --offline FIXTURE
  --json
```

### Example

```bash
exhibit-a advisories --requirements requirements.txt
```

Query OSV for security advisories affecting dependencies declared in `requirements.txt`.

See docs/security/advisory.md: advisory matches serve only as hypotheses for the verification loop.

## exhibit-a dashboard

Launches a local, read-only web dashboard to explore verification runs, call graphs, traces, and proof artifacts.

### Help output

```text
usage: exhibit-a dashboard [-h] --source SOURCE [--port PORT] [--export DIR]
                           [--run RUN_ID] [--open]

options:
  -h, --help       show this help message and exit
  --source SOURCE  Dashboard source, such as local:RUNS.
  --port PORT
  --export DIR     Write a self-contained static dashboard to DIR.
  --run RUN_ID     Run to include in a static export (default: newest).
  --open           Open the live dashboard URL in the default browser.
```

### Example

```bash
exhibit-a dashboard --source local:runs --port 8080
```

Start the read-only dashboard server on `http://127.0.0.1:8080` reading run data from the `runs` directory.

For a serverless artifact, export one local run (the newest run by default):

```bash
exhibit-a dashboard --source local:runs --export site --run run-20261029-123456
```

The resulting `site/index.html` can be opened with `file://` or served by GitHub Pages. It contains the copied dashboard frontend, the selected raw ledger under `runs/<run-id>/`, and deterministic derived JSON under `data/`; it makes no network requests. Use `--open` only with live server mode to open its one-time browser URL automatically.

See docs/design/dashboard.md for security model and architecture.

## exhibit-a audit

Performs a whole-repository security audit by ranking static call graph reach paths and verifying top sink targets under a budget cap.

### Help output

```text
usage: exhibit-a audit [-h] --repo REPO [--out OUT] [--budget-usd BUDGET_USD]
                       [--max-targets MAX_TARGETS] [--list-only]
                       [--profile {standard,compact}] [--provider PROVIDER]
                       [--model MODEL]
                       [--effect {canary_read,canary_write,canary_exec,canary_sql}]

options:
  -h, --help            show this help message and exit
  --repo REPO           Repository directory to audit.
  --out OUT             Output directory for audit.json/audit.md.
  --budget-usd BUDGET_USD
                        Hard cost limit in USD.
  --max-targets MAX_TARGETS
                        Most sink targets to attempt.
  --list-only           Only rank and print targets; call no model and spend
                        nothing.
  --profile {standard,compact}
                        Prompt profile for the verification loop.
  --provider PROVIDER   Model provider for every role.
  --model MODEL         Model name for every role.
  --effect {canary_read,canary_write,canary_exec,canary_sql}
                        Reserved: audit already covers every provable effect;
                        ignored.
```

### Example

```bash
exhibit-a audit --repo . --budget-usd 2.0 --max-targets 5 --profile compact
```

Audit the local repository by ranking reach paths to dangerous sinks and testing up to 5 targets within a $2.00 cost limit using the compact profile.

See docs/ci/audit.md for scheduled and on-demand audit workflows.

## exhibit-a doctor

Verifies the effective isolation, runtime capabilities, seccomp filters, and cgroup limits of the sandbox via an ephemeral probe container.

### Help output

```text
usage: exhibit-a doctor [-h] [--runtime RUNTIME] [--json]

options:
  -h, --help         show this help message and exit
  --runtime RUNTIME  Docker runtime to verify (overrides
                     EXHIBIT_A_DOCKER_RUNTIME, e.g. runsc).
  --json             Print the isolation report and seccomp profile as JSON.
```

### Example

```bash
exhibit-a doctor
```

Launch an ephemeral sandbox probe container and verify that isolation guarantees (no network, dropped capabilities, non-root user, seccomp mode, read-only mounts) are strictly enforced.

See docs/reference/sandbox.md for isolation requirements and threat mitigations.

## exhibit-a reproduce

Re-executes a proof bundle inside the isolated, resource-limited sandbox against vulnerable and fixed code trees without calling any AI model.

### Help output

```text
usage: exhibit-a reproduce [-h] --repo REPO [--timeout TIMEOUT] [--key KEY]
                           [--key-file FILE]
                           package

positional arguments:
  package            Proof-bundle directory to reproduce.

options:
  -h, --help         show this help message and exit
  --repo REPO        Vulnerable source tree to replay the proof against.
  --timeout TIMEOUT  Seconds per sandbox run (default: 120).
  --key KEY          Attestation key as hex (overrides EXHIBIT_A_ATTEST_KEY).
  --key-file FILE    File holding the attestation key as hex.
```

### Example

```bash
exhibit-a reproduce runs/case/packages/starlette-cve-2023-29159 --repo /path/to/starlette
```

Verify reproducibility of a proof bundle by running its exploit test in the sandbox against vulnerable and fixed repository checkouts with zero model calls.

See docs/reference/proof-bundles.md for verification and reproduction workflows.

## exhibit-a sarif

Exports proven findings and evidence locations from a completed run directory to standard SARIF 2.1.0 format.

### Help output

```text
usage: exhibit-a sarif [-h] --out-dir DIR [--output FILE]

options:
  -h, --help     show this help message and exit
  --out-dir DIR  Run directory containing packages/ and ledger.jsonl.
  --output FILE  File to write SARIF JSON to (default: stdout).
```

### Example

```bash
exhibit-a sarif --out-dir runs/case --output findings.sarif
```

Convert proven findings in `runs/case` to a SARIF 2.1.0 report saved to `findings.sarif` for GitHub Code Scanning upload.

Includes CWE mappings, rule metadata, and observed source sink locations.

## exhibit-a verify

Performs offline cryptographic verification of a proof bundle by validating file SHA-256 digests and the attestation manifest HMAC signature.

### Help output

```text
usage: exhibit-a verify [-h] [--key KEY] [--key-file FILE] package

positional arguments:
  package          Proof-bundle directory to check.

options:
  -h, --help       show this help message and exit
  --key KEY        Attestation key as hex (overrides EXHIBIT_A_ATTEST_KEY).
  --key-file FILE  File holding the attestation key as hex.
```

### Example

```bash
exhibit-a verify runs/case/packages/starlette-cve-2023-29159
```

Check that all proof files in the package match their digests in `manifest.json` and verify the cryptographic signature using the attestation key.

See docs/reference/proof-bundles.md for key discovery and verification rules.
