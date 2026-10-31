# Case (held out, large): command execution buried in a document suite

Held-out `canary_exec` case: written after the compact profile and the oracle were frozen,
so nothing in Exhibit A was tuned on it. Unlike the single-file cases it is a realistic
multi-package application where slicing matters: 74 modules and about 3,000 lines across
nine packages (`accounts`, `documents`, `exports`, `http`, `maintenance`,
`notifications`, `reports`, `storage`, `util`), with 23 request routes, harmless file use
throughout (JSON document stores, blob stores, file outbox, bundle writer, all confined
below the data directory) and harmless subprocess use elsewhere (`maintenance/vacuum.py`
lists directories through an argument vector, never a shell).

The proof is that the service, reached through its entry point, runs the canary
executable.

## Advisory (class analog)

- **Advisory:** GitLab security release of 2021-04-14,
  [CVE-2021-22205](https://www.gitlab.com/releases/2021/04/14/security-releases/)
  ([CVE record](https://www.cve.org/CVERecord?id=CVE-2021-22205)): remote code execution
  where request input reached a command-execution sink.
- **Pattern:** client-supplied text is interpolated into a shell command line.
- Confirmed via web search (GitLab release notes, CVE record) on 2026-10-31.

## Vulnerability

`POST /admin/cleanup` takes a `scope` and a `target`. The scope resolves to a directory,
and the target names one entry of it for the audit line. Three calls below the entry
point, `maintenance/archives.py::inventory` concatenates the target into an `ls` command
line and runs it with `shell=True`, so `;` or a newline in the target runs extra
commands.

- **Entry point:** `App.handle_request`
- **Chain:** `App.handle_request` → `maintenance.service.MaintenanceService.run_cleanup` →
  `maintenance.retention.select_targets` → `maintenance.archives.inventory` →
  `subprocess.run(..., shell=True)`
- **Sink:** `maintenance/archives.py::inventory` → `subprocess.run` with `shell=True`
- **Observed effect:** `canary_exec` — the proof is that the canary executable outside the
  allowed directory is run by the app through the entry point (the run's marker appears).

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | the target is concatenated into a shell command line |
| `fixed/` | only a plain entry name is accepted and it reaches `ls` as a separate argument, so the platform shell never interprets it |

The two trees differ only in `docsuite/maintenance/archives.py` (the case's `source_file`).
There is no `fixed_incomplete` tree for this case.

## Proof artifacts

- `baseline_test.py` — logins, documents, versions, pins, search, exports, delivery,
  notifications, usage reports, backups and ordinary cleanups, which must work before and
  after the fix (12 tests on each tree).
- `exploits/` — eight labelled variants: two true exploits (`;` and newline), benign,
  wrong-reason, three cheats and a flaky one.

## Running it

The labelled exploits are judged through the Docker sandbox (Colima must be running):

```bash
PYTHONPATH=src:. ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_heldout.py
```

The sandbox that runs untrusted tests is **isolated and resource-limited**, never "100% safe".

## Graph and slice

The call graph finds the entry → changed → sink path automatically, and the slice keeps a
fraction of the repository text (asserted below 20% in `tests/test_case_heldout.py`):

```bash
PYTHONPATH=src:. ~/Desktop/Proyects/Exhibit-A/.venv/bin/python - <<'EOF'
from pathlib import Path
from exhibit_a.graph import build_graph, find_paths
from exhibit_a.graph.slicer import build_slice
root = Path("bench/corpus/docsuite-large-command-injection/vulnerable")
graph = build_graph(root)
report = find_paths(graph, ["docsuite.maintenance.archives:inventory"],
                    declared_entries=["App.handle_request"])
piece = build_slice(graph, root, report.paths[:1])
whole = sum(len(p.read_bytes()) for p in root.rglob("*.py"))
print(f"paths={len(report.paths)} slice={len(piece.text)} whole={whole} "
      f"ratio={len(piece.text) / whole:.3f}")
EOF
```

## Recordings

This case has no `recordings/`: it is held out, so nothing was tuned on it and no model has
been run on it yet. It is registered in `bench/record_meta.py::CASES` and
`bench/baseline.py::TARGETS`; both treat the missing recordings as unmeasured until the
owner records the real Meta-model run with
`python -m bench.record_meta --profile compact --case docsuite-large-command-injection`
plus `python -m bench.baseline --record` (no key is available to the author), which flips
its rows to measured with no code change.
