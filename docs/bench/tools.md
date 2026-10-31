# Benchmark: static tools versus Exhibit A

## Results

<!-- BEGIN GENERATED: python -m bench.tools_compare -->
Static tools are run as installed, with Bandit 1.8.6 and Semgrep 1.141.0 pinned for reproducibility. A missing CLI is **not run**, never zero findings.

| tool | target tree | role | status | reported | TP | FP | false accusations | precision | recall |
|---|---|---|---|---:|---:|---:|---:|---:|---:|
| Bandit | archive-extraction-pathtraversal/vulnerable | vulnerable | not run | - | - | - | - | - | - |
| Semgrep | archive-extraction-pathtraversal/vulnerable | vulnerable | not run | - | - | - | - | - | - |
| CodeQL | archive-extraction-pathtraversal/vulnerable | vulnerable | not run | - | - | - | - | - | - |
| Bandit | archive-extraction-pathtraversal/fixed | fixed | not run | - | - | - | - | - | - |
| Semgrep | archive-extraction-pathtraversal/fixed | fixed | not run | - | - | - | - | - | - |
| CodeQL | archive-extraction-pathtraversal/fixed | fixed | not run | - | - | - | - | - | - |
| Bandit | archive-extraction-pathtraversal/fixed_incomplete | incomplete | not run | - | - | - | - | - | - |
| Semgrep | archive-extraction-pathtraversal/fixed_incomplete | incomplete | not run | - | - | - | - | - | - |
| CodeQL | archive-extraction-pathtraversal/fixed_incomplete | incomplete | not run | - | - | - | - | - | - |
| Bandit | command-injection-shell/fixed | fixed | not run | - | - | - | - | - | - |
| Semgrep | command-injection-shell/fixed | fixed | not run | - | - | - | - | - | - |
| CodeQL | command-injection-shell/fixed | fixed | not run | - | - | - | - | - | - |
| Bandit | command-injection-shell/fixed_incomplete | incomplete | not run | - | - | - | - | - | - |
| Semgrep | command-injection-shell/fixed_incomplete | incomplete | not run | - | - | - | - | - | - |
| CodeQL | command-injection-shell/fixed_incomplete | incomplete | not run | - | - | - | - | - | - |
| Bandit | command-injection-shell/vulnerable | vulnerable | not run | - | - | - | - | - | - |
| Semgrep | command-injection-shell/vulnerable | vulnerable | not run | - | - | - | - | - | - |
| CodeQL | command-injection-shell/vulnerable | vulnerable | not run | - | - | - | - | - | - |
| Bandit | starlette-cve-2023-29159 | vulnerable | not run | - | - | - | - | - | - |
| Semgrep | starlette-cve-2023-29159 | vulnerable | not run | - | - | - | - | - | - |
| CodeQL | starlette-cve-2023-29159 | vulnerable | not run | - | - | - | - | - | - |
| Bandit | starlette-cve-2023-29159-fixed | fixed | not run | - | - | - | - | - | - |
| Semgrep | starlette-cve-2023-29159-fixed | fixed | not run | - | - | - | - | - | - |
| CodeQL | starlette-cve-2023-29159-fixed | fixed | not run | - | - | - | - | - | - |
| Bandit | unsafe-deserialization-pickle/vulnerable | vulnerable | not run | - | - | - | - | - | - |
| Semgrep | unsafe-deserialization-pickle/vulnerable | vulnerable | not run | - | - | - | - | - | - |
| CodeQL | unsafe-deserialization-pickle/vulnerable | vulnerable | not run | - | - | - | - | - | - |
| Bandit | unsafe-deserialization-pickle/fixed | fixed | not run | - | - | - | - | - | - |
| Semgrep | unsafe-deserialization-pickle/fixed | fixed | not run | - | - | - | - | - | - |
| CodeQL | unsafe-deserialization-pickle/fixed | fixed | not run | - | - | - | - | - | - |
| Bandit | unsafe-deserialization-pickle/fixed_incomplete | incomplete | not run | - | - | - | - | - | - |
| Semgrep | unsafe-deserialization-pickle/fixed_incomplete | incomplete | not run | - | - | - | - | - | - |
| CodeQL | unsafe-deserialization-pickle/fixed_incomplete | incomplete | not run | - | - | - | - | - | - |

Headline totals (measured rows only):

| tool | reported | TP | FP | false accusations | precision | recall |
|---|---:|---:|---:|---:|---:|---:|
| Bandit | not run | - | - | - | - | - |
| Semgrep | not run | - | - | - | - | - |
| CodeQL | not run | - | - | - | - | - |

Exhibit A aggregate rows (from existing replayed recordings/results):

| system | reported | TP | FP | false accusations | precision | recall |
|---|---:|---:|---:|---:|---:|---:|
| Bandit | 0 | 0 | 0 | 0 | n/a | n/a |
| CodeQL | 0 | 0 | 0 | 0 | n/a | n/a |
| Semgrep | 0 | 0 | 0 | 0 | n/a | n/a |

Exhibit A rows come from the existing replayed recordings and benchmark results; they are not rerun as a static tool. Static tools are fast and free and cover classes Exhibit A cannot prove. Exhibit A reports less and proves what it reports.
<!-- END GENERATED -->
