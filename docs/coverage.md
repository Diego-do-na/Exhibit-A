# Coverage matrix

<!-- BEGIN GENERATED: python -m bench.coverage_matrix -->
Coverage is derived from the corpus case manifests, the oracle effects, and the SARIF CWE table.

| vulnerability class | CWE | oracle effect | corpus cases (count) | held-out cases (count) | measured status |
|---|---|---|---:|---:|---|
| arbitrary_file_write | CWE-73 | canary_write | 0 | 0 | not covered |
| archive_extraction_path_traversal | CWE-22 | canary_write | 1 | 0 | measured |
| code_injection | CWE-95 | canary_exec | 0 | 0 | not covered |
| command_injection | CWE-78 | canary_exec | 1 | 0 | unmeasured |
| eval_injection | CWE-95 | canary_exec | 0 | 0 | not covered |
| insecure_deserialization | CWE-502 | canary_exec | 1 | 0 | unmeasured |
| os_command_injection | CWE-78 | canary_exec | 0 | 0 | not covered |
| path_traversal | CWE-22 | canary_read | 1 | 0 | measured |
| path_traversal | CWE-22 | canary_write | 0 | 0 | not covered |
| path_traversal_write | CWE-22 | canary_write | 0 | 0 | not covered |
| sql_injection | CWE-89 | canary_exec | 0 | 0 | not covered |
| sql_injection | CWE-89 | canary_sql | 2 | 0 | unmeasured |
| unsafe_deserialization | CWE-502 | canary_exec | 0 | 0 | not covered |

### Corpus case IDs

- `archive-extraction-pathtraversal`
- `command-injection-shell`
- `sql-injection-login`
- `sql-injection-search`
- `starlette-cve-2023-29159`
- `starlette-cve-2023-29159-fixed`
- `unsafe-deserialization-pickle`

### Not covered by design

- Weak cryptography has no oracle-observable effect in the current proof loop.
- Business logic flaws have no oracle-observable effect in the current proof loop.
<!-- END GENERATED -->
