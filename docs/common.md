# docs/common.md — shared per-task log (iteration 2)

Shared per-task log for this iteration (one line per finished task).
Concurrent appends from different branches reconcile without conflicts via `merge=union` in `.gitattributes`.

Protocol:
- Before starting a task: read the last ~40 lines of docs/common.md plus any entries from tasks you depend on; do NOT read the whole file.
- When done: append exactly ONE line:
  `- <TID> <agent>: <did>; pending: <left>`
- docs/common.md is append-only.

## Log

- T011 agy: bootstrapped bitacora and merge driver (docs/common.md, .gitattributes); pending: none
- T012 claude: pyproject console script exhibit-a, pytest markers docker/ollama/integration; no web extra (live server is stdlib only); pending: none
