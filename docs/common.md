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
- T013 Copilot: rewrote AGENTS.md with project thesis, module map, protocol, test command, sandbox prerequisites, and hard rules; pending: none
- T012 claude: pyproject console script exhibit-a, pytest markers docker/ollama/integration; no web extra (live server is stdlib only); pending: none
- T030 Muse: per-role provider/model config with registry and build_roles (src/exhibit_a/models/config.py, tests/test_models_config.py); pending: none
- T016 claude: added .github/workflows/ci.yml (push/PR, Python 3.11, pip install -e '.[dev]', pytest -m 'not docker and not ollama and not integration', no secrets); pending: no test carries the docker/ollama/integration markers yet so the filter deselects nothing (sandbox tests run in CI), and the workflow has not run on GitHub yet
- T017 Copilot: split cli.py into cli package modules and preserved both module entry points; pending: none
- T031 Muse: Meta Model API adapter (src/exhibit_a/models/meta.py, registry in config.py, tests/test_meta.py); endpoint/structured-output/pricing UNVERIFIED, key from env only; pending: stale test_meta_provider_is_explicitly_not_built_yet in tests/test_models_config.py needs a scope exception to update
- T014 cursor-agent: <did>; pending: <left>
- T032 Copilot: added live RecordingProvider wrapper and record-then-replay round-trip test; pending: none
- T018 claude: added src/exhibit_a/sandbox/image.py (build_image/image_tag, python:3.11.9-slim, hash-tagged, reuse via docker image inspect) and tests/test_sandbox_image.py; pending: runner.py still uses its own BASE_IMAGE and does not use build_image yet
- T033 Muse: hardened models/jsonschema.py (bounded depth/strings/containers, strict rules, no silent allows) + tests/test_jsonschema.py adversarial suite green; pending: sandbox suite needs Docker (docker info fails in this env)
- T015 agy: created docs/architecture.md with loop diagram-in-prose, public interfaces, JSON contracts, and sandbox/oracle/model boundaries; pending: none
- T035 Copilot: added marked Ollama integration coverage for all four real role prompts and schemas; pending: none
- T034 assistant: added bounded retries/backoff and strict timeout to post_json; pending: none
- T019 claude: sandbox run() now takes requirements/image and uses image.build_image (pytest always included) instead of committing an image per run, isolation flags unchanged, exports build_image/image_tag/PYTEST_VERSION; pending: callers (oracle/case baseline) do not pass case requirements yet
- T036 assistant: added docs/sandbox.md; pending: none
- T048 Copilot: bounded fixer file count/content and rejected symlink/archive path payloads with focused tests; pending: zip archives are not unpacked, but archive-like content is only bounded as text
- T020 claude: sandbox run() takes canary_path/events_path/env, mounts oracle plugin read-only with PYTHONPATH + -p, events file is the only extra writable mount, oracle_events now populated (tests/test_sandbox_events.py); pending: oracle.py does not call run() with these yet (T026/T027)
- T036 Muse: added bench/probe.py per-role schema-valid-JSON probe (real prompts, N repeats, summary.json/md) + tests/test_probe.py with fake provider green; pending: full suite has 17 pre-existing env failures (Docker down, local-socket PermissionError) plus stale test_meta_provider_is_explicitly_not_built_yet

- T021 assistant: added sandbox limits tests; pending: none
 - T049 assistant: added sandbox security tests; pending: none
