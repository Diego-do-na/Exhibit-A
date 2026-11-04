# Sandbox CI timing and shards

The `test` job is unchanged: `pytest -m 'not docker and not ollama and not integration'`
on Python 3.11, no job timeout.

## What timed out

On `main`, the `sandbox` job ran:

```text
timeout-minutes: 60
pytest -m docker
```

after `python -c "from exhibit_a.sandbox.image import build_image; print(build_image([]))"`.

GitHub cancelled that job at 59m59s with `Error: The operation was canceled.`
The last visible progress was around `tests/test_sandbox_security.py` (~98% of
the serial suite). That is the job timeout, not a failing assertion.

This checkout collects **866** tests marked `docker` (37 files). A local count
of "317 tests" is a different collection (older tree or a subset); CI must
run every test `pytest -m docker --collect-only` lists.

## What dominates

| Cost | Once or per test? | Notes |
|---|---|---|
| `docker pull` of `python:3.11.9-slim` / Node LTS | first image build | network; then cached on the runner |
| `docker build` + pip/npm | first use of each content-hashed tag | `build_image` already skips when `docker image inspect` succeeds |
| Wrong CI pre-build (`build_image([])`) | once per job, wasted | that tag is not `pytest==7.3.2`, so the first real test still built |
| Container start (`docker run`, no network, resource limits) | **every test** | required for isolation; this is most of the wall time |
| Image inspect | every `build_image` call | cheap (~0.1s) after the tag exists |

Session-scoped pre-build (and the CI `--prebuild` step) pays pip/npm once per
job. It does not merge containers: each test still runs in its own isolated
and resource-limited sandbox.

## Shards

Four matrix jobs, `fail-fast: false`, `timeout-minutes: 30` (half the old
60-minute budget; intended as about 2x a ~15 minute shard, capped at 30).

```text
python -m exhibit_a.ci.sandbox_shards --list
python -m exhibit_a.ci.sandbox_shards --prebuild
python -m exhibit_a.ci.sandbox_shards --group N --run
```

`N` is `1`..`4`. Extra pytest flags go after `--`:

```text
python -m exhibit_a.ci.sandbox_shards --group 1 --run -- -q --durations=40
```

Packing is greedy by docker-test count per file, then by path, so the same
collection always maps a test to the same shard. On this tree that is 866
tests in 37 files:

| shard | tests | files (examples) |
|---|---|---|
| 1 | 234 | `tests/test_case_expansion.py` only |
| 2 | 211 | held-out, mapped classes, connect, hardening, ... |
| 3 | 211 | JS judged, SQL oracle, redirect, dos, sandbox security, ... |
| 4 | 210 | meta replay, exec oracle, SQL injection, loop, ... |

`tests/test_ci_sandbox_shards.py` asserts the union of shard node ids equals
`pytest -m docker --collect-only` and that no node id appears in two shards.

`sandbox-complete` `needs: sandbox` with `if: always()` and fails unless
`needs.sandbox.result` is `success`. A cancelled or failed shard cannot look
green. Make **sandbox-complete** the required check (the old job name
`sandbox` no longer exists as a single job).

The `test` job is not sharded and keeps the same pytest command.

## Measure locally (Docker must be running)

Full serial baseline (the command that cancelled on GitHub):

```bash
~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest -m docker --durations=40 -q
```

One shard:

```bash
PYTHONPATH=src:. ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m exhibit_a.ci.sandbox_shards --prebuild
PYTHONPATH=src:. ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m exhibit_a.ci.sandbox_shards --group 1 --run -- -q --durations=40
PYTHONPATH=src:. ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m exhibit_a.ci.sandbox_shards --group 2 --run -- -q --durations=40
PYTHONPATH=src:. ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m exhibit_a.ci.sandbox_shards --group 3 --run -- -q --durations=40
PYTHONPATH=src:. ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m exhibit_a.ci.sandbox_shards --group 4 --run -- -q --durations=40
```

Record wall time per shard and the 40 slowest tests in this file when you have
them. Until that run lands, treat old wall time as **>= 60 minutes (cancelled)**
and new expected wall time as **about 15-25 minutes per shard in parallel**.

## Checkout / setup-python pins

Unchanged, already full SHAs:

- `actions/checkout@11d5960a326750d5838078e36cf38b85af677262`
- `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065`

No new third-party action. The Node 20 runner deprecation is left as those
existing pins; bumping them is out of scope until a replacement SHA is
verified the same way as `tests/test_action_yml.py`.
