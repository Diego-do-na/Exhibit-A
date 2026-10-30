# Action demo app

A tiny original web-style app (`pamphlets.py`) with its own baseline test
(`test_pamphlets.py`). It exists only so the GitHub Action can run on a real pull request.
On `main` it confines every requested name to the shelf directory.

Two prepared changes live in `patches/`:

| Patch | What it does | Expected check |
|---|---|---|
| `01-path-traversal.patch` | Replaces the containment check in `_resolve` with a plain `os.path.join`, so `?name=../outside.txt` reads outside the shelf. | red: a proven finding |
| `02-harmless-refactor.patch` | Extracts a `_not_found()` helper and inlines a variable. Behaviour is unchanged. | green: nothing could be proven |

`scripts/action-demo.sh` applies each patch on its own branch. The runbook is
`docs/ci/live-pr-demo.md`. Run the baseline locally with `python -m pytest examples/action-demo`.

The baseline has no path-escape test on purpose: it would fail on the vulnerable branch and
abort the run before the engine could prove anything.
