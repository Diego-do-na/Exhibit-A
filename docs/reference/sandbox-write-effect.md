# Sandbox write effect (`canary_write`)

`SandboxRunner.run_exploit(..., effect="canary_write")` proves an archive-extraction style
escape inside the isolated, resource-limited Docker sandbox: the application, reached through
an entry point, creates a file outside the allowed directory. The signed-events channel, the
staged-manifest check and the static guard are the same as for the read effect.

## Mount layout

| Path in the container | What it is |
| --- | --- |
| `/workspace` | writable copy of the staged app (hashed before and after the run) |
| `/tmp/exhibit_a_oracle` | a `tmpfs`, `size=16m`, empty at start, discarded with the container |
| `/tmp/exhibit_a_oracle/allowed/` | created by the exploit's conftest (holds `public.txt`) |
| `/tmp/exhibit_a_oracle/outside/` | does not exist at start; the app must create it and the canary |
| `/tmp/exhibit_a_oracle/outside/canary.txt` | the canary path. **No file is mounted here** |
| `/oracle/events.jsonl` | signed oracle events (as for the read effect) |
| `/oracle/outside.json` | result file for the post-run dump (below), the only extra writable bind mount |

Exploits find the canary relative to `EXHIBIT_A_ALLOWED_DIR` (`../outside/canary.txt`); the
guard rejects any mention of `EXHIBIT_A_CANARY` in the test.

Nothing new from the host is exposed: no canary file, no host directory. Unlike a bind mount,
the tmpfs is size-capped and every file the test creates there disappears with the container.

## How the host learns what was written

A tmpfs cannot be read once the container is gone, so the container command runs a short dump
after pytest, preserving pytest's exit status:

```
pytest ... ; rc=$?; python -I -S -c <dump> <work> <canary> /oracle/outside.json; exit $rc
```

The dump lstat's the canary (it must be a regular file, not a link) and checks that it holds the
run's token, and lists `outside/` (path, kind, size; at most 200 entries). The host reads that
JSON as untrusted data (size cap, strict types, only a literal `true` counts) and returns it as
`canary_written` and `outside_listing`. `SandboxRunner` passes `canary_written` to the judge,
so a write proof is confirmed on the sandbox path like on the host path
(`oracle.canary_written`). If the dump never ran (timeout, killed container) the answer is
`False`: nothing is proven.

The token is also known to the test, so a test could write the file itself. That is the
cheating case, not an escape: the judge still requires the open event to come from admitted
application code reached through a declared entry point.

## App-tree check

Only `/workspace` is hashed. A write to `outside/` (tmpfs) never changes the app tree, so
`app_tree_changed` does not fire; a write inside `/workspace` still does.

## Limits

Isolated and resource-limited, not "safe": a green result means nothing could be proven.
