# Code graph, reachability and slicing (SCAN / SLICE, T084)

The graph **proposes; only the sandboxed proof decides.** It answers one question before any
model is called: is a changed function on a path from an entry point an attacker can reach
to a sink the oracle can observe? Reachability is not exploitability. A path says where to
look and which entry point the oracle must see. It is never a finding, and an empty result
means "nothing could be proven", never "safe".

## Why

Two problems came from sending every changed file whole to the adversary:

1. **The adversary chose the entry point the oracle judges against.** On 2026-10-30 it wrote
   decorated names (`App.handle_request(POST, blob)`) that matched no frame. Nothing stopped it
   from naming the sink's own caller, which lets a test that calls the sink directly pass the
   provenance check (`tests/test_graph_slice.py::test_the_model_entry_point_cannot_widen_what_the_oracle_accepts`
   shows this on the archive case).
2. **A PR that touches nothing reachable still paid for model calls.**

## Design

| Piece | Module | What it does |
|---|---|---|
| Graph | `src/exhibit_a/graph/build.py` | Call graph of a Python tree, standard-library `ast` only |
| Catalog | `src/exhibit_a/graph/catalog.py` | Sinks and entry points, as data, each with a vulnerability class |
| Reach | `src/exhibit_a/graph/reach.py` | Diff hunks to changed functions, then paths from an entry point through a changed function to a sink |
| Slice | `src/exhibit_a/graph/slicer.py` | The source of the functions on the best paths, numbered, under a size cap; `SlicePlan` for the loop |
| Contracts | `src/exhibit_a/schemas/graph.py` | `CodeGraph` and `ReachReport` JSON, `schema_version` 1 |
| CLI | `exhibit-a scan`, `exhibit-a run --slice` | See below |

### Graph

Repository code is untrusted input. It is parsed, never imported or executed. Files come from
`os.walk` without following symlinks. Symlinked files, hidden directories and vendored
directories (`.venv`, `venv`, `node_modules`, `site-packages`, `dist-packages`, `__pycache__`)
are skipped. Every file is opened with `O_NOFOLLOW` and `O_NONBLOCK` and must be a regular
file. Limits: 5,000 files, 1 MB per file, 50 MB in total. A file that does not parse is
listed under `skipped` with the reason.

Nodes are modules, classes, functions and methods. Each is named `module:qualname`, where the
qualname is the `__qualname__` CPython gives the code object (`StaticFiles.__call__`,
`create_app.<locals>.raw`). The part after the colon is therefore exactly what the oracle
compares against a frame. Each node records its file and line span, including decorators.
Module names follow the package chain: `src/pkg/mod.py` is `pkg.mod`.

Edges resolve without guessing:

| Kind | Example |
|---|---|
| `call` | `helper()` bound by a def, `from m import f` (re-exports through a package `__init__` followed) |
| `attr` | `pkg.helpers.helper()`, `hh.other()` after `import pkg.helpers as hh` |
| `method` | `self.m()`, `cls.m()`, `super().m()` through in-repository bases, `self` inside a closure |
| `ctor` | `Class()` to `Class.__init__` (inherited if needed), `cls()` in a classmethod |
| `instance` | `x = Class(); x.m()`, `Class().m()`, `self.attr = Class()` then `self.attr.m()`, a parameter annotated with a class |
| `ref` | a function handed to a call: `anyio.to_thread.run_sync(self.lookup_path, path)`, `Route("/", home)` |
| `external` | a call leaving the repository, with its dotted name and capped arguments: `os.path.join`, `pathlib.Path.read_text`, `builtins.open` |
| `unresolved` | everything else, with its text: `obj.anything`, `view(query)`, `getattr(os, name)()` |

A name bound by a parameter or an assignment of unknown type shadows outer names, so
`def f(open): open(x)` is an unresolved call, never `builtins.open`. The output is sorted and
deterministic.

### Catalog

Sinks are external dotted names. Each has a category, a vulnerability class, and the oracle
effect that can prove it today:

| Class | Sinks | Effect |
|---|---|---|
| `path_traversal` | `open` / `io.open` / `os.open` (read), `pathlib.Path.read_*`, `os.stat`, `os.path.realpath`, `os.listdir`, `anyio.open_file`, framework file responses | `canary_read` |
| `path_traversal_write` | `open` with a w/a/x/+ mode, `os.open` with write flags, `pathlib.Path.write_*`, `shutil.copy*`/`move`, `os.rename`/`replace` | `canary_write` |
| `archive_extraction_path_traversal` | `zipfile`/`tarfile` `extract`/`extractall`, `shutil.unpack_archive` | `canary_write` |
| `command_injection` | `subprocess.*`, `os.system`, `os.popen`, `os.exec*` | none |
| `code_injection` | `eval`, `exec`, `compile`, `__import__`, `importlib.import_module` | none |
| `insecure_deserialization` | `pickle.load(s)`, `marshal.loads`, `yaml.load` without a `SafeLoader` | none |
| `ssrf` | `urllib.request.urlopen`, `http.client`, `requests.*`, `httpx.*` | none (not a v1 class: the sandbox has no network) |

A sink argument built with `os.path.join` is flagged (`joined_path`) and breaks ranking ties.
A method name such as `.extractall` or `.read_text` on a receiver nothing resolved is a
**weak** sink hit.

Entry points: ASGI callables (`__call__(self, scope, receive, send)`, or a function with
those parameters), WSGI callables, route decorators (`@app.route`, `@router.get`, ...), route
tables (`Route(path, handler)`, Django `path(...)`, `add_url_rule`, ...), Django views, CLI
mains (`main()`, functions called under `if __name__ == "__main__":`, `@click.command()`), and
request-handler methods (`handle_request`, `dispatch_request`, `do_GET`, ...). The
`entry_points` list in a case's `case.json` always wins: when present, those are the only
entry points.

### Reach

A unified diff (parsed with `triage/diffparse.py`) is mapped to new-side lines, then to the
innermost function around each line. A deleted line counts as the line it sat before. For a
benchmark case, which names a file and not a change, every function of `source_file` counts
as changed.

From each changed function the search runs breadth-first, layer by layer, backward to entry
points and forward to sinks. A depth limit (12) and a shared node budget (50,000 expansions)
bound it. A path is `entry -> ... -> changed -> ... -> sink`. When the changed function only
computes a value that its immediate caller hands to a sink, the sink chain may start at that
caller (`returns = 1`). This is the archive case:

```
App.handle_request -> Extractor.extract_all -> Extractor.extract_member -> [Extractor._target]
  -> (returns to Extractor.extract_member) -> builtins.open (line 71)
```

An unresolved attribute call is followed to methods with the same name, but only when there
are at most three of them. Each such hop, like each weak sink hit, halves `confidence`. Paths
are ranked by hops (plus the return), then unresolved hops, then a joined-path argument, then
names, so the ranking is deterministic.

### Slice and the loop (`--slice`, off by default)

`exhibit-a run --case ... --slice` and `exhibit-a run --pr-diff BASE..HEAD --slice` build the
graph of the staged clone first. Only paths to a sink whose effect is the run's effect count.
A path to `subprocess.run` can never end in a `canary_read` proof, so it is not worth a model
call.

- **No path:** a `scan_done` event with `status: nothing_reachable` records the changed
  functions, why each one is unreached, and the graph size. No baseline runs, no model is
  called, and the run exits 0. A PR-diff run still writes `result.json` and its run-index line.
- **Paths:** the loop records a `scan_done` event with `status: sliced` (the paths and the
  slice size). The adversary gets the slice instead of the whole file: the best three paths,
  their functions with file names and line numbers, and a header naming each path and its
  entry point.

Each suspicion is then mapped to the best path through a function containing its location,
falling back to the best path overall. Its `entry_point` is replaced by that path's entry
point, and the oracle judges with that single name. The model's text is kept in the
`suspicion_raised` event (`graph.model_entry_point`) for the record only. It can never widen
what the oracle accepts.

The prompt builders, schemas and replay keys are unchanged. `tests/test_compact_profile.py`
pins the standard hash (unchanged) and now the compact hash too; the slice is only a
different input to the same builders. `--slice` with `--replay` is refused, because no
recorded key was made with a slice.

### `exhibit-a scan`

```bash
exhibit-a scan                       # RepoProfile placeholder, unchanged
exhibit-a scan REPO                  # RepoProfile from scan.detect()
exhibit-a scan REPO --graph [--graph-out graph.json] [--entry-point Class.method ...]
exhibit-a scan REPO --pr-diff BASE..HEAD   # adds the reach report, built on HEAD as committed
```

## What the graph cannot see

Each of these costs recall (a missed path, so `nothing_reachable` or a slice without the
relevant code), or money (a path that leads nowhere). None of them produces a proof.

- **Dynamic dispatch.** `view = self.routes.get(path); view(query)`, `await response(scope,
  receive, send)`, handlers stored in dicts or lists, `*args`/`**kwargs` forwarding to a
  callable parameter. The oracle fixture app (`tests/fixtures/oracle/vulnerable/app.py`)
  routes through a dict, so its graph has no edge from `App.handle_request` to the handler.
- **`getattr`, `importlib`, `__import__`, string-built names.**
- **Monkeypatching and runtime rebinding** (`module.f = g`, patched methods, metaclasses that
  inject methods).
- **Framework magic beyond the catalog.** Middleware stacks (`self.middleware_stack(...)`),
  dependency injection, signal and event dispatch, decorators that wrap or replace a function,
  class-based views registered by string, plugin entry points, ORM hooks.
- **Values of unknown type.** Return values of functions, items of containers, parameters
  without a class annotation, attributes assigned more than one type, and instances of classes
  outside the repository except through their dotted name.
- **Data flow.** Reach is call-graph reachability, not taint. The only flow it follows is one
  return to the immediate caller. A helper two calls deep whose result reaches a sink is
  missed.
- **Changes outside functions.** Module constants, class attributes and import lines are
  listed (`changed_outside_functions`) but start no search.
- **Native code, C extensions, subprocesses**, and anything that happens outside Python.
- **Limits.** Files over the caps, the depth limit and the node budget (`budget_exhausted` in
  the report).

## Why imprecision never yields a false proof

A `proven` verdict still needs everything in SPEC section 4: the baseline passes, the exploit
fails on the vulnerable code, and the oracle observes the intended effect inside the isolated,
resource-limited sandbox with valid provenance, stably across N runs. The fix must then make
the exploit pass while the baseline still passes. The graph changes none of these checks. It
only decides three things:

1. **Whether to call a model at all.** A missed path skips the call, which costs recall. A
   wrong path wastes a call, which costs money.
2. **What the adversary reads.** A slice that misses code can only make a proof less likely.
3. **The entry point the oracle requires.** This is the only place the graph touches the
   judgement, and it can only **narrow** it. Without `--slice` the oracle accepts whatever
   name the model wrote, including the sink's own caller. With `--slice` it accepts one
   function that the catalog detected in the code, or that the case declared. A wrong
   detection (for example an internal method that happens to be called `handle_request`) is
   no wider than what the model could name before, and it comes from the code, not from
   model output. Declaring `entry_points` in `case.json` removes even that.

## Measured on the corpus (2026-10-30)

Environment: this cloud container (4 vCPU, Python 3.13). Times are the median of 5 graph
builds. The Starlette trees are the PyPI wheels unzipped as plain files, never installed or
imported. "case clone" is the tree `exhibit-a run --case` stages: `pip --target` with
Starlette 0.26.1, anyio, idna and typing_extensions. "Diff" means the vulnerable tree as a
change against the fixed one (or the reverse for a fixed tree). "All functions" means every
function of `source_file`, which is what `--case --slice` searches from. The slice column
counts characters for the case run (best three paths for the run's effect) against the whole
`source_file`.

| Tree | Files | Nodes | Edges | Resolved / external / unresolved | Build | Entry points | Sink calls | Changed (diff) | Paths (diff) | Paths (all functions) | Slice / whole file (chars) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| archive-extraction vulnerable | 1 | 14 | 27 | 7 / 9 / 11 | 5 ms | 1 | 1 | `Extractor._target` | 1 | 5 | 1,763 / 3,666 |
| archive-extraction fixed | 1 | 14 | 31 | 7 / 13 / 11 | 5 ms | 1 | 3 | `Extractor._target` | 3 | 15 | 1,766 / 3,950 |
| Starlette 0.26.1 (vulnerable, wheel) | 34 | 609 | 1,398 | 379 / 570 / 449 | 285 ms | 24 | 7 | `StaticFiles.lookup_path` | 3 | 22 | 5,342 / 8,735 |
| Starlette 0.27.0 (fixed, wheel) | 34 | 609 | 1,398 | 379 / 570 / 449 | 240 ms | 24 | 7 | `StaticFiles.lookup_path` | 3 | 22 | 5,340 / 8,733 |
| Starlette 0.26.1 case clone | 91 | 2,207 | 5,412 | 1,483 / 2,680 / 1,249 | 1,485 ms | 26 | 27 | `StaticFiles.lookup_path` | 4 | 29 | 5,342 / 8,735 |

Paths found (best first, all with confidence 1.0):

- **Archive, vulnerable and fixed:** `App.handle_request -> Extractor.extract_all ->
  Extractor.extract_member -> [Extractor._target] -> (returns to Extractor.extract_member) ->
  builtins.open`, an open for writing (`path_traversal_write`, `canary_write`). On the fixed
  tree, the `os.path.realpath` calls the fix added to `_target` rank first. The open for
  writing is still reported.
- **Starlette 0.26.1 and 0.27.0:** `StaticFiles.__call__ -> StaticFiles.get_response ->
  [StaticFiles.lookup_path] -> os.path.realpath` (and `-> os.stat`). The `get_response ->
  lookup_path` edge is a `ref` edge: the method is handed to `anyio.to_thread.run_sync`, not
  called. The fixed tree still has the path, as it should. Reachability is not
  exploitability, and the proof decides.

**Entry points found automatically:** yes for both cases. `StaticFiles.__call__` comes from
the ASGI rule. `App.handle_request` comes from the request-handler rule, and the archive
case's `case.json` also declares it, which wins. Both match the entry points the
hand-authored materials and the compact Meta recordings use.

Both corpus cases also ran end to end through `exhibit-a run --case <case> --slice`, with a
scripted provider (the case's hand-authored answers, served by role) and the host oracle
instead of Docker. Both ended `proven` with a verified fix, judged with the graph's entry
point. The same run inside the sandbox is the docker-marked
`tests/test_graph_slice.py::test_corpus_case_with_slice_in_the_sandbox`, run by the CI
`sandbox` job.

### Not measured

- Live model cost with `--slice`. No key was used and no live model was called. The slice is
  48% of `archive.py` and 61% of `staticfiles.py` in characters, but the token and cost effect
  on a real run, and whether a model proves as often from a slice, are open. Compare verdicts
  and cost per case against `docs/meta-run.md` before claiming a saving.
- Larger repositories. The caps are set, but build time beyond a few thousand nodes was not
  profiled.
