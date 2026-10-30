# Advisory lookup (A-10)

`exhibit_a.advisory` looks up known advisories (OSV schema) for a project's **pinned**
PyPI dependencies and checks whether a fixed release exists. It is a **second signal**
that can feed a suspicion. It never produces a finding, and an advisory match is never
`proven`: proof still needs the exploit loop and oracle described in SPEC.md section 4.

## What it does

1. **Parses pins** (`deps.py`).
   - `requirements.txt`: `name==X` and `name===X` lines, with extras, environment
     markers (kept as text, **not evaluated**), `--hash` options, comments and `\`
     continuations.
   - `pyproject.toml`, best effort: `[project].dependencies`,
     `[project].optional-dependencies`, `[dependency-groups]` (string entries) and
     `[tool.poetry.dependencies]` / poetry groups when the constraint is an exact version.
   - Everything else is returned as `Unsupported` with a reason, never silently dropped:
     ranges (`>=`, `~=`, `^`, `~`), wildcard pins (`==1.*`), multi-spec constraints,
     direct URLs, VCS and local paths, editable installs, `-r`/`-c` includes (not
     followed), `include-group`, `dynamic = ["dependencies"]`, and lock files
     (`poetry.lock`, `uv.lock`, `pdm.lock` are not read at all).
2. **Fetches candidates** from an OSV backend (`osv.py`):
   - `RecordedOsvBackend` (offline): a JSON file `{"vulns": [<OSV records>]}`. Used by
     every test. Candidates are all records naming the package in the PyPI ecosystem.
   - `HttpOsvBackend` (online): `POST /v1/querybatch` for ids, `GET /v1/vulns/{id}` for
     each record, `POST /v1/query` with `page_token` when a batch result is paginated.
     stdlib `urllib` only, https only, a per-request timeout (default 10 s), a response
     size cap (default 5 MB) and a page cap.
3. **Re-evaluates every candidate locally.** A backend can only propose; the installed
   version is matched against the record's `versions` list and `ranges` here:
   - `ECOSYSTEM` ranges use the built-in PEP 440 ordering (`version.py`; `packaging` is
     not a dependency, so a minimal implementation with epoch/pre/post/dev/local rules).
   - `SEMVER` ranges use a SemVer 2.0 ordering; a non-SemVer installed version leaves the
     range unevaluated (reported, not guessed).
   - `GIT` ranges are not evaluated (they need the commit graph).
   - Events: `introduced`, `fixed`, `last_affected`, `limit`, following the OSV
     evaluation algorithm. `withdrawn` records are counted and skipped.
4. **Reports** an `AdvisoryReport` of `AdvisoryMatch` records
   (`schemas/advisory.py`, JSON Schema in `schemas/advisory_match.schema.json`,
   `schema_version: "1"`, `signal: "advisory_hint"`): package, installed version, where
   the pin was declared, advisory id and aliases (CVE ids), summary, severity as given
   (CVSS vector strings are not recomputed), `fixed_in` (smallest fixed version above the
   installed one), `patch_available`, `upgrade_kind` (`patch`/`minor`/`major`) and
   `upgrade_is_minor_or_major`, `evidence_urls` (the osv.dev page for live data, a
   `fixture://` reference for recorded data, plus the record's references), and notes.
   The report also counts candidates that were not affected, unevaluable or withdrawn.
5. **Reachability hint** (`reachability.py`, optional, `project_root=`): parses the
   project's `.py` files with `ast` (never imports or executes them) and reports whether
   the package is imported and whether any symbol named in the advisory's
   `ecosystem_specific` (`imports[].path/symbols` or `affected_functions`; OSV has no
   PyPI-standard field) is mentioned in a file that imports the package. Virtualenvs,
   hidden and build directories and symlinked files are skipped; files that do not parse
   are counted as skipped.

```python
from exhibit_a.advisory import HttpOsvBackend, RecordedOsvBackend, lookup, parse_requirements

deps = parse_requirements(open("requirements.txt").read()).dependencies
report = lookup(deps, RecordedOsvBackend.from_file("recorded_osv.json"),  # offline
                project_root=".", import_names={"pyyaml": ["yaml"]})
print(report.to_json())
# online: lookup(deps, HttpOsvBackend(timeout=10))
```

## What it cannot prove

- That the project is vulnerable. An advisory says a version range is affected; whether
  the vulnerable code is reachable, configured, and exploitable here is exactly what the
  proof loop exists to decide.
- That the project is safe. No match means no OSV record matched the **pins that could
  be parsed**: unpinned ranges, transitive dependencies (no lock file is read), vendored
  code, and advisories not yet in OSV are invisible.
- That the reachability hint is right. It is a name-level heuristic.
  - False positives: an import that never reaches the vulnerable path, dead code,
    test-only imports, an unrelated identifier that shares the symbol's name.
  - False negatives: `importlib`/`__import__`, re-exports through another module or
    dependency, an import name that differs from the project name and was not given in
    `import_names`, runtime-generated code, non-Python entry points (templates, C
    extensions, config), advisories that list no symbols.
- That `fixed_in` is a safe target. It is the first release the record calls fixed; it
  may be affected by another advisory, and `upgrade_kind` is a version-number heuristic,
  not an API-compatibility promise.
- Environment markers are not evaluated, so a pin that only applies on another platform
  or Python version is still reported (with its marker in `notes`).
- A record whose ranges cannot be evaluated locally is reported as
  `affected_status: "unverified"` when it came from the live service (OSV said the
  version is affected) and only counted as `unevaluable` when it came from recorded data.

## Offline and online modes

- **Offline (default for tests and CI)**: `RecordedOsvBackend`. Deterministic, no network.
  The fixture at `tests/fixtures/advisory/osv_synthetic.json` is **hand-authored and
  synthetic**: written by hand from the OSV schema, fictional package names
  (`fictional-*`), made-up `SYNTH-` ids and `CVE-0000-*` aliases, `.invalid` reference
  URLs. It is not a live capture and describes no real package.
- **Online**: `HttpOsvBackend`. Not exercised against the real service by the test
  suite; tests drive it through an injected fake opener and assert the exact request
  bodies. A real run has not been recorded in this repository.

## Privacy

In online mode the only data sent to api.osv.dev is, per dependency, the normalized
package name, the ecosystem (`PyPI`) and the pinned version, plus the advisory ids when
fetching full records. No source code, file paths, repository names, environment
variables, or credentials are sent, and no API key is used. The User-Agent is
`exhibit-a-advisory`. That a given set of packages and versions was queried is still
visible to the OSV operator and any proxy on the path.

## Network allowlist caveat for CI

The online mode needs outbound HTTPS to `api.osv.dev` (and `osv.dev` if someone follows
the evidence links). CI runners and the Exhibit A sandbox are commonly network-restricted:
the sandbox has **no network by design**, so the lookup must run on the host side, never
inside the sandbox. In a CI job with an egress allowlist, add `api.osv.dev:443` or use
offline mode with a recorded file refreshed by a separate, allowlisted job. A timeout or
connection error surfaces as an exception (`urllib.error.URLError`, `TimeoutError`, or
`AdvisoryDataError` for a malformed reply); callers should treat it as "no data", never
as "no advisories".

## CLI hook (not built)

`cli/` is out of scope for A-10. The intended command:

```
exhibit-a advisories [--requirements PATH ...] [--pyproject PATH]
                     [--offline RECORDED.json | --online] [--timeout S]
                     [--reachability ROOT] [--import-name PROJECT=MODULE ...]
                     [--out advisories.json]
```

It would print unsupported pins to stderr, write the `AdvisoryReport` JSON, append an
`advisory_lookup` event to the ledger, and exit 0 whether or not matches exist (matches
are hints, not failures). Feeding matches into SUSPECT as suspicion `source: "advisory"`
is a loop change and also not built.
