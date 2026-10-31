# Case (held out): path traversal write through an uploaded file name

Held-out `canary_write` case: written after the compact profile and the oracle were frozen, from a
public, already-fixed advisory, so nothing in Exhibit A was tuned on it. Unlike the archive case it
is not an extractor: the file name of a multipart **upload** decides where the file is written. The
proof is that the service, reached through its entry point, creates the canary file outside its
storage directory.

## Advisory

- **Advisory:** Django security releases of 2021-05-04,
  [CVE-2021-31542](https://www.djangoproject.com/weblog/2021/may/04/security-releases/)
  ([CVE record](https://www.cve.org/CVERecord?id=CVE-2021-31542)): `MultiPartParser`,
  `UploadedFile` and `FieldFile` allowed directory traversal via uploaded files with suitably
  crafted file names. Fixed in Django 3.2.1, 3.1.9 and 2.2.21 by stricter basename and path
  sanitation.
- **Pattern:** a client-supplied upload name is only partly sanitized and then joined onto the
  storage root.
- Confirmed via web search (Django weblog, release notes, CVE record, fix commit) on 2026-10-31.

## Vulnerability

`uploaded.sanitize` keeps what follows the last backslash of the client's file name (clients that
send a Windows path) and nothing else, so a name with forward-slash components reaches
`FileStorage.save` unchanged, where `os.path.join(root, name)` follows `../` and lets an absolute
name replace the root.

- **Entry point:** `App.handle_request`
- **Chain:** `App.handle_request` → `service.store_upload` → `UploadedFile` (`sanitize`) →
  `FileStorage.save` → `open(path, "wb")`
- **Sink:** `FileStorage.save` → `open(path, "wb")`
- **Observed effect:** `canary_write` — the proof is that a file holding the run's token appears at
  `outside/canary.txt`, written by the app through the entry point.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | the name is only reduced after the last backslash |
| `fixed/` | a name that is not its own basename, and the names `''`, `.` and `..`, are refused with a 400, as in the upstream fix |
| `fixed_incomplete/` | a name that starts with `..` or `/` is refused, but a name that enters a sub-directory first (`sub/../../...`) is accepted and still climbs out |

The three trees differ only in `uploadsvc/uploaded.py` (the case's `source_file`).

## Proof artifacts

- `baseline_test.py` — ordinary uploads, several files, clashing names, a client-side Windows
  path, refusals and unknown routes, which must work before and after the fix.
- `exploits/` — nine labelled variants: three true exploits (`../`, absolute name, nested
  `sub/../../`), benign, wrong-reason, three cheats and a flaky one.
- `exploits/exploit_true_nested_dotdot_filename.py` is also the **bypass check**: it stays proven
  against `fixed_incomplete/`, so a screen on how the name begins is not accepted as a fix.

## Running it

The labelled exploits are judged through the Docker sandbox (Colima must be running):

```bash
PYTHONPATH=src:. ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_heldout.py
```

The sandbox that runs untrusted tests is **isolated and resource-limited**, never "100% safe".

## Recordings

This case has no `recordings/`: it is held out, so nothing was tuned on it and no model has been
run on it yet. Its offline `--replay` answers come from its own hand-authored materials
(`suspicion.json`, `exploits/`, `fixed/`) through `CaseMaterialsProvider`, not from any model. It
is registered in `bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS`; both treat the
missing recordings as unmeasured until the owner records the real Meta-model run with
`python -m bench.record_meta --profile compact --case upload-filename-traversal` plus `python -m bench.baseline
--record` (no key is available to the author), which flips its rows to measured with no code change.
