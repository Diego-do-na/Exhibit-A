# Case: tar slip in a backup restore (member path escapes the destination)

Tar-slip case for Exhibit A. It is proven through the existing
``canary_write`` effect: the vulnerable app extracts a tar archive without
confining member names, and the proof is that a member lands on the canary
outside the restore directory.

## Vulnerability

`restore` opens the request bytes as a tar archive and calls `extractall`
on the destination. A member named `../outside/canary.txt` (or an absolute
path) is written outside the destination.

- **Entry point:** `App.handle_request`
- **Sink:** `tarfile.open.extractall`
- **Observed effect:** `canary_write`
- **CWE:** CWE-22 Improper Limitation of a Pathname to a Restricted Directory

## Real-world analog and originality

This models tar slip. The real public CVE is **CVE-2007-4559** (Python
`tarfile` directory traversal via member names). The fix analog is
confining each member's resolved path to the destination directory.
Confirmed via public records; the app is original synthetic code.

**No third-party code is vendored.**

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | `extractall(dest)` with no path confinement |
| `fixed/` | extract only members whose resolved path stays under `dest` |
| `fixed_incomplete/` | skips members whose names contain `..`, but an absolute name still extracts |

## Running it

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_mapped_classes.py
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet. It is registered in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS`.
