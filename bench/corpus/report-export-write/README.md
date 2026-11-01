# Case: Analysis export path traversal (report name)

Analysis export path traversal case for Exhibit A. It is proven through the ``canary_write`` effect: the vulnerable app itself creates the canary file outside the allowed directory.

## Vulnerability

`store_report` joins the requested name onto the export directory without confinement. A name such as the absolute canary path stores the token outside the directory; the proof is that the app itself creates it.

- **Entry point:** `App.handle_request`
- **Sink:** `open` for writing (report store)
- **Observed effect:** `canary_write`
- **CWE:** CWE-73 External Control of File Name or Path

## Real-world analog and originality

This models the path_traversal_write class. The real public advisory is **CVE-2022-29464**
(Arbitrary file upload in WSO2 API Manager: the filename parameter traversed directories during upload, writing outside the target directory (CWE-73).). Confirmed via public records; the app is original synthetic code.

**No third-party code is vendored.** The case installs no third-party package. The trees contain no hint comments
naming the vulnerability.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | stores any joined name |
| `fixed/` | stores only the base name inside the export directory |
| `fixed_incomplete/` | strips leading slashes, which a relative climb still defeats |

## Held-out status

This case is marked `held_out: true`: it was written after the compact profile
and the oracle were frozen, from a public advisory, so nothing in Exhibit A was
tuned on it.

## Running it

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_expansion.py -k report-export-write
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet. It is registered in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS` as unmeasured.
