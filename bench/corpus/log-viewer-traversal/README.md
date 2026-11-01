# Case: Log viewer path traversal (log name)

Log viewer path traversal case for Exhibit A. It is proven through the ``canary_read`` effect: the vulnerable app serves the canary file, reached through the entry point from the test.

## Vulnerability

`read_log` joins the requested name onto the log directory without canonicalization. A name such as `../outside/canary.txt` is served, and the served content carries the canary token.

- **Entry point:** `App.handle_request`
- **Sink:** `open` (log file read)
- **Observed effect:** `canary_read`
- **CWE:** CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## Real-world analog and originality

This models the path_traversal class. The real public advisory is **CVE-2023-31059**
(Path traversal in Repetier-Server: the file parameter reached the filesystem without canonicalization, allowing arbitrary file reads (CWE-22).). Confirmed via public records; the app is original synthetic code.

**No third-party code is vendored.** The case installs no third-party package. The trees contain no hint comments
naming the vulnerability.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | reads any joined name |
| `fixed/` | refuses names escaping the log directory |
| `fixed_incomplete/` | removes one `../`, which an absolute name still defeats |

## Held-out status

This case is marked `held_out: true`: it was written after the compact profile
and the oracle were frozen, from a public advisory, so nothing in Exhibit A was
tuned on it.

## Running it

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_expansion.py -k log-viewer-traversal
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet. It is registered in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS` as unmeasured.
