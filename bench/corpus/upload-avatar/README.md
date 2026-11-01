# Case: path traversal in an avatar upload (file name from the request)

Unrestricted-upload / path-traversal-write case for Exhibit A. It is proven
through the existing ``canary_write`` effect: the vulnerable app stores the
upload under the request file name, and the proof is that a name landing on
the canary is written outside the avatar directory.

## Vulnerability

`store_avatar` joins the request name onto the destination and opens it for
writing. A name such as `../outside/canary.txt` (or an absolute path) is
written outside the destination.

- **Entry point:** `App.handle_request`
- **Sink:** `open(..., "wb")` (write mode; catalog also names `FileStorage.save`)
- **Observed effect:** `canary_write`
- **CWE:** CWE-434 Unrestricted Upload of File with Dangerous Type

## Real-world analog and originality

This models unsafe upload names. The real public CVE is **CVE-2021-31542**
(Django, `MultiPartParser` filename traversal) / **CVE-2018-14574** style
upload path control. Confirmed via public records; the app is original
synthetic code, not Django.

**No third-party code is vendored.**

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | `open(join(root, name), "wb")` |
| `fixed/` | store under `basename(name)` confined with `realpath` |
| `fixed_incomplete/` | refuses names holding `..`, but an absolute name still stores |

## Running it

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_mapped_classes.py
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet. It is registered in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS`.
