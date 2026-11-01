# Case: unsafe YAML load in a job intake handler

Unsafe YAML deserialization case for Exhibit A. It is proven through the
existing ``canary_exec`` effect: the vulnerable app loads request YAML with
``yaml.unsafe_load``, and the proof is that the app itself runs the planted
canary executable, reached through the entry point from the test.

## Vulnerability

`load_job` passes the request document to `yaml.unsafe_load`. A document
tagged `!!python/object/apply:os.system` runs the canary while the job is
loaded.

- **Entry point:** `App.handle_request`
- **Sink:** `yaml.unsafe_load` (non-constant document; no SafeLoader)
- **Observed effect:** `canary_exec`
- **CWE:** CWE-502 Deserialization of Untrusted Data

## Real-world analog and originality

This models unsafe YAML load. The real public CVE is **CVE-2017-18342**
(PyYAML, arbitrary code execution through `yaml.load` of untrusted input)
and **CVE-2020-1747**. Confirmed via public records; the app is original
synthetic code.

**No third-party code is vendored.** PyYAML is a pip requirement of the
case, not copied into the tree.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | `yaml.unsafe_load(document)` |
| `fixed/` | `yaml.safe_load(document)` |
| `fixed_incomplete/` | refuses documents holding `!!python/object/apply:os.system` or `subprocess`, but an `eval` tag still loads |

## Running it

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_mapped_classes.py
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet. It is registered in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS`.
