# Case: Catalog expansion quadratic blowup (expand counter)

Catalog expansion quadratic blowup case for Exhibit A. It is proven through the ``canary_dos`` effect: the runner itself times the entry point on two same-length inputs and observes the application CPU gap.

## Vulnerability

`handle_request` expands the expression with a counter that rescans the whole tail for every character. A crafted expression of the same length as a benign one burns far more application CPU, which the runner times itself.

- **Entry point:** `App.handle_request`
- **Sink:** `matches` (expression expansion)
- **Observed effect:** `canary_dos`
- **CWE:** CWE-407 Inefficient Algorithmic Complexity

## Real-world analog and originality

This models the algorithmic_complexity class. The real public advisory is **CVE-2026-66046**
(Quadratic algorithmic complexity in Expat: processing N attributes triggered an O(N²) scan (CWE-407).). Confirmed via public records; the app is original synthetic code.

**No third-party code is vendored.** The case installs no third-party package. The trees contain no hint comments
naming the vulnerability.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | expands with a per-character rescan |
| `fixed/` | answers the length without expanding |
| `fixed_incomplete/` | strips one prefix, which a doubled prefix still defeats |

## Held-out status

This case is marked `held_out: true`: it was written after the compact profile
and the oracle were frozen, from a public advisory, so nothing in Exhibit A was
tuned on it.

## Running it

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_expansion.py -k redos-search-query
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet. It is registered in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS` as unmeasured.
