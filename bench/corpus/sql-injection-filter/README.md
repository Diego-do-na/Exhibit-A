# Case: Product search SQL injection (filter string)

Product search SQL injection case for Exhibit A. It is proven through the ``canary_sql`` effect: the vulnerable app reads a table it never queries in the seeded database copy, reached through the entry point from the test.

## Vulnerability

`search_products` formats the filter into the lookup statement. A filter such as `' UNION SELECT token, 'x' FROM exhibit_canary -- ` returns rows carrying the canary token. The database is seeded with the canary table on a copy; the original is never touched.

- **Entry point:** `App.handle_request`
- **Sink:** `conn.execute` (product lookup)
- **Observed effect:** `canary_sql`
- **CWE:** CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

## Real-world analog and originality

This models the sql_injection class. The real public advisory is **CVE-2024-1071**
(SQL injection in a WordPress email plugin: a filter parameter reached the statement by string building, enabling UNION extraction (CWE-89).). Confirmed via public records; the app is original synthetic code.

**No third-party code is vendored.** The case installs no third-party package. The trees contain no hint comments
naming the vulnerability.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | formats the filter into the statement |
| `fixed/` | binds the filter as a parameter |
| `fixed_incomplete/` | removes spaces, which tabs still avoid |

## Held-out status

This case is marked `held_out: true`: it was written after the compact profile
and the oracle were frozen, from a public advisory, so nothing in Exhibit A was
tuned on it.

## Running it

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_expansion.py -k sql-injection-filter
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet. It is registered in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS` as unmeasured.
