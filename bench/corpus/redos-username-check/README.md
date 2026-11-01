# Case: Directory lookup ReDoS (nested quantifiers)

Directory lookup ReDoS case for Exhibit A. It is proven through the ``canary_dos`` effect: the runner itself times the entry point on two same-length inputs and observes the application CPU gap.

## Vulnerability

`handle_request` matches the query with a nested-quantifier pattern. A crafted input of the same length as a benign one burns far more application CPU, which the runner times itself.

- **Entry point:** `App.handle_request`
- **Sink:** `PATTERN.search` (user-name match)
- **Observed effect:** `canary_dos`
- **CWE:** CWE-1333 Inefficient Regular Expression Complexity

## Real-world analog and originality

This models the regex_denial_of_service class. The real public advisory is **CVE-2021-46823**
(Regular expression denial of service in python-ldap: an ambiguous pattern caused exponential backtracking on crafted input (CWE-1333).). Confirmed via public records; the app is original synthetic code.

**No third-party code is vendored.** The case installs no third-party package. The trees contain no hint comments
naming the vulnerability.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | matches with a nested-quantifier pattern |
| `fixed/` | matches with a linear character-class pattern |
| `fixed_incomplete/` | rejects one failing character, which another one survives |

## Held-out status

This case is marked `held_out: true`: it was written after the compact profile
and the oracle were frozen, from a public advisory, so nothing in Exhibit A was
tuned on it.

## Running it

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_expansion.py -k redos-username-check
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet. It is registered in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS` as unmeasured.
