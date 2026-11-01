# Case: Connectivity check command injection (`ping` host)

Connectivity check command injection case for Exhibit A. It is proven through the ``canary_exec`` effect: the vulnerable app itself runs the planted canary executable, reached through the entry point from the test.

## Vulnerability

`ping` builds a shell command line from the requested host and runs it with `shell=True`. A host such as `x; <canary>` runs the canary while the shell parses the line.

- **Entry point:** `App.handle_request`
- **Sink:** `subprocess.run` with `shell=True` (host operand)
- **Observed effect:** `canary_exec`
- **CWE:** CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

## Real-world analog and originality

This models the command_injection class. The real public advisory is **CVE-2025-14092**
(OS command injection in an Edimax router diagnostic page: the host parameter reached a shell command by string building (CWE-78).). Confirmed via public records; the app is original synthetic code.

**No third-party code is vendored.** The case installs no third-party package. The trees contain no hint comments
naming the vulnerability.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | builds a shell line from the host and runs it |
| `fixed/` | passes the host as an argument without a shell, after a shape check |
| `fixed_incomplete/` | rejects `;`, `&` and `|`, which a newline still avoids |

## Held-out status

This case is marked `held_out: true`: it was written after the compact profile
and the oracle were frozen, from a public advisory, so nothing in Exhibit A was
tuned on it.

## Running it

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_expansion.py -k command-injection-ping
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet. It is registered in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS` as unmeasured.
