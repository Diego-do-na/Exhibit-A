# Case: Order notification SSTI (subject template)

Order notification SSTI case for Exhibit A. It is proven through the ``canary_exec`` effect: the vulnerable app itself runs the planted canary executable, reached through the entry point from the test.

## Vulnerability

`render_subject` compiles the request subject with a default Jinja2 environment and renders it. A subject that reaches operating system calls through template internals runs the canary during render.

- **Entry point:** `App.handle_request`
- **Sink:** `Environment().from_string` (non-constant subject)
- **Observed effect:** `canary_exec`
- **CWE:** CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine

## Real-world analog and originality

This models the server_side_template_injection class. The real public advisory is **CVE-2023-22621**
(Server-side template injection in Strapi: email templates rendered with a template engine executed attacker input (CWE-1336).). Confirmed via public records; the app is original synthetic code.

**No third-party code is vendored.** `Jinja2` is a pip requirement of the case, not copied into the tree. The trees contain no hint comments
naming the vulnerability.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | renders the subject with a default environment |
| `fixed/` | renders the subject with a sandboxed environment |
| `fixed_incomplete/` | refuses subjects holding a token block-list, which an index lookup of the module still avoids |

## Held-out status

This case is marked `held_out: true`: it was written after the compact profile
and the oracle were frozen, from a public advisory, so nothing in Exhibit A was
tuned on it.

## Running it

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_expansion.py -k ssti-email-template
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet. It is registered in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS` as unmeasured.
