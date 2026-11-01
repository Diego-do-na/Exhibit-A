# Case: SSTI in a greeting preview (Jinja2 template from request input)

Server-side template injection case for Exhibit A. It is proven through the
existing ``canary_exec`` effect: the vulnerable app compiles request text as
a Jinja2 template, and the proof is that the app itself runs the planted
canary executable, reached through the entry point from the test.

## Vulnerability

`render_preview` passes the request source to `jinja2.Template(...).render`.
A source such as `{{ lipsum.__globals__['os'].system(...) }}` runs the
canary while the template is rendered.

- **Entry point:** `App.handle_request`
- **Sink:** `jinja2.Template` (non-constant source)
- **Observed effect:** `canary_exec`
- **CWE:** CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine

## Real-world analog and originality

This models the SSTI class. The real public CVE is **CVE-2019-8341**
(Jinja2 / Flask, SSTI through attacker-controlled template strings) and
the class analog **CVE-2016-0752** (Rails render params). Confirmed via
public records; the app is original synthetic code.

**No third-party code is vendored.** Jinja2 is a pip requirement of the
case, not copied into the tree.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | `Template(source).render(**values)` |
| `fixed/` | `SandboxedEnvironment().from_string(source)` |
| `fixed_incomplete/` | refuses sources holding `__class__` / `os.system` / `popen` / `subprocess` / `eval` / `exec`, but an index lookup of `os` still renders |

## Running it

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_mapped_classes.py
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet. It is registered in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS`.
