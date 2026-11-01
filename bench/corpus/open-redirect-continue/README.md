# Case: Continue-page open redirect (meta refresh)

Continue-page open redirect case for Exhibit A. It is proven through the ``canary_redirect`` effect: the vulnerable app answers with a redirect to the per-run canary host, which the runner observes through the declared entry point.

## Vulnerability

`handle_request` answers with an HTML meta refresh to the caller-supplied target without checking its host. This case declares `redirect_meta`, so a meta refresh to the canary host counts as proof.

- **Entry point:** `App.handle_request`
- **Sink:** `answer_with_target` (meta-refresh page)
- **Observed effect:** `canary_redirect`
- **CWE:** CWE-601 URL Redirection to Untrusted Site ('Open Redirect')

## Real-world analog and originality

This models the open_redirect class. The real public advisory is **CVE-2024-43794**
(Open redirect in OpenSearch Dashboards: the `nextUrl` parameter on login led to external redirects (CWE-601).). Confirmed via public records; the app is original synthetic code.

**No third-party code is vendored.** The case installs no third-party package. The trees contain no hint comments
naming the vulnerability.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | refreshes to any caller-supplied target |
| `fixed/` | answers a plain page, never a caller refresh |
| `fixed_incomplete/` | scrubs one `http` marker, which a doubled marker survives |

## Held-out status

This case is marked `held_out: true`: it was written after the compact profile
and the oracle were frozen, from a public advisory, so nothing in Exhibit A was
tuned on it.

## Running it

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_expansion.py -k open-redirect-continue
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet. It is registered in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS` as unmeasured.
