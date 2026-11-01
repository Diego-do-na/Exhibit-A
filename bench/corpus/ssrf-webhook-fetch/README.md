# Case: Webhook delivery SSRF (subscriber URL)

Webhook delivery SSRF case for Exhibit A. It is proven through the ``canary_connect`` effect: the vulnerable app itself requests the per-run canary URL served on a loopback listener, and the token comes back in the response.

## Vulnerability

`handle_request` fetches any caller-supplied subscriber URL without checking where it points. The runner serves the token on a loopback listener; the application requesting the canary URL is the proof.

- **Entry point:** `App.handle_request`
- **Sink:** `fetch` (subscriber fetch)
- **Observed effect:** `canary_connect`
- **CWE:** CWE-918 Server-Side Request Forgery

## Real-world analog and originality

This models the server_side_request_forgery class. The real public advisory is **CVE-2026-105636**
(Server-side request forgery in Plane: webhook delivery followed redirects without re-validation, reaching internal targets (CWE-918).). Confirmed via public records; the app is original synthetic code.

**No third-party code is vendored.** The case installs no third-party package. The trees contain no hint comments
naming the vulnerability.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | fetches any subscriber URL |
| `fixed/` | fetches only allow-listed subscriber hosts |
| `fixed_incomplete/` | refuses URLs naming loopback by name, which the literal address still satisfies |

## Held-out status

This case is marked `held_out: true`: it was written after the compact profile
and the oracle were frozen, from a public advisory, so nothing in Exhibit A was
tuned on it.

## Running it

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_expansion.py -k ssrf-webhook-fetch
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet. It is registered in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS` as unmeasured.
