# Case: Library document IDOR (missing ownership check)

Library document IDOR case for Exhibit A. It is proven through the ``canary_access`` effect: the vulnerable app returns the seeded victim-owned resource holding the token to an attacker-authenticated request.

## Vulnerability

`handle_request` returns the stored document for any caller without checking ownership. The runner seeds a victim-owned resource holding the token; the attacker asking for it gets the token back.

- **Entry point:** `App.handle_request`
- **Sink:** `lookup` (document store read)
- **Observed effect:** `canary_access`
- **CWE:** CWE-639 Authorization Bypass Through User-Controlled Key

## Real-world analog and originality

This models the broken_access_control class. The real public advisory is **CVE-2023-43900**
(Insecure direct object reference in EMSigner: manipulating the documentID parameter exposed other users' documents (CWE-639).). Confirmed via public records; the app is original synthetic code.

**No third-party code is vendored.** The case installs no third-party package. The trees contain no hint comments
naming the vulnerability.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | returns any document to any caller |
| `fixed/` | returns a document only to its owner |
| `fixed_incomplete/` | requires a signed-in caller but never checks ownership |

## Held-out status

This case is marked `held_out: true`: it was written after the compact profile
and the oracle were frozen, from a public advisory, so nothing in Exhibit A was
tuned on it.

## Running it

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_expansion.py -k idor-document-fetch
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet. It is registered in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS` as unmeasured.
