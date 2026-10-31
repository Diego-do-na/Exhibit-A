# Case: unsafe deserialization in a job intake handler (pickle of request bytes)

Second `canary_exec` corpus case for Exhibit A. It is proven by the same loop
as the other cases (BASELINE → SUSPECT → EXPLOIT → RUN → VERDICT → FIX →
VERIFY), but through an **execution** effect: the vulnerable app unpickles
the request blob, and the proof is that decoding runs the planted canary
executable, reached through the entry point from the test.

## Vulnerability

`decode` passes the request blob to `pickle.loads`. A blob carrying a
pickled job with an attacker-controlled reduction executes it while
decoding: reducing through `os.system` runs the canary directly, and
reducing through `eval` with the launcher name assembled at run time runs it
without naming any launcher. Anything else falls back to JSON decoding.

- **Entry point:** `App.handle_request`
- **Sink:** `decode` → `pickle.loads`
- **Observed effect:** `canary_exec` — the oracle plants an executable at
  `outside/canary`; the proof is that decoding runs it (the token lands in
  `outside/canary_ran`), reached through the entry point from the test.

## Real-world analog and originality

This models the unsafe-deserialization class. The real public CVE is
**CVE-2015-7501** — remote code execution in Java applications bundling
Apache Commons-Collections, where deserializing a crafted object graph ran an
attacker transformer chain with the application's permissions. The CVE
number and summary were confirmed via web search on 2026-10-31. The same
pattern in Python is `pickle.loads` on request bytes, which the Python
documentation warns must never unpickle untrusted data.

**No third-party code is vendored.** The vulnerable, fixed and incomplete-fix
apps are original code written for this case during the hackathon build
period. The CVE is referenced only as the real-world analog of the class.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | the blob is unpickled first, JSON-decoded as a fallback |
| `fixed/` | the blob is only ever JSON-decoded; nothing is unpickled |
| `fixed_incomplete/` | blobs naming a process launcher are refused, but anything else is still unpickled |

The proper fix is a one-idea change (decode JSON only, never unpickle
request bytes), equivalent to disabling the executing classes upstream.

## Proof artifacts

- `baseline_test.py` — ordinary intakes that must work before and after the
  fix (a JSON job decodes, GET is rejected, an undecodable blob raises).
- `exploits/` — a labelled set of exploit variants (true exploits, benign,
  wrong-reason, cheating and flaky) judged by the oracle evaluation pattern.
- `exploits/exploit_true_eval.py` is also the **bypass check**: it stays
  proven against `fixed_incomplete/`, so a screen for launcher names is not
  accepted as fixed.

## Running it

The labelled exploits are judged through the Docker sandbox (Colima must be
running):

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_unsafe_deserialization.py
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet: its offline `--replay` answers come from
its own hand-authored materials (`suspicion.json`, `exploits/`, `fixed/`)
through `CaseMaterialsProvider`, not from any model. The owner records the
real Meta-model run with
`python -m bench.record_meta --profile compact --case unsafe-deserialization-pickle`
(no key was available when the case was written), then registers the id in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS` together with
those recordings so every registered case keeps a real recording behind it.
