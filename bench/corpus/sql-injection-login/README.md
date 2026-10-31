# Case: SQL injection in an account login and lookup

First `canary_sql` corpus case for Exhibit A. It is proven by the same loop as
the other cases (BASELINE → SUSPECT → EXPLOIT → RUN → VERDICT → FIX → VERIFY),
through the SQL effect: the proof is that the app, reached through its entry
point, **reads a row of a table it never queries**.

## Vulnerability

`app.py` answers `POST /login` and `GET /users/<id>`. Both handlers build their
statement by string formatting. The login statement places the username inside
quotes, so a username holding a quote closes the string and can append a
`UNION` that returns rows of any table, or turn the password check into a
condition on another table. The lookup statement places the id in the
statement bare, so no quote is needed at all.

- **Entry point:** `App.handle_request`
- **Sinks:** `find_by_login` and `find_by_id` → `conn.execute(<formatted text>)`
- **Observed effect:** `canary_sql` — the oracle seeds a **copy** of
  `data/app.db` with a table `exhibit_canary (token TEXT)` holding one row; the
  proof is that the app reads that table through the entry point, and the
  failing assertion shows the token (or a decision based on it) reached the
  response. The original database is never touched and the test is never given
  its path.

## Real-world analog and originality

This models the login-statement class. The real public CVE is **CVE-2004-1737**
— SQL injection in `auth_login.php` of Cacti 0.8.5a, where the username and
password parameters reached the login statement (arbitrary SQL, authentication
bypass). The CVE number and summary were confirmed via web search (NVD) on
2026-10-31.

**No third-party code is vendored.** The three apps, the seed data, the
baseline test and the exploits are original code written for this case during
the hackathon build period. The CVE is referenced only as the analog of the
class.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | both statements are built by string formatting |
| `fixed/` | both statements use bound parameters; the id is converted with `int()` (400 on failure) |
| `fixed_incomplete/` | request values are passed through a helper that doubles single quotes; the quoted login statement is safe, but the id is placed without quotes, so a quote-free `UNION` still works |

Every tree carries the same `data/app.db`, built from `seed.sql` (a test
checks they are identical to it). The proper fix is a one-idea change: values
travel as parameters, never as statement text.

## Proof artifacts

- `baseline_test.py` — ordinary logins and lookups that must work before and
  after the fix.
- `exploits/` — a labelled set of exploit variants (true exploits, benign,
  wrong-reason, cheating and flaky) judged through the Docker sandbox.
- `exploits/exploit_true_numeric_lookup.py` is also the **bypass check**: it
  stays proven against `fixed_incomplete/`, so a quote-escaping "fix" is not
  accepted as fixed.

### Not covered: second-order injection

A second-order variant (a value stored by one request, used unescaped by a
later one) needs the app to write to its database. The sandbox mounts the
seeded copy read-only, so such a case cannot be proven with this effect; the
bypass here is the numeric context instead.

## Running it

The labelled exploits are judged through the Docker sandbox (Colima must be
running):

```bash
PYTHONPATH=src:. ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_sql_injection.py
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe". A result where nothing is proven means "nothing could be
proven", never "safe".

## Recordings

This case has no `recordings/` yet. The benchmark pipeline answers it from its
own hand-authored materials (`suspicion.json`, `exploits/`, `fixed/`) through
`CaseMaterialsProvider`, not from any model; `tests/test_case_sql_injection.py`
runs that whole loop in the sandbox and verifies the fix. (`exhibit-a run
--case ... --replay` does not pass `run.sql_db` to its sandbox runner yet, so
it fails closed for `canary_sql` cases.) The case id is registered
in `bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS`; both
commands treat its missing recordings as unmeasured until the owner records the
real Meta-model run with
`python -m bench.record_meta --profile compact --case sql-injection-login`
plus `python -m bench.baseline --record` (no key was available when the case
was written).
