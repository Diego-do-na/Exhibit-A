# Case (held out): SQL injection through a date unit and date part

Held-out `canary_sql` case: written after the compact profile and the oracle were frozen, from a
public, already-fixed advisory, so nothing in Exhibit A was tuned on it. The injection point is
not a value in a `WHERE` clause (as in the two tuned SQL cases): it is a **keyword argument that
is placed inside the quoted argument of a SQL function** of a report query. The proof is that the
app, reached through its entry point, reads a row of a table it never queries.

## Advisory

- **Advisory:** Django security releases of 2022-07-04,
  [CVE-2022-34265](https://www.djangoproject.com/weblog/2022/jul/04/security-releases/)
  ([GHSA-p64x-8rxx-wf6q](https://github.com/advisories/GHSA-p64x-8rxx-wf6q)): `Trunc()` and
  `Extract()` were subject to SQL injection if untrusted data was used as a `kind` / `lookup_name`
  value. Fixed in Django 4.0.6 and 3.2.14. Applications that constrain the value to a known safe
  list are unaffected.
- **Pattern:** a unit or date-part name chosen by the caller is concatenated into the statement.
- Confirmed via web search (Django weblog, release notes, GitHub advisory database, fix commit) on
  2026-10-31.

## Vulnerability

`reports.revenue_by_period` puts the request's `unit` inside `date(placed_at, 'start of <unit>')`,
and `reports.orders_by_part` uses a part name that is not a known one as the `strftime` format as
it is. A value that closes the quote and the call changes the statement.

- **Entry point:** `App.handle_request`
- **Chain:** `App.handle_request` → `service.revenue_report` / `service.seasonality_report` →
  `reports.revenue_by_period` / `reports.orders_by_part` → `conn.execute`
- **Sink:** `conn.execute(<concatenated text>)` in `salesreport/reports.py`
- **Observed effect:** `canary_sql` — the oracle seeds a **copy** of `data/app.db` with a table
  `exhibit_canary (token TEXT)`; the proof is that the app reads that table through the entry point
  and the token reaches the response. The original database is never touched and the test is never
  given its path.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | unit and part are concatenated into the statement |
| `fixed/` | unit and part must be one of the known names (a 400 otherwise), the same remedy as the advisory's "known safe list" |
| `fixed_incomplete/` | the value is matched against the known names with `re.match`, which only checks how it begins, so `month') ...` is accepted; values that begin with anything else are refused |

The three trees differ only in `salesreport/reports.py` (the case's `source_file`) and carry the same
`data/app.db`, built from `seed.sql`.

## Proof artifacts

- `baseline_test.py` — the three reports with ordinary parameters, which must work before and after
  the fix.
- `exploits/` — nine labelled variants: three true exploits (unit with a quote-first payload, part,
  and a unit that begins with `month`), benign, wrong-reason, three cheats and a flaky one.
- `exploits/exploit_true_prefixed_union_unit.py` is also the **bypass check**: it stays proven
  against `fixed_incomplete/`, so a check on the beginning of the value is not accepted as a fix.

## Running it

The labelled exploits are judged through the Docker sandbox (Colima must be running):

```bash
PYTHONPATH=src:. ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_heldout.py
```

The sandbox that runs untrusted tests is **isolated and resource-limited**, never "100% safe".

## Recordings

This case has no `recordings/`: it is held out, so nothing was tuned on it and no model has been
run on it yet. Its offline `--replay` answers come from its own hand-authored materials
(`suspicion.json`, `exploits/`, `fixed/`) through `CaseMaterialsProvider`, not from any model. It
is registered in `bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS`; both treat the
missing recordings as unmeasured until the owner records the real Meta-model run with
`python -m bench.record_meta --profile compact --case sql-trunc-kind-injection` plus `python -m bench.baseline
--record` (no key is available to the author), which flips its rows to measured with no code change.
