# Case: SQL injection in a catalog search (multi-module app)

Second `canary_sql` corpus case, built so the graph slice has something real to
cut. The app is ten modules, and the statement that is injectable is assembled
two calls below the route handler. It is proven by the same loop as the other
cases (BASELINE → SUSPECT → EXPLOIT → RUN → VERDICT → FIX → VERIFY) through the
SQL effect: the app, reached through its entry point, **reads a row of a table
it never queries**.

## Layout

| Module | Role |
|---|---|
| `app.py` | `App.handle_request`, the entry point; turns `ApiError` into a response |
| `shop/routes.py` | route table and handlers (`search_products`, `show_product`, `show_categories`) |
| `shop/services.py` | use cases (`search_catalog`, `get_product`, `list_categories`) |
| `shop/repository.py` | `ProductRepository`: the only module that builds SQL |
| `shop/models.py` | `Product`, `SearchCriteria` |
| `shop/serializers.py` | models to response bodies |
| `shop/utils.py` | request-parameter helpers (`as_list`, `first`, `parse_int`, ...) |
| `shop/db.py` | one connection per unit of work |
| `shop/config.py` | paths and limits |
| `shop/errors.py` | `ApiError` |

The call chain for a search is `App.handle_request` → `routes.dispatch` →
`routes.search_products` → `services.search_catalog` →
`ProductRepository.find` → `conn.execute`.

## Vulnerability

`ProductRepository.find` builds one statement by string concatenation from the
parsed request: the search term goes inside a quoted `LIKE` pattern, the
category list is joined into a quoted `IN` list, and the sort text is placed in
the `ORDER BY` clause. Each of the three can change the statement.

- **Entry point:** `App.handle_request`
- **Sink:** `ProductRepository.find` → `conn.execute(<concatenated text>)`
- **Observed effect:** `canary_sql` — the oracle seeds a **copy** of
  `data/app.db` with a table `exhibit_canary (token TEXT)` holding one row; the
  proof is that the app reads that table through the entry point, and the
  failing assertion shows the token (or a decision based on it) reached the
  response. The original database is never touched and the test is never given
  its path.

## Real-world analog and originality

The real public CVE is **CVE-2017-8917** — SQL injection in the `com_fields`
component of Joomla 3.7.0, where the `list[fullordering]` request parameter
reached a list query's `ORDER BY` unsanitized, without authentication. The
`IN`-list exploit models the family of **CVE-2014-3704** (Drupal 7
`expandArguments`, an `IN` list assembled from caller-controlled array keys).
Both were confirmed via web search (Joomla security centre, NVD, Drupal
SA-CORE-2014-005) on 2026-10-31.

**No third-party code is vendored.** The apps, seed data, baseline test and
exploits are original code written for this case during the hackathon build
period. The CVEs are referenced only as analogs of the class.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | term, category list and sort are concatenated into the statement |
| `fixed/` | sort goes through an allow-list of columns (400 for anything else); term and categories travel as bound parameters, with `LIKE` wildcards escaped |
| `fixed_incomplete/` | term and categories are bound parameters, but the sort text is only checked to be made of identifier-like characters (letters, digits, `_`, parentheses, commas, spaces and a few operators), so a quote-free subquery still gets into the `ORDER BY` |

The three trees differ only in `shop/repository.py` (that is the case's
`source_file`) and carry the same `data/app.db`, built from `seed.sql` (a test
checks they are identical to it).

## Proof artifacts

- `baseline_test.py` — ordinary listing, search, filtering, sorting and
  lookups that must work before and after the fix.
- `exploits/` — a labelled set of exploit variants (true exploits through the
  `LIKE` term, the `IN` list and the `ORDER BY`; benign, wrong-reason,
  cheating and flaky) judged through the Docker sandbox.
- `exploits/exploit_true_order_by_quote_free.py` is also the **bypass check**:
  it stays proven against `fixed_incomplete/`, so a character screen is not
  accepted as a fix, while the quoted `ORDER BY` exploit and both `UNION`
  exploits are stopped there.

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

This case has no `recordings/` yet. The case id is registered in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS`; both commands
treat its missing recordings as unmeasured until the owner records the real
Meta-model run with
`python -m bench.record_meta --profile compact --case sql-injection-search`
plus `python -m bench.baseline --record` (no key was available when the case
was written).
