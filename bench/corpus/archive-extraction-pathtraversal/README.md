# Case: archive-extraction path traversal (zip-slip)

Second vulnerability class for Exhibit A, chosen in `docs/second-class.md`. It is proven by the
same loop as the Starlette case (BASELINE → SUSPECT → EXPLOIT → RUN → VERDICT → FIX → VERIFY),
but through a **write** effect instead of a read: the vulnerable app creates a file *outside*
its destination directory when it extracts a crafted archive.

## Vulnerability

`Extractor._target` joins an archive member's name onto the destination directory without
confining it. A member named `../outside/x` or an absolute path therefore escapes the
destination, and `extract_member` writes outside it (archive-extraction path traversal, also
called zip-slip).

- **Entry point:** `App.handle_request`
- **Sink:** `Extractor.extract_member` → `open(target, "w")`
- **Observed effect:** `canary_write` — the oracle plants no canary file; the proof is that the
  app itself opens the canary path (outside the allowed directory) for writing, reached through
  the entry point from the test.

## Real-world analog and originality

This models the well-known archive-extraction traversal class. The real public CVE is
**CVE-2007-4559** — directory traversal in Python's `tarfile` `extract`/`extractall`, fixed by
the extraction filter added in Python 3.11.4 (PEP 706, `filter="data"`). The CVE number and fix
were confirmed via web search on 2026-10-29.

**No third-party code is vendored.** The vulnerable, fixed and incomplete-fix apps and the tiny
length-prefixed archive format are original code written for this case during the hackathon
build period. The CVE is referenced only as the real-world analog of the class.

## Trees

| Tree | `_target` behaviour |
|---|---|
| `vulnerable/` | joins the member name onto the destination unchecked — escapes |
| `fixed/` | confines the resolved target to the destination (rejects `..` and absolute paths) |
| `fixed_incomplete/` | screens for `".."` only — an absolute member path still escapes |

The proper fix is a one-idea change in `_target` (resolve the target and require it to stay
under the destination), equivalent to the upstream `filter="data"`.

## Proof artifacts

- `baseline_test.py` — ordinary in-bounds extraction that must pass before and after the fix.
- `exploits/` — a labelled set of exploit variants (true exploits, benign, wrong-reason,
  cheating and flaky) used by the oracle evaluation set.
- `exploits/exploit_true_absolute.py` is also the **bypass check**: it stays proven against
  `fixed_incomplete/`, so a plausible incomplete fix is not accepted as fixed.

## Running it (no Docker needed)

The oracle runs the exploits as isolated host child processes (not the Docker sandbox), so this
case runs offline. It is exercised by:

```bash
PYTHONPATH=src python -m pytest tests/test_case_archive_extraction.py tests/test_oracle_eval_archive.py
```

The sandbox that runs untrusted tests is **isolated and resource-limited**, never "100% safe".
