# Case: path traversal in an Express download handler (JavaScript)

First `canary_read` corpus case for the Node oracle. It is proven by the same
loop as the Python cases (BASELINE → SUSPECT → EXPLOIT → RUN → VERDICT →
FIX → VERIFY), but through a JavaScript effect: the Express app joins a
request-controlled name onto its base directory and reads the result, reached
through the entry point from a `node:test` test.

## Vulnerability

`resolveName` joins the requested name onto the base directory with
`path.join` and reads whatever that resolves to. A name carrying dot-dot
segments (`../outside/canary.txt`) escapes the served directory and reads an
arbitrary file.

- **Entry point:** `downloadHandler`
- **Sink:** `resolveName` → `fs.readFile`
- **Observed effect:** `canary_read` — the oracle plants a canary file at
  `outside/canary.txt`; the proof is that the app reads it through the entry
  point from the test.

## Real-world analog and originality

This models the path-traversal class. The public analog is **CVE-2014-6394**
(directory traversal in Express static file serving, GHSA-xwg4-93c6-3h42):
the requested path was resolved with no check that it stayed inside the
served root. The advisory id and summary were confirmed via the Express
security-updates page in a web search on 2026-11-01.

**No third-party code is vendored.** The vulnerable, fixed and
incomplete-fix apps, the baseline test and the labelled exploits are all
original code written for this case during the hackathon build period. The
only runtime dependency is the pinned Express release in `package.json`
(`express 4.18.2`, installed with `--ignore-scripts` by the Node sandbox
image, which also provides `tsx`); the CVE is referenced only as the
real-world analog of the class.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | the name is joined and read with no containment check |
| `fixed/` | the joined path is normalized and must equal the base or sit below it |
| `fixed_incomplete/` | the raw request text is screened for `..` and the resolved path is compared as a string prefix, but the name is decoded after the screen |

The proper fix is a one-idea change (normalize, then require the result to
equal the base directory or sit below it with a separator). The incomplete
fix screens the raw request for `..` text, which a percent-encoded escape
(`%2e%2e%2f`) passes: Express decodes the query value after the screen.

## Proof artifacts

- `baseline_test.js` — ordinary downloads that must work before and after
  the fix (a present file is served, a missing one answers 404, other
  methods are not served). Run it from inside the tree under test, which puts
  that tree's `app.js` on the require path the same way `PYTHONPATH=tree`
  does for the Python cases:
  `cd vulnerable && node --test ../baseline_test.js`.
- `exploits/` — a labelled set of exploit variants (true exploits, benign,
  wrong-reason, cheating and flaky) judged by the oracle evaluation pattern.
- `exploits/exploit_true_percent_encoded_dotdot.js` is also the **bypass
  check**: it stays proven against `fixed_incomplete/`, so a screen on the
  raw request text is not accepted as fixed.

## Recordings

This case has no `recordings/` yet: judging its labelled exploits in the real
Node sandbox is a separate task (T136) that runs after the Node oracle
(T125) exists. The case id is registered in `bench/record_meta.py::CASES`
and `bench/baseline.py::TARGETS`; both commands treat its missing recordings
as unmeasured until the owner records the real Meta-model run, which flips
its rows to measured with no code change.
