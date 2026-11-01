# Case: path traversal in an Express download handler (TypeScript)

TypeScript twin of `express-download-traversal` and the second
`canary_read` corpus case for the Node oracle. The logic is identical to
the JavaScript twin; only type annotations are added. The trees keep the
CommonJS module shape (`require` / `module.exports`) so they run under
the sandbox image's `tsx` exactly like their JavaScript twins, with no
extra type-checking dependency.

Held out: written after the Node oracle design was frozen, so nothing in
Exhibit A was tuned on it.

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
(directory traversal in Express static file serving, GHSA-xwg4-93c6-3h42),
confirmed via the Express security-updates page in a web search on
2026-11-01.

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

## Proof artifacts

- `baseline_test.ts` — ordinary downloads that must work before and after
  the fix. Run it from inside the tree under test with the image's `tsx`:
  `cd vulnerable && tsx --test ../baseline_test.ts`.
- `exploits/` — a labelled set of exploit variants (true exploits, benign,
  wrong-reason, cheating and flaky) judged by the oracle evaluation pattern.
- `exploits/exploit_true_percent_encoded_dotdot.ts` is also the **bypass
  check**: it stays proven against `fixed_incomplete/`, so a screen on the
  raw request text is not accepted as fixed.

## Recordings

This case has no `recordings/` yet: judging its labelled exploits in the real
Node sandbox is a separate task (T136) that runs after the Node oracle
(T125) exists. The case id is registered in `bench/record_meta.py::CASES`
and `bench/baseline.py::TARGETS`; both commands treat its missing recordings
as unmeasured until the owner records the real Meta-model run, which flips
its rows to measured with no code change.
