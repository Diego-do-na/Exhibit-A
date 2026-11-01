# Case: command injection in an Express lookup handler (TypeScript)

TypeScript twin of `express-command-injection` and the second
`canary_exec` corpus case for the Node oracle. The logic is identical to
the JavaScript twin; only type annotations are added. The trees keep the
CommonJS module shape (`require` / `module.exports`) so they run under
the sandbox image's `tsx` exactly like their JavaScript twins, with no
extra type-checking dependency.

Held out: written after the Node oracle design was frozen, so nothing in
Exhibit A was tuned on it.

## Vulnerability

`runLookup` assembles a shell command line from the requested name and runs
it with `exec`. A name carrying a shell metacharacter breaks out of the file
operand: `x; /tmp/.../outside/canary` runs the canary as a second command,
and so does a name carrying a newline.

- **Entry point:** `lookupHandler`
- **Sink:** `runLookup` → `child_process.exec`
- **Observed effect:** `canary_exec` — the oracle plants an executable at
  `outside/canary`; the proof is that the app runs it (the token lands in
  `outside/canary_ran`), reached through the entry point from the test.

## Real-world analog and originality

This models the command-injection class. The public analog is
**CVE-2021-22205** — remote code execution in GitLab CE/EE via ExifTool,
confirmed via web search when the sibling Python case was written.

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
| `vulnerable/` | the name is assembled into a shell command line (`exec`) |
| `fixed/` | the name reaches `ls` as an argument vector element, with no shell (`execFile`) |
| `fixed_incomplete/` | names holding `;`, `\|`, `&`, backtick, `$`, `(` or `)` are refused, but a newline still reaches the shell |

## Proof artifacts

- `baseline_test.ts` — ordinary lookups that must work before and after the
  fix. Run it from inside the tree under test with the image's `tsx`:
  `cd vulnerable && tsx --test ../baseline_test.ts`.
- `exploits/` — a labelled set of exploit variants (true exploits, benign,
  wrong-reason, cheating and flaky) judged by the oracle evaluation pattern.
  The `node:test` files never invoke `child_process` themselves and never
  name the canary environment entry, per the Node oracle's static guard.
- `exploits/exploit_true_newline.ts` is also the **bypass check**: it stays
  proven against `fixed_incomplete/`, so a blacklist that misses the newline
  is not accepted as fixed.

## Recordings

This case has no `recordings/` yet: judging its labelled exploits in the real
Node sandbox is a separate task (T136) that runs after the Node oracle
(T125) exists. The case id is registered in `bench/record_meta.py::CASES`
and `bench/baseline.py::TARGETS`; both commands treat its missing recordings
as unmeasured until the owner records the real Meta-model run, which flips
its rows to measured with no code change.
