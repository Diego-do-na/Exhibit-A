# Case: command injection in an Express lookup handler (JavaScript)

First `canary_exec` corpus case for the Node oracle. It is proven by the
same loop as the Python cases (BASELINE → SUSPECT → EXPLOIT → RUN → VERDICT
→ FIX → VERIFY), but through a JavaScript execution effect: the Express app
starts a shell for a command line built from the request, and the proof is
that the app itself runs the planted canary executable, reached through the
entry point from a `node:test` test.

## Vulnerability

`runLookup` assembles a shell command line from the requested name and runs
it with `exec`. A name carrying a shell metacharacter breaks out of the file
operand: `x; /tmp/.../outside/canary` runs the canary as a second command,
and so does a name carrying a newline (the shell treats it as a command
separator too).

- **Entry point:** `lookupHandler`
- **Sink:** `runLookup` → `child_process.exec`
- **Observed effect:** `canary_exec` — the oracle plants an executable at
  `outside/canary`; the proof is that the app runs it (the token lands in
  `outside/canary_ran`), reached through the entry point from the test.

## Real-world analog and originality

This models the command-injection class. The public analog is
**CVE-2021-22205** — remote code execution in GitLab CE/EE, where an
unauthenticated image upload reached ExifTool and its DjVu handler evaluated
attacker metadata into commands. The CVE number and summary were confirmed
via web search when the sibling Python case was written.

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

The proper fix is a one-idea change (pass an argument vector with no shell),
equivalent to never letting request input reach a shell. The blacklist in
the incomplete fix misses the newline separator.

## Proof artifacts

- `baseline_test.js` — ordinary lookups that must work before and after the
  fix (a present file is listed, a missing one lists nothing, a missing name
  field is rejected). Run it from inside the tree under test, which puts
  that tree's `app.js` on the require path the same way `PYTHONPATH=tree`
  does for the Python cases:
  `cd vulnerable && node --test ../baseline_test.js`.
- `exploits/` — a labelled set of exploit variants (true exploits, benign,
  wrong-reason, cheating and flaky) judged by the oracle evaluation pattern.
  The `node:test` files never invoke `child_process` themselves and never
  name the canary environment entry, per the Node oracle's static guard.
- `exploits/exploit_true_newline.js` is also the **bypass check**: it stays
  proven against `fixed_incomplete/`, so a blacklist that misses the newline
  is not accepted as fixed.

## Recordings

This case has no `recordings/` yet: judging its labelled exploits in the real
Node sandbox is a separate task (T136) that runs after the Node oracle
(T125) exists. The case id is registered in `bench/record_meta.py::CASES`
and `bench/baseline.py::TARGETS`; both commands treat its missing recordings
as unmeasured until the owner records the real Meta-model run, which flips
its rows to measured with no code change.
