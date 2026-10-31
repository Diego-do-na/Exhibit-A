# Case: command injection in a listing handler (shell command from request input)

First `canary_exec` corpus case for Exhibit A. It is proven by the same loop
as the other cases (BASELINE → SUSPECT → EXPLOIT → RUN → VERDICT → FIX →
VERIFY), but through an **execution** effect instead of a read or a write:
the vulnerable app starts a shell for a command line built from the request,
and the proof is that the app itself runs the planted canary executable,
reached through the entry point from the test.

## Vulnerability

`list_dir` assembles a shell command line from the requested name and runs it
with `shell=True`. A name carrying a shell metacharacter breaks out of the
file operand: `x; /tmp/.../outside/canary` runs the canary as a second
command, and so does a name carrying a newline (the shell treats it as a
command separator too).

- **Entry point:** `App.handle_request`
- **Sink:** `list_dir` → `subprocess.run(..., shell=True)`
- **Observed effect:** `canary_exec` — the oracle plants an executable at
  `outside/canary`; the proof is that the app runs it (the token lands in
  `outside/canary_ran`), reached through the entry point from the test.

## Real-world analog and originality

This models the command-injection class. The real public CVE is
**CVE-2021-22205** — remote code execution in GitLab CE/EE, where an
unauthenticated image upload reached ExifTool and its DjVu handler evaluated
attacker metadata into commands (root cause CVE-2021-22204). The CVE number
and summary were confirmed via web search on 2026-10-31.

**No third-party code is vendored.** The vulnerable, fixed and incomplete-fix
apps are original code written for this case during the hackathon build
period. The CVE is referenced only as the real-world analog of the class.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | the name is assembled into a shell command line (`shell=True`) |
| `fixed/` | the name reaches `ls` as an argument vector element, with no shell |
| `fixed_incomplete/` | names holding `;`, `|`, `&`, backtick, `$`, `(` or `)` are refused, but a newline still reaches the shell |

The proper fix is a one-idea change (pass an argument vector without a
shell), equivalent to the upstream response of removing the executable
content from the data path.

## Proof artifacts

- `baseline_test.py` — ordinary listings that must work before and after the
  fix (a present file is listed, a missing one lists nothing, GET is
  rejected).
- `exploits/` — a labelled set of exploit variants (true exploits, benign,
  wrong-reason, cheating and flaky) judged by the oracle evaluation pattern.
- `exploits/exploit_true_newline.py` is also the **bypass check**: it stays
  proven against `fixed_incomplete/`, so a blacklist that misses the newline
  is not accepted as fixed.

## Running it

The labelled exploits are judged through the Docker sandbox (Colima must be
running):

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_command_injection.py
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet: its offline `--replay` answers come from
its own hand-authored materials (`suspicion.json`, `exploits/`, `fixed/`)
through `CaseMaterialsProvider`, not from any model. The case id is already
registered in `bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS`;
both commands treat its missing recordings as unmeasured until the owner
records the real Meta-model run with
`python -m bench.record_meta --profile compact --case command-injection-shell`
plus `python -m bench.baseline --record` (no key was available when the case
was written), which flips its rows to measured with no code change.
