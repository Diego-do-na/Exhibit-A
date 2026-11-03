# Closure tasks T145-T152 (planning by Claude, verified against the code on Mon 2026-11-02 23:55)

Deadline: product freeze Tue 2026-11-03 ~18:00 CDMX. Submission Wed 2026-11-04 20:00 CDMX (send by 16:00).
Gate: a branch merges to main ONLY with the full suite green (Docker on). Red work is documented as roadmap, never merged half-done. No Claude-Session lines in commits. Diego commits and merges himself. No push by agents.

## Verified state (do NOT rebuild)
- Sandbox: AGENTS.md "Current state" is correct: baseline, exploit, fixed-code and bypass runs go through `SandboxRunner` in every CLI/bench mode; `HostRunner`/`run_oracle` exist only behind `allow_host_execution=True`, never set by the CLI (src/exhibit_a/loop/runner.py). T026/T027 are DONE.
- SCAN exists: src/exhibit_a/scan/ (rule-based `detect`), `exhibit-a scan REPO` with `--graph` and `--pr-diff` (src/exhibit_a/cli/scan.py). Only `exhibit-a scan` with NO repo prints a RepoProfile placeholder.
- SLICE exists: src/exhibit_a/graph/slicer.py, wired in loop/pipeline.py via `run --slice`; on by default with `--profile compact`, off with `standard`. Tests: tests/test_graph_slice.py.
- The older AGENTS.md text quoted in some agent prompts (oracle/baseline on host, SCAN/SLICE not built) is STALE. Read the file in the repo, not a cached copy.

## Parallel worktrees (one agent per tree)
```
cd ~/Desktop/Proyects/Exhibit-A
git worktree add ../Exhibit-A-verify -b chore/verify-and-polish-cli main
git worktree add ../Exhibit-A-chain  -b test/chain-validation     main
git worktree add ../Exhibit-A-docs   -b docs/readme-final         main
```
Merge order: T145 -> T146/T147/T148/T149 -> T150 -> T151 -> T152.

## T145 - Verify claims end to end (needs Docker; Diego runs the docker commands)
Prove with evidence, not assumptions: (1) one real `exhibit-a run` on a benchmark case with `--profile compact --slice` shows in the ledger that baseline/exploit/fix/bypass ran in the sandbox and no host execution; (2) `grep` proves no production path sets `allow_host_execution=True`; (3) full suite with Docker, 3 consecutive runs of tests/test_meta_replay.py with no skip/xfail; (4) every README/SPEC/AGENTS claim about SCAN, SLICE, sandbox coverage, CLI subcommands is TRUE or reworded. Output docs/plan/verification.md (claim, evidence command, result).

## T146 - `exhibit-a scan` without arguments scans the current directory
Replace the placeholder behaviour: no REPO argument means scan the current working directory (RepoProfile, `--graph`, `--pr-diff` unchanged). Update parser help text and tests. Keep exit codes and JSON schema.

## T147 - Slice default in CI
Check action.yml and the workflow: which profile does the GitHub Action run? Decide and document whether PR runs use `--profile compact` (slice on). If not, add the input/default needed so PR runs are diff-scoped and cost-capped. Test it.

## T148 - Risk gate wording
src/exhibit_a/ci/gate.py calls itself "a deliberately small placeholder". Keep the behaviour, reword honestly as a rule-based risk gate (what it does, what it does not), and make sure README describes it the same way. No behaviour change unless a test requires it.

## T149 - CLI polish and per-repo dashboard
`exhibit-a --help` lists scan, run, dashboard, report, verify, doctor, audit, sarif, reproduce, runs, ledger, trace, advisories, one line each; global `--verbose` works. Run `exhibit-a dashboard` from inside a different repo (not Exhibit-A) and confirm it opens the local per-repo dashboard and prints the one-time link. Fix or document exactly what works.

## T150 - Chain validation (private throwaway repo `exhibit-a-testbed`)
Prereqs by Diego: repo created, secret META_API_KEY set, "Exhibit A" required status check on main. Agent never prints or reads the key. Small app with passing tests; ~14 PRs: 5 vulnerable (path traversal, SQLi, SSRF, IDOR, ReDoS), 5 controls, 4 adversarial (prompt injection in diff/README, test that tries to fool the oracle, huge diff, empty PR). Per PR record expected vs got verdict, cost, time, check result, merge blocked?, comment present?, suggested fix present?. Output: the chain-validation report under docs/ci (produced by T150). Total API budget US$3; stop if exceeded. These real runs feed the video.

## T151 - README, SECURITY, cleanup
README: tagline, demo/video link, how it works (keep mermaid), install in 3 steps, sample PR comment, results (only numbers in bench/results), "What it does NOT do" (green != safe), threat model, tests, credits. Create SECURITY.md. Cleanup: remove docs/design/screenshots-before|after|verify (keep matrix), decide spikes/, `git rm --cached` files that .gitignore excludes under audit-out/ and runs/ except those the demo uses, ensure .gitignore covers __pycache__, .pytest_cache, .DS_Store. Optional ASCII logo only (<= 8 lines).

## T152 - Release
Suite green with Docker, CI green on main, tag v0.1.0-hackathon, cold clone in a fresh folder following README verbatim, secrets scan of git history.

## Cut rule
Tue 14:00: each branch is green and merged, or dropped and listed as Roadmap in README.
