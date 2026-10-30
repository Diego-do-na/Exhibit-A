# Spikes

Research spikes, not product code. Nothing under `spikes/` runs in the
product, ships in the package, or is imported by `src/`, `bench/` or `tests/`.
Each spike documents an attack or an observation technique so the product can
defend against it or learn from it. Findings that changed the product are
written up under `docs/oracle/` and `docs/security/`.

- `observer/` — out-of-process oracle observers (A-1 spike). A ptrace
  parent-observer and a host-side fanotify watch that record canary opens from
  outside the test process, prototyped under the exact product sandbox posture.
  Has its own [README](observer/README.md); full analysis and recommendation in
  [docs/oracle/oracle-observer-spike.md](../docs/oracle/oracle-observer-spike.md).
  Linux only; the ptrace prototype is x86_64-only.
- `redteam/` — oracle red-team PoCs (A-1-redteam). One script per attack
  (`attack_*.py`) plus a shared harness (`_harness.py`) and a runner
  (`run_all.py`, with a sandbox twin driver). Each attack builds a throwaway
  app and exploit, then runs the real oracle exactly as the product does.
  Covered attacks include forged events, forged frames, key introspection,
  symlink rechecks, subprocess/ctypes/dir-fd sinks, dependency monkeypatching,
  and differential bypasses. Written up in
  [docs/security/oracle-redteam.md](../docs/security/oracle-redteam.md).
