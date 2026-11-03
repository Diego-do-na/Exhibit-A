# Security policy

## Reporting a vulnerability

Please do not open a public issue for a vulnerability in Exhibit A or its
GitHub Action. Use
[GitHub's private vulnerability reporting form](https://github.com/Diego-do-na/Exhibit-A/security/advisories/new).
Include the affected commit or version, a minimal reproduction, impact, and
whether the issue affects the CLI, Action, dashboard, oracle, or sandbox.
Do not include API keys, tokens, private repository contents, or other secrets.

If private reporting is unavailable, contact the repository maintainers
privately through GitHub and request a security channel. We will acknowledge
reports when practicable, reproduce them, and coordinate disclosure after a
fix is available.

## Security boundaries

Exhibit A intentionally handles untrusted PR diffs, model output, and
model-written exploit tests. The engine validates model output against
schemas, and untrusted test and fix code runs in an **isolated and
resource-limited** sandbox with no network or secrets, dropped capabilities,
read-only filesystem controls, and bounded CPU, memory, process, and wall-clock
resources.

The model API and orchestration run outside the sandbox. Protected keys come
from environment or GitHub secrets and must never be committed. Fork pull
requests do not receive the model key. The dashboard binds to localhost and
uses a one-time link.

## Limits and non-guarantees

- A green result means nothing could be proven; it does not mean safe.
- Proof is limited to supported vulnerability classes, oracle effects, entry
  points, and benchmark coverage.
- `SCAN` and static slicing can miss behavior outside their rules and graph.
- The default container runtime shares the host kernel; optional gVisor can
  add another boundary when configured.
- The Starlette oracle has a documented host-process limitation.
- Residual oracle limits, host-side baseline limitations, and CI trust
  boundaries are maintained in
  [docs/security/THREAT_MODEL.md](docs/security/THREAT_MODEL.md) and
  [docs/oracle/oracle-provenance.md](docs/oracle/oracle-provenance.md).

Exhibit A does not guarantee that a repository is secure, that every
vulnerability will be found, or that the sandbox is impenetrable.
