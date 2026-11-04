# Docs index

One line per document. Paths are relative to the repository root.

- [common.md](common.md) — shared append-only per-task log (merge=union); read the last ~40 lines before starting a task.
- [GUIDE.md](GUIDE.md) — Spanish walkthrough of the project, verified against `main` on 2026-10-28.
- [how-this-was-built.md](how-this-was-built.md) — factual account of the spec-first, multi-agent build workflow.
- [related-work.md](related-work.md) — positioning against static analyzers, LLM scanners, and exploit tools: what is reported, what is proven, and what Exhibit A does not do.
- [README.md](README.md) — this index.

## oracle/ — the proof oracle

- [oracle/oracle-provenance.md](oracle/oracle-provenance.md) — authenticated provenance: admitting only staged application code, threat layers, residual limits R1-R6.
- [oracle/auto-redteam.md](oracle/auto-redteam.md) — automated red team: cheat prompts on fixed trees classified against R1-R6, replayable findings.
- [oracle/js-oracle.md](oracle/js-oracle.md) — JavaScript and TypeScript oracle (design): node:test runner, V8 structured stacks, authenticated provenance, and residual limits.
- [oracle/oracle-a1.md](oracle/oracle-a1.md) — finding A-1: signed oracle events (forged lines are dropped and counted, never proven).
- [oracle/oracle-eval.md](oracle/oracle-eval.md) — labelled exploit/variant evaluation set with measured precision and recall.
- [oracle/oracle-observer-spike.md](oracle/oracle-observer-spike.md) — out-of-process observer spike (research, not product): ptrace and fanotify prototypes.
- [oracle/second-class.md](oracle/second-class.md) — second vulnerability class decision: archive-extraction path traversal proven via `canary_write`.

## plan/ — closure planning


## ci/ — continuous integration

- [ci/github-action.md](ci/github-action.md) — GitHub Action usage: PR-diff runs, exit codes, result comments, ledger artifacts.
- [ci/github-action-security.md](ci/github-action-security.md) — Action security model: key handling, fork guard, leak scan, residual risks.
- [ci/live-pr-demo.md](ci/live-pr-demo.md) — Runbook for the live pull-request demo: setup, the two demo PRs, expected checks, disabling, cost.
- [ci/chain-validation.md](ci/chain-validation.md) — T150 live chain: 14 PRs on exhibit-a-testbed, expected vs obtained verdict, cost, time, merge block, comment, suggested fix.
- [ci/audit.md](ci/audit.md) — Repository audit: ranked graph reach paths, budget-capped loop, audit.json/audit.md, weekly workflow.
- [ci/fix-pr.md](ci/fix-pr.md) — Verified fix pull requests: review suggestions and automated PR branches.
- [ci/replay-determinism.md](ci/replay-determinism.md) — Why batch replay verdicts flipped under load, and the warm-up/sample and replay-timeout fixes.
- [ci/artifact-schema.md](ci/artifact-schema.md) — GitHub Action artifact contents and schema.
- [ci/ci-timing.md](ci/ci-timing.md) — sandbox job timeout, four docker shards, how to run one shard locally.

## bench/ — benchmark and costs

- [bench/bench.md](bench/bench.md) — naive LLM versus the proof loop on the corpus, with the generated results table.
- [bench/benchmark.md](bench/benchmark.md) — benchmark harness: corpus format, ablations, metrics, run instructions.
- [bench/ablations.md](bench/ablations.md) — ablation table: each loop flag and each oracle layer switched off; false proofs, true proofs, what attack got through.
- [coverage.md](coverage.md) — generated CWE coverage matrix: CWE id and name, effect, corpus case, proven live, notes.
- [bench/tools.md](bench/tools.md) — static tools (Bandit, Semgrep, CodeQL) versus Exhibit A on the corpus.
- [bench/meta-run.md](bench/meta-run.md) — real Meta-model runs (`muse-wonder-1.0`), standard and compact profiles, recordings and replay.
- [bench/repeatability.md](bench/repeatability.md) — repeatability harness output, with and without slicing.
- [bench/cost-controls.md](bench/cost-controls.md) — `--profile compact` cost controls: bounded answers, search/replace fixes, reasoning effort.

## security/ — threat model and audits

- [security/THREAT_MODEL.md](security/THREAT_MODEL.md) — attack surfaces, trust boundaries, mitigations, declared limits R1-R6, audit finding status.
- [security/audit-integration.md](security/audit-integration.md) — A-11 integration audit: findings F1-F20, PoCs, claim corrections, follow-up task specs.
- [security/oracle-redteam.md](security/oracle-redteam.md) — oracle red-team report: false-proof attacks found, recall gaps, what each layer stops.
- [security/advisory.md](security/advisory.md) — advisory lookup (OSV): version-range matching as a suspicion hint, never a verdict.

## design/ — architecture and surfaces

- [design/architecture.md](design/architecture.md) — system architecture, component contracts, and the loop diagram in prose.
- [design/code-graph.md](design/code-graph.md) — SCAN/SLICE code graph, reachability, and slicing: entry points from the graph, never from the model.
- [design/dashboard.md](design/dashboard.md) — local read-only dashboard: sources, threat model, views.
- [design/dashboard-api.md](design/dashboard-api.md) — dashboard API: every endpoint with a real example, per-source costs, hide missing fields.
- [design/first-cve.md](design/first-cve.md) — first real CVE end to end: Starlette CVE-2023-29159 proven through the loop.

## reference/ — CLI and runtime details

- [reference/cli.md](reference/cli.md) — CLI reference for every subcommand and flag.
- [reference/cli-exit-codes.md](reference/cli-exit-codes.md) — exit codes: 0 nothing proven, 10 proven, 20 incomplete, 2 usage error.
- [reference/models.md](reference/models.md) — model roles, providers (replay, ollama, openai-compatible, meta), budgets, recording and replay.
- [reference/providers.md](reference/providers.md) — model providers: Meta (primary) and Baseten (comparison and fallback) via OpenAI-compatible endpoints.
- [reference/sandbox.md](reference/sandbox.md) — sandbox isolation: image, limits, what the flags do and do not guarantee.
- [reference/sandbox-write-effect.md](reference/sandbox-write-effect.md) — write-effect sandbox plumbing: no canary file, tmpfs `outside/` dir, post-run dump.
- [reference/demo.md](reference/demo.md) — demo storyboard: red-to-green in 2-3 minutes via `scripts/demo.sh --offline` or `--live`.
- [reference/variants.md](reference/variants.md) — variant hunting: after a proof, list and prove the same bug on other graph paths.
- [reference/dependency-proofs.md](reference/dependency-proofs.md) — `exhibit-a deps`: advisory reachability through the call graph, sandbox proof, verified upgrade, `deps.json`.
- [reference/proof-bundles.md](reference/proof-bundles.md) — re-verifiable proof bundles: offline `verify` and sandbox `reproduce` with no model call.
- [reference/sbom-vex.md](reference/sbom-vex.md) — `exhibit-a sbom`: CycloneDX 1.5 SBOM with VEX states derived from Exhibit A evidence.

## demo/ and video/

- [demo/runbook.md](demo/runbook.md) — recording and operating runbook for the live demonstration.
- [video/script.md](video/script.md) — synchronized three-minute demonstration script.
