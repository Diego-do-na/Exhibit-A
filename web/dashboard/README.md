# Exhibit A dashboard

Six static pages served by `python -m exhibit_a.dashboard` (or any static file server), with
no build step and no third-party code.

| File | View |
|---|---|
| `index.html` | Overview: proof state, merges per day, findings by effect, verification funnel |
| `prs.html` | Pull requests: throughput, merge timeline, size and cycle-time histograms, searchable table |
| `pr.html` | Pull request analysis: risk, live proof-loop replay, decision, diff with the vulnerable line, blast radius, proposed fix, approve-and-commit flow, MITRE ATT&CK / CWE / CAPEC / OWASP sheets |
| `findings.html` | Findings: verdicts, outcome by effect or CWE, refusal reasons, held-out vs tuning, cost per case, case explorer |
| `graph.html` | Code graph: layers, graph canvas (space reserved), packages, hotspots |
| `benchmark.html` | Benchmark: proof loop vs naive LLM, ablations, model economics, agent performance and scorecard |

## Layout of the folder

- `<page>.html`: the markup of one page inside `<template data-dc>`.
- `views/<page>.js`: that page's logic, `window.Component = class Component extends DCLogic`.
  `renderVals()` returns every value the template reads.
- `dashboard.css`: shared styles and the `@font-face` rules.
- `views/viz.js`: shared helpers loaded before `dc-lite.js`: the chart zoom dialog (any `<button data-zoom data-zoom-desc="..." data-zoom-points="a|b|c">` opens its card's chart in a zoomable dialog with the description), `DCViz.graph` (SVG graph with force or fixed layout, pan, zoom, focus, filter and search; hosts carry `data-keep` so `dc-lite` leaves their children alone) and the entrance count-up.
- `dc-lite.js`: the runtime. It renders the template and morphs each state change into the
  live DOM, so focus, scroll and CSS animations survive.
- `fonts/`: self-hosted Space Grotesk, IBM Plex Sans and JetBrains Mono, with their licences.

## Template rules

- `<sc-for>` cannot sit inside `<select>` (the HTML parser drops it). A select takes `data-options="{{list}}"`, a list of `{ k, l }`.
- A host that code draws into (chart, graph) carries `data-keep`; `dc-lite` then syncs its attributes but never touches its children. `componentDidRender(root)` runs after every render.

- Holes are lookups only (`{{a.b}}`, `{{ true }}`), never expressions.
- `<sc-for list="{{xs}}" as="x">` repeats, `<sc-if value="{{cond}}">` branches.
- `onClick="{{fn}}"`, `onChange="{{fn}}"` (fires on every keystroke for inputs) bind handlers.
- Write inline styles as `data-style="..."`, never `style="..."`. The server's CSP is
  `style-src 'self'`; `dc-lite.js` applies `data-style` through the CSSOM, which the CSP allows,
  and the browser never sees a style attribute it would block.
- No inline `<script>` and no `eval`: the CSP is `script-src 'self'`.

## Data

Every number comes from the dashboard API for the current `--source`
(`local:<dir>` or `github:<owner/repo>`): the run ledger is the single source
of truth, and any field the ledger and artifacts do not record reads
`not recorded`, never an estimate. See
[docs/design/dashboard.md](../../docs/design/dashboard.md) for the sources,
the data rule, and what is simulated.

The unparameterised `pr.html` view is a recorded demo that replays a fixed
example client-side; the approve flow is UI only and pushes nothing.

## Next steps

- Wire "Approve and commit fix" to the Action's fix-PR flow (`docs/ci/fix-pr.md`).
- `exhibit-a dashboard --export` still writes `data/*.json` and `static.js` for one run; the
  pages do not read them yet.
