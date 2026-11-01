# Design handoff notes (T132)

- Source: Figma file `oirV5yNnRAgvro6VH7iIED` ("Sin título"), page 1. Frozen frames: **04 Run overview** (node 20:2754) and **05 Finding detail** (node 20:2936). Detail tweaks happen later in code.
- Renders: `04-run-overview.png`, `05-finding-detail.png` (1752 px wide; use as the visual target).
- `tokens.json`: all variables used by both frames. Implement as CSS custom properties; never hardcode hex in components.
- `components.md`: structure, sizes and behavior.
- **Illustrative data**: every number, id and path in the frames (EA0248, $1.84, 24 tests, src/routes/export.ts, etc.) is mock content. The UI must read real values from the ledger/export and show "not available" when missing.
- **Code samples are TypeScript** (JS/TS target apps; matches the Node oracle). They are examples, not a statement that the engine only supports TS.
- **Assets not exported**: the sandbox proxy blocked downloads from Figma, so `assets/` is empty. Icons are Lucide (names in components.md). The "A" brand mark is marked *Provisional* in Figma (node 20:2758 / 20:2940); export it as SVG from Figma before the final build or use a text fallback.
- Fonts: Lora (editorial), IBM Plex Sans (UI), JetBrains Mono (code/ids). Self-host or use a CDN-free bundle if the live view must work offline.
- Glass effects (backdrop blur 24, inner shadow, drop shadow) are in `tokens.json` under `effect`; degrade gracefully to solid navy when `backdrop-filter` is unsupported.
- Only screens 04 and 05 exist in the file. Live run, Findings list, Benchmark and Dependencies must be restyled from tokens.
