# Components (from Figma frames 04 and 05)

Icons are Lucide names (use the `lucide` package or inline SVG; sizes 14/20/22 px): layout-dashboard, activity, file-search, chart-no-axes-combined, git-branch, monitor, download, circle-check, layers-2, file-check-2, minus-circle, circle-x, repeat-2, unplug, clock-3, file-text, chevron-down/up/right, x, check, code-2, circle-alert.

## Shell (both screens)
- **Sidebar** 260 px, glass over navy gradient: brand (A mark + "Exhibit A", Lora 27 bold), **Run context** card (label, run id in JetBrains Mono 22 bold + chevron, "Illustrative data"), **Navigation** (Overview, Live run, Findings, Benchmark, Dependencies; 56 px items, radius 12; active = glass fill + border + inner shadow, white semibold 20; inactive = navigation/inactive), **Environment** footer (monitor icon, "Local replay", branch in mono 15).
- **Workspace header** 134 px: breadcrumb (UI 18), page title (Lora 40 bold, -0.6 tracking, white), glass **Action** button (52 px, radius 12, download icon).
- **Data workspace**: white-blue panel (surface/workspace-white), radius 24, padding 40, gap 32. **Record footer**: "Proof before accusation" left, "Illustrative data · ..." right (UI 16, text/slate).

## 04 Run overview
- **Run status** row: circle-check + "Run completed" + run id (mono); commit range right (mono 16).
- **Run summary** (3 cards, radius 18, padding 28, border default):
  - Finding count 300 px: label, big number (Lora 88 bold), "N raw proven proofs", dedup bar (accent = unique, chart/duplicates = grouped), "N duplicates grouped".
  - Test outcomes (flex): title + "N tests"; 5 rows (Proven, Unproven, Invalid, Flaky, Environment failure) = icon + label + proportional bar (9 px, track surface/workspace, fill chart/*) + count (UI 24 semibold, right).
  - Run resources 300 px: "Budget used", cost (Lora 52 bold), "92% of $2.00", meter (12 px), elapsed time (clock + UI 26).
- **Findings list**: section heading (Lora 28 + subtitle), 2-column grid of **Finding card** (radius 12, padding 24): id (mono, accent) + Proven chip (surface/selected), title (UI 26 semibold), file:lines (mono 16), classification row (effect chip + "High · CWE-22" in severity/high + "N proofs · Open →" accent semibold).

## 05 Finding detail
- **Finding metadata**: verdict chip (Proven), severity+CWE tag, effect chip, proof id; right: "base X → fix Y" (mono).
- **Selected proof**: heading "Boundary assertion"; two cards "Before fix" (FAIL pill: test/fail on test/fail-surface) and "After fix" (PASS pill: accent on selected). Each shows Expected / Received status codes (mono 42-ish; received red on fail, accent on pass) and a one-line observed result.
- **Evidence workspace** (968 + 356 px, gap 24): tabs ("Patch & test" selected = accent fill, white; "Source context"), **Source patch** code block (code/* tokens, diff markers -/+), **Replay test** code block, **Duplicate proof disclosure** (collapsed row "3 proofs / 1 finding · View grouped proofs"). Right column: **Oracle observation** card (collapsible; "1 → 0" reads outside root, facts: Effect, Allowed root, Observed path, Canary match, "3/3 consistent", fixture scope note) and **Location** card (file, Guess vs Observed lines).
- **Offline record** card: heading "Re-verify offline" + Download bundle button; terminal block (commands) + manifest list (file label + SHA-256 mono); mismatch policy line with circle-alert icon.

## Data mapping hints
Verdict classes map to chart tokens: proven, unproven, invalid, flaky, environment (environment failure). Show "not available" instead of inventing numbers (T131 scope decision).
