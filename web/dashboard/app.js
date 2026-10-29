/* Exhibit A dashboard client. Plain JavaScript, no build step, no CDN.
 *
 * Every string shown here comes from a ledger or from GitHub and is
 * untrusted. It reaches the page only through textContent / createTextNode
 * (via h() below); innerHTML is never used. Links are limited to internal
 * "#/" routes and https://github.com/ URLs.
 */
"use strict";

const STAGES = ["BASELINE", "SUSPECT", "EXPLOIT", "RUN", "VERDICT", "FIX", "VERIFY", "PACKAGE"];
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SERIES = [
  ["proven", "Proven", "s1"],
  ["discarded_unproven", "Discarded (unproven)", "s2"],
  ["invalid_test", "Invalid test", "s3"],
];
const SVG_NS = "http://www.w3.org/2000/svg";

const view = document.getElementById("view");
let activeStream = null; // the replay EventSource, closed on navigation

// -- DOM helpers ---------------------------------------------------------------

function safeHref(value) {
  const text = String(value || "");
  if (text.startsWith("#/")) return text;
  try {
    const url = new URL(text);
    if (url.protocol === "https:" && url.hostname === "github.com") return url.href;
  } catch (_) { /* not a URL */ }
  return "#";
}

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") el.className = value;
    else if (key === "text") el.textContent = String(value);
    else if (key === "href") el.setAttribute("href", safeHref(value));
    else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, String(value));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

function svg(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (key === "text") el.textContent = String(value);
    else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, String(value));
  }
  for (const child of children) if (child) el.appendChild(child);
  return el;
}

function show(...nodes) {
  view.replaceChildren(...nodes.filter(Boolean));
}

// -- formatting ----------------------------------------------------------------

function fmtDuration(seconds) {
  if (typeof seconds !== "number" || !isFinite(seconds)) return "—";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  if (m < 60) return `${m}m ${String(s).padStart(2, "0")}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

function fmtCost(value) {
  return typeof value === "number" && isFinite(value) ? `$${value.toFixed(4)}` : "—";
}

function fmtDate(value, withTime = true) {
  const date = new Date(String(value || ""));
  if (isNaN(date.getTime())) return String(value || "—");
  const opts = withTime
    ? { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }
    : { month: "short", day: "numeric" };
  return date.toLocaleString(undefined, opts);
}

function fmtTime(value) {
  const date = new Date(String(value || ""));
  if (isNaN(date.getTime())) return "";
  return date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

function shortSha(value) {
  const text = String(value || "");
  return /^[0-9a-f]{7,64}$/.test(text) ? text.slice(0, 7) : text;
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

// -- API -----------------------------------------------------------------------

class AuthError extends Error {}

async function api(path) {
  const response = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" } });
  if (response.status === 401) throw new AuthError("not signed in");
  let body = null;
  try { body = await response.json(); } catch (_) { body = null; }
  if (!response.ok) throw new Error((body && typeof body.error === "string") ? body.error : `HTTP ${response.status}`);
  return body;
}

function renderError(error) {
  if (error instanceof AuthError) {
    show(h("div", { class: "notice" },
      h("h2", { text: "Open the one-time link" }),
      h("p", { text: "This dashboard needs the session set by the bootstrap link printed in the terminal where you started it." }),
      h("p", { class: "muted", text: "Each link works once. If it was already used, stop the dashboard and start it again for a new one." })));
    return;
  }
  show(h("div", { class: "notice error" }, h("strong", { text: "Could not load: " }), String(error.message || error)));
}

// -- shared pieces -------------------------------------------------------------

function statusBadge(row) {
  if (row.status === "unreadable") return h("span", { class: "badge warn", text: "unreadable" });
  if (row.proven > 0) return h("span", { class: "badge proven", text: `${row.proven} proven` });
  const labels = { aborted: "aborted", timed_out: "timed out", not_run: "not run", skipped: "skipped" };
  if (labels[row.status]) return h("span", { class: "badge warn", text: labels[row.status] });
  return h("span", { class: "badge", text: "nothing could be proven" });
}

function riskTag(risk) {
  return risk ? h("span", { class: "tag", text: `risk ${risk}` }) : h("span", { class: "muted", text: "—" });
}

function prCommit(row) {
  const parts = [];
  if (row.pr) parts.push(`PR #${String(row.pr).replace(/^#/, "")}`);
  if (row.commit) parts.push(shortSha(row.commit));
  else if (row.branch) parts.push(row.branch);
  return parts.join(" · ") || "—";
}

function stageTracker(stages, activeName) {
  return h("ol", { class: "stages", "aria-label": "Verification loop stages" },
    stages.map((stage) => h("li", {
      class: `${stage.reached ? "reached" : ""} ${stage.name === activeName ? "active" : ""}`.trim(),
      title: stage.reached ? `${stage.name}: ${plural(stage.count, "event")}` : `${stage.name}: not reached`,
    }, stage.name, h("span", { class: "count", text: stage.reached ? String(stage.count) : "—" }))));
}

function setTab(name) {
  for (const link of document.querySelectorAll(".tabs a")) {
    if (link.dataset.view === name) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
}

// -- runs list -----------------------------------------------------------------

async function renderRuns(page) {
  setTab("runs");
  const data = await api(`/api/runs?page=${page}&per_page=20`);
  const rows = data.runs || [];
  const synthetic = rows.some((r) => r.synthetic);
  const table = h("table", { class: "runs" },
    h("thead", {}, h("tr", {},
      h("th", { text: "Status" }), h("th", { text: "Run" }), h("th", { text: "Repository" }),
      h("th", { text: "PR / commit" }), h("th", { text: "Risk" }), h("th", { class: "num", text: "Proven" }),
      h("th", { class: "num", text: "Duration" }), h("th", { class: "num", text: "Cost" }))),
    h("tbody", {}, rows.map((row) => {
      const target = `#/run/${encodeURIComponent(row.run_id)}`;
      return h("tr", { onclick: () => { location.hash = target; } },
        h("td", {}, statusBadge(row)),
        h("td", {},
          h("a", { class: "run-title", href: target, text: row.headline }),
          h("div", { class: "run-sub" }, `${fmtDate(row.started_at)} · ${row.run_id}`, row.synthetic ? " · synthetic" : "")),
        h("td", { "data-label": "Repo", class: "run-sub", text: row.repo || "—" }),
        h("td", { "data-label": "PR/commit", class: "mono", text: prCommit(row) }),
        h("td", { "data-label": "Risk" }, riskTag(row.risk)),
        h("td", { "data-label": "Proven", class: "num", text: String(row.proven) }),
        h("td", { "data-label": "Duration", class: "num", text: fmtDuration(row.duration_s) }),
        h("td", { "data-label": "Cost", class: "num", text: fmtCost(row.cost_usd) }));
    })));
  const totalProven = rows.reduce((n, r) => n + (r.proven || 0), 0);
  show(
    h("h1", { text: "Runs" }),
    h("p", { class: "lede", text: `${plural(data.total, "run")} from ${data.source}. ${plural(totalProven, "proven finding")} on this page. A run with nothing proven means nothing could be proven, not that the code is safe.` }),
    synthetic ? h("p", { class: "banner-synthetic", text: "Synthetic sample data" }) : null,
    rows.length
      ? h("div", { class: "card table-wrap" }, table, pager(data.page, data.pages, (p) => `#/runs/${p}`))
      : h("div", { class: "card muted", text: "No runs found in this source." }));
}

function pager(page, pages, hrefFor) {
  if (pages <= 1) return null;
  return h("div", { class: "pager" },
    page > 1 ? h("a", { href: hrefFor(page - 1), text: "← Newer" }) : null,
    h("span", { class: "muted small", text: `Page ${page} of ${pages}` }),
    page < pages ? h("a", { href: hrefFor(page + 1), text: "Older →" }) : null);
}

// -- run detail ----------------------------------------------------------------

function metaList(row, extra) {
  const items = [
    ["Repository", row.repo || "—"],
    ["PR / commit", prCommit(row)],
    ["Started", fmtDate(row.started_at)],
    ["Duration", fmtDuration(row.duration_s)],
    ["Cost", fmtCost(row.cost_usd)],
    ["Tokens in / out", `${row.tokens_in} / ${row.tokens_out}`],
    ["Suspicions", `${row.suspicions_raised} raised · ${row.proven} proven · ${row.dropped} dropped`],
    ["Ledger run id", row.ledger_run_id || "—"],
    ...extra,
  ];
  return h("dl", { class: "meta" }, items.map(([k, v]) => h("div", {}, h("dt", { text: k }), h("dd", { text: v }))));
}

function findingCard(item) {
  const ev = item.evidence || {};
  const red = ev.fails_on_vulnerable || {};
  const effect = ev.effect || {};
  const prov = ev.provenance || {};
  const fixed = ev.passes_on_fixed || {};
  const fix = ev.fix || {};
  const bypass = ev.bypass || { tried: 0, succeeded: 0, variants: [] };
  const runsText = red.of ? `${red.runs} of ${red.of} runs` : plural(red.runs || 0, "run");
  const effectLabel = effect.type === "canary_write" ? "canary_write — the app created a file outside its allowed directory"
    : effect.type === "canary_read" ? "canary_read — the app read a file outside its allowed directory"
      : String(effect.type || "unknown");

  const chain = h("ol", { class: "chain" }, (prov.frames || []).map((f) => h("li", {
    class: f.entry_point ? "entry" : (f.admitted ? "app" : ""),
  },
  h("span", { class: "fn", text: f.qualname || f.function || "?" }),
  f.entry_point ? h("span", { class: "tag", text: "entry point" }) : null,
  f.admitted === true ? h("span", { class: "tag", text: "app code" }) : null,
  h("span", { class: "where", text: `${f.file || "?"}${f.line ? `:${f.line}` : ""}` }))));

  let green;
  if (fixed.fix_verified) {
    green = h("p", {}, `Exploit passes on the fixed code (${plural(fixed.runs, "run")}); baseline ${fixed.baseline_ok ? "still passes" : "not confirmed"}.`);
  } else if (!fix.proposed) {
    green = h("p", { text: "No fix was proposed." });
  } else if (!fix.applied) {
    green = h("p", {}, "The proposed fix was rejected: ", fix.error || "invalid patch");
  } else {
    green = h("p", { text: "The fix was not verified: the exploit did not pass on the fixed code, or the baseline failed." });
  }

  return h("article", { class: "card finding" },
    h("div", { class: "headline" },
      h("span", { class: "badge proven", text: "proven" }),
      h("h3", { text: `${item.id} · ${item.class || "unknown class"}` })),
    h("p", { class: "mono small muted", text: `${item.file || "?"}:${item.line} · entry point ${item.entry_point || "?"}` }),
    h("p", { class: "hyp", text: item.hypothesis || item.reason || "" }),
    h("div", { class: "proof" },
      h("section", {},
        h("h3", {}, h("span", { class: "dot red" }), "Red: fails on vulnerable code"),
        h("p", { text: `The exploit test failed in ${runsText}, with ${plural(red.oracle_events || 0, "oracle event")}.` }),
        h("p", { class: "muted small", text: item.reason || "" })),
      h("section", {},
        h("h3", {}, h("span", { class: "dot amber" }), "Effect seen by the oracle"),
        h("p", { text: effectLabel }),
        effect.path ? h("p", { class: "mono small", text: `${effect.path}${effect.mode ? ` (mode ${effect.mode})` : ""}` }) : null,
        effect.via_symlink ? h("p", { class: "small", text: "Opened through a symlink created during the run." }) : null),
      h("section", {},
        h("h3", {}, h("span", { class: "dot green" }), "Green: passes on fixed code"),
        green,
        bypass.succeeded
          ? h("p", { class: "notice small", text: `${plural(bypass.succeeded, "defender variant")} still reached the effect on the fixed code: the fix is incomplete.` })
          : null,
        bypass.tried
          ? h("div", {},
            h("p", { class: "small", text: `Defender bypass variants: ${bypass.tried} tried, ${bypass.succeeded} succeeded.` }),
            h("ul", { class: "variants small" }, bypass.variants.map((v) => h("li", {},
              h("span", { class: v.bypassed ? "badge proven" : (v.error ? "badge warn" : "badge good"), text: v.bypassed ? "bypassed" : (v.error ? "error" : "held") }),
              " ", v.name || "?"))))
          : h("p", { class: "small muted", text: "No defender bypass variants were run." }),
        ev.package ? h("p", { class: "small muted mono", text: `package: ${ev.package}` }) : null)),
    h("section", { style: null },
      h("h3", { text: "Provenance chain" }),
      h("p", { class: "small muted", text: `Call stack recorded by the oracle when the effect happened, outermost first. The proof requires the effect to come from application code reached through the entry point ${prov.entry_point || "?"}.` }),
      (prov.frames || []).length ? chain : h("p", { class: "muted small", text: "No stack was recorded in this ledger." })));
}

function discardedTable(items) {
  if (!items.length) return h("p", { class: "muted", text: "No suspicions were discarded." });
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, h("th", { text: "Suspicion" }), h("th", { text: "Verdict" }), h("th", { text: "Location" }), h("th", { text: "Why it was not proven" }))),
    h("tbody", {}, items.map((item) => h("tr", {},
      h("td", {}, h("strong", { text: item.id }), h("div", { class: "run-sub", text: item.class || "" })),
      h("td", {}, h("span", { class: "badge plain", text: item.verdict })),
      h("td", { class: "mono small", text: item.file ? `${item.file}:${item.line}` : "—" }),
      h("td", { class: "small", text: item.reason || "—" }))))));
}

function eventItem(ev, fresh) {
  return h("li", { class: fresh ? "fresh" : "" },
    h("span", { class: "ts", text: fmtTime(ev.ts) }),
    h("span", { class: "stage", text: ev.stage || ev.type }),
    h("span", { class: "text" }, ev.summary, ev.role ? h("span", { class: "muted small", text: ` · ${ev.role}` }) : null));
}

async function renderRun(id) {
  setTab("runs");
  const data = await api(`/api/runs/${encodeURIComponent(id)}`);
  const row = data.run;
  const extra = [["Source run", row.run_id]];
  if (row.risk) extra.push(["Risk gate", row.risk]);
  const header = h("div", { class: "card" },
    row.synthetic ? h("p", { class: "banner-synthetic", text: "Synthetic sample run" }) : null,
    h("div", { class: "headline" }, statusBadge(row), h("h1", { text: row.headline })),
    row.status === "unreadable" ? h("p", { class: "notice error" }, "This run's ledger or result did not validate, so nothing from it is shown: ", row.error) : null,
    row.skipped_reason ? h("p", { class: "muted" }, "Skipped: ", row.skipped_reason) : null,
    row.ablated ? h("p", { class: "notice" }, "This run used ablation flags; its verdicts do not meet the full proof standard.") : null,
    metaList(row, extra),
    h("div", { class: "toolbar", style: null },
      h("span", { class: "spacer" }),
      row.url ? h("a", { href: row.url, rel: "noreferrer noopener", target: "_blank", text: "Open on GitHub" }) : null,
      row.status !== "unreadable" && row.event_count ? h("a", { href: `#/replay/${encodeURIComponent(row.run_id)}`, text: "Replay this run →" }) : null));

  const sections = [h("p", {}, h("a", { href: "#/runs", text: "← All runs" })), header];
  if (row.status !== "unreadable") {
    sections.push(h("div", { class: "card" }, h("h2", { text: "Verdict timeline" }), stageTracker(data.stages)));
    sections.push(h("h2", { text: data.proven.length ? `Proven findings (${data.proven.length})` : "Proven findings" }));
    if (data.proven.length) sections.push(...data.proven.map(findingCard));
    else sections.push(h("div", { class: "card" }, h("p", { text: "Nothing could be proven in this run." }),
      h("p", { class: "muted small", text: "This is not a statement that the code is safe: only that no suspicion survived the proof standard." })));
    sections.push(h("div", { class: "card" }, h("h2", { text: `Discarded suspicions (${data.discarded.length})` }), discardedTable(data.discarded)));
    const list = h("ol", { class: "events" });
    const more = h("button", { type: "button", text: "Load more events" });
    const eventsCard = h("div", { class: "card" }, h("h2", { text: `Ledger events (${row.event_count})` }), list, h("div", { class: "pager" }, more));
    let cursor = 0;
    const load = async () => {
      more.disabled = true;
      try {
        const page = await api(`/api/runs/${encodeURIComponent(id)}/events?from=${cursor}&limit=100`);
        append(list, page.events.map((ev) => eventItem(ev, false)));
        cursor += page.count;
        more.hidden = cursor >= page.total;
      } catch (error) {
        append(list, h("li", { class: "muted", text: String(error.message || error) }));
      }
      more.disabled = false;
    };
    more.addEventListener("click", load);
    sections.push(eventsCard);
    show(...sections);
    await load();
    return;
  }
  show(...sections);
}

// -- trends --------------------------------------------------------------------

function trendChart(points) {
  const width = 760;
  const height = 260;
  const pad = { top: 12, right: 8, bottom: 30, left: 34 };
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const totals = points.map((p) => SERIES.reduce((n, [key]) => n + (p[key] || 0), 0));
  const maxY = Math.max(1, ...totals);
  const step = maxY <= 5 ? 1 : Math.ceil(maxY / 5);
  const top = Math.ceil(maxY / step) * step;
  const y = (v) => pad.top + innerH - (v / top) * innerH;
  const slot = innerW / Math.max(points.length, 1);
  const barW = Math.max(6, Math.min(36, slot * 0.6));

  const root = svg("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": "Verdicts per run over time, stacked: proven, discarded unproven, invalid test" });
  const grid = svg("g", { class: "grid axis" });
  for (let v = 0; v <= top; v += step) {
    grid.appendChild(svg("line", { x1: pad.left, x2: width - pad.right, y1: y(v), y2: y(v) }));
    grid.appendChild(svg("text", { x: pad.left - 8, y: y(v) + 4, "text-anchor": "end", text: String(v) }));
  }
  root.appendChild(grid);

  const wrap = h("div", { class: "chart" });
  const tip = h("div", { class: "tooltip", hidden: "hidden", role: "status" });
  const labelEvery = Math.max(1, Math.ceil(points.length / 8));
  points.forEach((p, i) => {
    const cx = pad.left + slot * i + slot / 2;
    let base = 0;
    const group = svg("g", {});
    SERIES.forEach(([key, , cls], si) => {
      const value = p[key] || 0;
      if (!value) return;
      const y0 = y(base);
      const y1 = y(base + value);
      const isTop = SERIES.slice(si + 1).every(([k]) => !(p[k] || 0));
      const r = isTop ? Math.min(4, barW / 2, y0 - y1) : 0;
      const x0 = cx - barW / 2;
      const x1 = cx + barW / 2;
      const d = r
        ? `M${x0},${y0} V${y1 + r} Q${x0},${y1} ${x0 + r},${y1} H${x1 - r} Q${x1},${y1} ${x1},${y1 + r} V${y0} Z`
        : `M${x0},${y0} V${y1} H${x1} V${y0} Z`;
      group.appendChild(svg("path", { d, class: `seg ${cls}` }));
      base += value;
    });
    root.appendChild(group);
    if (i % labelEvery === 0) {
      root.appendChild(svg("text", { x: cx, y: height - 10, "text-anchor": "middle", class: "axis", text: fmtDate(p.started_at, false) }));
    }
    const hit = svg("rect", {
      class: "hit", x: cx - slot / 2, y: pad.top, width: slot, height: innerH, tabindex: "0",
      "aria-label": `${p.run_id}: ${SERIES.map(([k, label]) => `${label} ${p[k] || 0}`).join(", ")}`,
    });
    const showTip = () => {
      tip.replaceChildren(
        h("strong", { text: fmtDate(p.started_at) }),
        h("div", { class: "muted small", text: p.run_id }),
        ...SERIES.map(([k, label, cls]) => h("div", { class: "row" }, h("span", {}, h("span", { class: `swatch ${cls}` }), ` ${label}`), h("strong", { text: String(p[k] || 0) }))),
        ...((p.flaky || p.env_failure) ? [h("div", { class: "muted small", text: `also flaky ${p.flaky || 0}, env_failure ${p.env_failure || 0}` })] : []));
      tip.hidden = false;
      const box = wrap.getBoundingClientRect();
      const frac = cx / width;
      const left = Math.min(Math.max(frac * box.width - 90, 0), Math.max(box.width - 200, 0));
      tip.style.left = `${left}px`;
      tip.style.top = "0px";
    };
    hit.addEventListener("mouseenter", showTip);
    hit.addEventListener("focus", showTip);
    hit.addEventListener("click", () => { location.hash = `#/run/${encodeURIComponent(p.run_id)}`; });
    hit.addEventListener("mouseleave", () => { tip.hidden = true; });
    hit.addEventListener("blur", () => { tip.hidden = true; });
    root.appendChild(hit);
  });
  return append(wrap, [root, tip]);
}

async function renderTrends() {
  setTab("trends");
  const data = await api("/api/trends?limit=50");
  const points = data.points || [];
  const sums = Object.fromEntries(SERIES.map(([k]) => [k, points.reduce((n, p) => n + (p[k] || 0), 0)]));
  const table = h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, h("th", { text: "Run" }), ...SERIES.map(([, label]) => h("th", { class: "num", text: label })), h("th", { class: "num", text: "Flaky" }), h("th", { class: "num", text: "Env failure" }))),
    h("tbody", {}, points.slice().reverse().map((p) => h("tr", { onclick: () => { location.hash = `#/run/${encodeURIComponent(p.run_id)}`; } },
      h("td", {}, h("a", { href: `#/run/${encodeURIComponent(p.run_id)}`, text: fmtDate(p.started_at) }), h("div", { class: "run-sub", text: p.run_id })),
      ...SERIES.map(([k]) => h("td", { class: "num", text: String(p[k] || 0) })),
      h("td", { class: "num", text: String(p.flaky || 0) }),
      h("td", { class: "num", text: String(p.env_failure || 0) }))))));
  show(
    h("h1", { text: "Trends" }),
    h("p", { class: "lede", text: `Verdicts per run across the ${plural(points.length, "most recent readable run")}: ${sums.proven} proven, ${sums.discarded_unproven} discarded for lack of proof, ${sums.invalid_test} invalid tests.` }),
    points.some((p) => p.synthetic) ? h("p", { class: "banner-synthetic", text: "Includes synthetic sample data" }) : null,
    points.length
      ? h("div", { class: "card" },
        h("h2", { text: "Proven vs discarded vs invalid, per run" }),
        h("ul", { class: "legend" }, SERIES.map(([, label, cls]) => h("li", {}, h("span", { class: `swatch ${cls}` }), label))),
        trendChart(points))
      : h("div", { class: "card muted", text: "No readable runs yet." }),
    points.length ? h("div", { class: "card" }, h("h2", { text: "Table" }), table) : null);
}

// -- replay --------------------------------------------------------------------

async function renderReplay(id) {
  setTab("runs");
  const detail = await api(`/api/runs/${encodeURIComponent(id)}`);
  const row = detail.run;
  const total = row.event_count;
  const reached = Object.fromEntries(STAGES.map((name) => [name, 0]));
  let cursor = 0;
  let current = "";

  const trackerHost = h("div", {});
  const list = h("ol", { class: "events" });
  const progress = h("span", { class: "muted small" });
  const speed = h("select", { "aria-label": "Replay speed" },
    ["0.5", "1", "2", "4", "8"].map((v) => h("option", { value: v, text: `${v}×` })));
  speed.value = "2";
  const play = h("button", { type: "button", class: "primary", text: "Play" });
  const step = h("button", { type: "button", text: "Step" });
  const restart = h("button", { type: "button", text: "Restart" });

  const redraw = () => {
    trackerHost.replaceChildren(stageTracker(STAGES.map((name) => ({ name, count: reached[name], reached: reached[name] > 0 })), current));
    progress.textContent = `${cursor} / ${total} events`;
    step.disabled = cursor >= total;
    if (cursor >= total) play.textContent = "Done";
    play.disabled = cursor >= total;
  };

  const add = (ev) => {
    if (typeof ev.seq !== "number" || ev.seq !== cursor) return; // ledger order only, no gaps
    cursor += 1;
    if (ev.stage && reached[ev.stage] !== undefined) { reached[ev.stage] += 1; current = ev.stage; }
    list.prepend(eventItem(ev, true));
    redraw();
  };

  const stop = () => {
    if (activeStream) { activeStream.close(); activeStream = null; }
    if (cursor < total) play.textContent = "Play";
  };

  play.addEventListener("click", () => {
    if (activeStream) { stop(); return; }
    activeStream = new EventSource(`/api/runs/${encodeURIComponent(id)}/replay?speed=${encodeURIComponent(speed.value)}&from=${cursor}`);
    play.textContent = "Pause";
    activeStream.addEventListener("step", (msg) => {
      try { add(JSON.parse(msg.data)); } catch (_) { /* ignore a malformed frame */ }
    });
    activeStream.addEventListener("done", stop);
    activeStream.onerror = stop;
  });
  step.addEventListener("click", async () => {
    stop();
    const page = await api(`/api/runs/${encodeURIComponent(id)}/events?from=${cursor}&limit=1`);
    page.events.forEach(add);
  });
  restart.addEventListener("click", () => {
    stop();
    cursor = 0;
    current = "";
    for (const name of STAGES) reached[name] = 0;
    list.replaceChildren();
    play.textContent = "Play";
    redraw();
  });
  speed.addEventListener("change", () => { if (activeStream) { stop(); play.click(); } });

  show(
    h("p", {}, h("a", { href: `#/run/${encodeURIComponent(id)}`, text: "← Run detail" })),
    h("div", { class: "card" },
      row.synthetic ? h("p", { class: "banner-synthetic", text: "Synthetic sample run" }) : null,
      h("div", { class: "headline" }, statusBadge(row), h("h1", { text: `Replay: ${row.headline}` })),
      h("p", { class: "muted", text: `Re-plays the recorded ledger of ${row.run_id} step by step, in ledger order. Nothing is re-executed.` }),
      h("div", { class: "toolbar" }, play, step, restart, h("label", { class: "small" }, "Speed ", speed), h("span", { class: "spacer" }), progress)),
    h("div", { class: "card" }, h("h2", { text: "Verdict timeline" }), trackerHost),
    h("div", { class: "card" }, h("h2", { text: "Events (newest first)" }), list));
  redraw();
}

// -- router --------------------------------------------------------------------

async function route() {
  if (activeStream) { activeStream.close(); activeStream = null; }
  const parts = location.hash.replace(/^#\/?/, "").split("/").map((p) => { try { return decodeURIComponent(p); } catch (_) { return ""; } });
  try {
    if (parts[0] === "run" && RUN_ID.test(parts[1] || "")) await renderRun(parts[1]);
    else if (parts[0] === "replay" && RUN_ID.test(parts[1] || "")) await renderReplay(parts[1]);
    else if (parts[0] === "trends") await renderTrends();
    else await renderRuns(Math.max(1, parseInt(parts[1] || "1", 10) || 1));
    window.scrollTo(0, 0);
  } catch (error) {
    renderError(error);
  }
}

async function boot() {
  try {
    const info = await api("/api/info");
    document.getElementById("source").textContent = info.source;
  } catch (error) {
    document.getElementById("source").textContent = "not connected";
  }
  window.addEventListener("hashchange", route);
  await route();
}

boot();
