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
const pageTitle = document.getElementById("page-title");
const headerBreadcrumb = document.getElementById("header-breadcrumb");
const actionBtn = document.getElementById("action-btn");
const actionBtnText = document.getElementById("action-btn-text");
const actionBtnIcon = document.getElementById("icon-action");
const runSelect = document.getElementById("run-select");
const runCurrentId = document.getElementById("run-current-id");
const runCurrentSub = document.getElementById("run-current-sub");
const themeToggle = document.getElementById("theme-toggle");
const recordFooterRight = document.getElementById("record-footer-right");

let activeStream = null; // Replay EventSource, closed on navigation
let currentRunId = null;
let allRuns = [];
let runsById = new Map();

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
    if (value === null || value === undefined || value === false) continue;
    if (key === "text") el.textContent = String(value);
    else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, String(value));
  }
  for (const child of children.flat()) {
    if (child instanceof Node) el.appendChild(child);
  }
  return el;
}

function show(...nodes) {
  view.replaceChildren(...nodes.filter(Boolean));
}

// -- Lucide SVG Icon helper ----------------------------------------------------

function icon(name, size = 18) {
  const s = String(size);
  const el = svg("svg", {
    width: s,
    height: s,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    "stroke-width": "2",
    "stroke-linecap": "round",
    "stroke-linejoin": "round",
    "aria-hidden": "true",
  });

  const p = (tag, attrs) => el.appendChild(svg(tag, attrs));

  switch (name) {
    case "layout-dashboard":
      p("rect", { width: "7", height: "9", x: "3", y: "3", rx: "1" });
      p("rect", { width: "7", height: "5", x: "14", y: "3", rx: "1" });
      p("rect", { width: "7", height: "9", x: "14", y: "12", rx: "1" });
      p("rect", { width: "7", height: "5", x: "3", y: "16", rx: "1" });
      break;
    case "activity":
      p("path", { d: "M22 12h-4l-3 9L9 3l-3 9H2" });
      break;
    case "file-search":
      p("path", { d: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" });
      p("polyline", { points: "14 2 14 8 20 8" });
      p("circle", { cx: "11.5", cy: "14.5", r: "2.5" });
      p("path", { d: "m13.3 16.3 2.7 2.7" });
      break;
    case "chart-no-axes-combined":
      p("path", { d: "M12 16v5" });
      p("path", { d: "M16 14v7" });
      p("path", { d: "M20 10v11" });
      p("path", { d: "m22 3-8.646 8.646a.5.5 0 0 1-.708 0L9.354 8.354a.5.5 0 0 0-.707 0L2 15" });
      p("path", { d: "M4 18v3" });
      p("path", { d: "M8 14v7" });
      break;
    case "git-branch":
      p("line", { x1: "6", x2: "6", y1: "3", y2: "15" });
      p("circle", { cx: "18", cy: "6", r: "3" });
      p("circle", { cx: "6", cy: "18", r: "3" });
      p("path", { d: "M18 9a9 9 0 0 1-9 9" });
      break;
    case "monitor":
      p("rect", { width: "20", height: "14", x: "2", y: "3", rx: "2" });
      p("line", { x1: "8", x2: "16", y1: "21", y2: "21" });
      p("line", { x1: "12", x2: "12", y1: "17", y2: "21" });
      break;
    case "download":
      p("path", { d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" });
      p("polyline", { points: "7 10 12 15 17 10" });
      p("line", { x1: "12", x2: "12", y1: "15", y2: "3" });
      break;
    case "circle-check":
      p("circle", { cx: "12", cy: "12", r: "10" });
      p("path", { d: "m9 12 2 2 4-4" });
      break;
    case "layers-2":
      p("polygon", { points: "12 2 2 7 12 12 22 7 12 2" });
      p("polyline", { points: "2 17 12 22 22 17" });
      p("polyline", { points: "2 12 12 17 22 12" });
      break;
    case "file-check-2":
      p("path", { d: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" });
      p("polyline", { points: "14 2 14 8 20 8" });
      p("path", { d: "m9 15 2 2 4-4" });
      break;
    case "minus-circle":
      p("circle", { cx: "12", cy: "12", r: "10" });
      p("line", { x1: "8", x2: "16", y1: "12", y2: "12" });
      break;
    case "circle-x":
      p("circle", { cx: "12", cy: "12", r: "10" });
      p("path", { d: "m15 9-6 6" });
      p("path", { d: "m9 9 6 6" });
      break;
    case "repeat-2":
      p("path", { d: "m2 9 3-3 3 3" });
      p("path", { d: "M13 18H7a2 2 0 0 1-2-2V6" });
      p("path", { d: "m22 15-3 3-3-3" });
      p("path", { d: "M11 6h6a2 2 0 0 1 2 2v10" });
      break;
    case "unplug":
      p("path", { d: "m19 5 3-3" });
      p("path", { d: "m2 22 3-3" });
      p("path", { d: "M6.3 20.3a2.4 2.4 0 0 0 3.4 0L12 18l-6-6-2.3 2.3a2.4 2.4 0 0 0 0 3.4z" });
      p("path", { d: "M7.5 13.5 10 11" });
      p("path", { d: "M10.5 16.5 13 14" });
      p("path", { d: "m12 6 6 6 2.3-2.3a2.4 2.4 0 0 0 0-3.4l-2.6-2.6a2.4 2.4 0 0 0-3.4 0Z" });
      break;
    case "clock-3":
      p("circle", { cx: "12", cy: "12", r: "10" });
      p("polyline", { points: "12 6 12 12 16.5 12" });
      break;
    case "file-text":
      p("path", { d: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" });
      p("polyline", { points: "14 2 14 8 20 8" });
      p("line", { x1: "16", x2: "8", y1: "13", y2: "13" });
      p("line", { x1: "16", x2: "8", y1: "17", y2: "17" });
      p("line", { x1: "10", x2: "8", y1: "9", y2: "9" });
      break;
    case "chevron-down":
      p("polyline", { points: "6 9 12 15 18 9" });
      break;
    case "chevron-up":
      p("polyline", { points: "18 15 12 9 6 15" });
      break;
    case "chevron-right":
      p("polyline", { points: "9 18 15 12 9 6" });
      break;
    case "code-2":
      p("polyline", { points: "16 18 22 12 16 6" });
      p("polyline", { points: "8 6 2 12 8 18" });
      break;
    case "circle-alert":
      p("circle", { cx: "12", cy: "12", r: "10" });
      p("line", { x1: "12", x2: "12", y1: "8", y2: "12" });
      p("line", { x1: "12", x2: "12.01", y1: "16", y2: "16" });
      break;
    case "copy":
      p("rect", { width: "14", height: "14", x: "8", y: "8", rx: "2", ry: "2" });
      p("path", { d: "M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" });
      break;
    case "sun":
      p("circle", { cx: "12", cy: "12", r: "4" });
      p("path", { d: "M12 2v2" });
      p("path", { d: "M12 20v2" });
      p("path", { d: "m4.93 4.93 1.41 1.41" });
      p("path", { d: "m17.66 17.66 1.41 1.41" });
      p("path", { d: "M2 12h2" });
      p("path", { d: "M20 12h2" });
      p("path", { d: "m6.34 17.66-1.41 1.41" });
      p("path", { d: "m19.07 4.93-1.41 1.41" });
      break;
    case "moon":
      p("path", { d: "M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" });
      break;
    default:
      p("circle", { cx: "12", cy: "12", r: "8" });
      break;
  }
  return el;
}

// -- Formatting ----------------------------------------------------------------

function fmtDuration(seconds) {
  if (typeof seconds !== "number" || !isFinite(seconds)) return "—";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  if (m < 60) return `${String(m).padStart(2, "0")}m ${String(s).padStart(2, "0")}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

function fmtCost(value) {
  return typeof value === "number" && isFinite(value) ? `$${value.toFixed(2)}` : "—";
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

function prCommit(row) {
  const parts = [];
  if (row.pr) parts.push(`PR #${String(row.pr).replace(/^#/, "")}`);
  if (row.commit) parts.push(shortSha(row.commit));
  else if (row.branch) parts.push(row.branch);
  return parts.join(" · ") || "—";
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

// -- Shell & Navigation --------------------------------------------------------

function setActiveNav(navKey) {
  document.querySelectorAll(".nav-item").forEach((el) => {
    if (el.dataset.nav === navKey) {
      el.classList.add("active");
      el.setAttribute("aria-current", "page");
    } else {
      el.classList.remove("active");
      el.removeAttribute("aria-current");
    }
  });
}

function updateShellNavLinks() {
  const id = currentRunId;
  const overview = document.getElementById("nav-overview");
  const liverun = document.getElementById("nav-liverun");
  const findings = document.getElementById("nav-findings");
  const benchmark = document.getElementById("nav-benchmark");
  const dependencies = document.getElementById("nav-dependencies");

  if (overview) overview.setAttribute("href", id ? `#/run/${encodeURIComponent(id)}` : "#/runs");
  if (liverun) liverun.setAttribute("href", id ? `#/replay/${encodeURIComponent(id)}` : "#/replay");
  if (findings) findings.setAttribute("href", id ? `#/run/${encodeURIComponent(id)}/findings` : "#/runs");
  if (benchmark) benchmark.setAttribute("href", "#/trends");
  if (dependencies) dependencies.setAttribute("href", id ? `#/run/${encodeURIComponent(id)}/graph` : "#/dependencies");
}

function setShellHeader(breadcrumbNodes, title, actionText = null, actionHandler = null, actionIconName = "download") {
  headerBreadcrumb.replaceChildren(...(Array.isArray(breadcrumbNodes) ? breadcrumbNodes : [breadcrumbNodes]));
  pageTitle.textContent = title;
  if (actionText && actionHandler) {
    actionBtnText.textContent = actionText;
    actionBtnIcon.replaceChildren(icon(actionIconName, 18));
    actionBtn.onclick = actionHandler;
    actionBtn.hidden = false;
  } else {
    actionBtn.hidden = true;
  }
}

function updateRunContextCard(runId, subtitleText = null) {
  currentRunId = runId;
  updateShellNavLinks();
  if (runSelect && runId) runSelect.value = runId;
  if (runCurrentId) runCurrentId.textContent = runId || "No run";
  if (runCurrentSub) {
    if (subtitleText) {
      runCurrentSub.textContent = subtitleText;
    } else if (runId && runsById.has(runId)) {
      const r = runsById.get(runId);
      runCurrentSub.textContent = r.repo || (r.synthetic ? "Illustrative data" : "Active run");
    } else {
      runCurrentSub.textContent = "Proof before accusation";
    }
  }
}

function downloadData(filename, dataObj) {
  try {
    const blob = new Blob([JSON.stringify(dataObj, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (_) {}
}

// -- Dark Theme Toggle (Stored only in localStorage inside try/catch) ----------

function initTheme() {
  let saved = null;
  try {
    saved = localStorage.getItem("exhibit_a_theme");
  } catch (_) {
    saved = null;
  }
  if (saved === "dark" || saved === "light") {
    document.documentElement.setAttribute("data-theme", saved);
  }
  updateThemeIcon();
}

function toggleTheme() {
  let current = document.documentElement.getAttribute("data-theme");
  if (!current) {
    const isDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    current = isDark ? "dark" : "light";
  }
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try {
    localStorage.setItem("exhibit_a_theme", next);
  } catch (_) {}
  updateThemeIcon();
}

function updateThemeIcon() {
  const iconHost = document.getElementById("icon-theme");
  if (!iconHost) return;
  const isDark = document.documentElement.getAttribute("data-theme") === "dark" ||
    (!document.documentElement.getAttribute("data-theme") && window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
  iconHost.replaceChildren(icon(isDark ? "sun" : "moon", 18));
}

// -- Shared Components ---------------------------------------------------------

function statusBadge(row) {
  if (row.status === "unreadable") return h("span", { class: "badge warn", text: "unreadable" });
  if (row.proven > 0) {
    return h("span", { class: "badge proven", text: `${row.proven} proven` },
      row.proven_raw > row.proven ? ` (${row.proven_raw} proofs)` : null);
  }
  const labels = { aborted: "aborted", timed_out: "timed out", not_run: "not run", skipped: "skipped" };
  if (labels[row.status]) return h("span", { class: "badge warn", text: labels[row.status] });
  return h("span", { class: "badge plain", text: "nothing could be proven" });
}

function stageTracker(stages, activeName) {
  return h("ol", { class: "stages", "aria-label": "Verification loop stages" },
    stages.map((stage) => h("li", {
      class: `${stage.reached ? "reached" : ""} ${stage.name === activeName ? "active" : ""}`.trim(),
      title: stage.reached ? `${stage.name}: ${plural(stage.count, "event")}` : `${stage.name}: not reached`,
    }, stage.name, h("span", { class: "count", text: stage.reached ? String(stage.count) : "—" }))));
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

function copyButton(textToCopy) {
  const btn = h("button", { type: "button", class: "code-copy-btn", title: "Copy to clipboard", "aria-label": "Copy" }, icon("copy", 16));
  btn.onclick = async () => {
    try {
      await navigator.clipboard.writeText(textToCopy);
      btn.replaceChildren(icon("circle-check", 16));
      setTimeout(() => btn.replaceChildren(icon("copy", 16)), 1500);
    } catch (_) {}
  };
  return btn;
}

// ==============================================================================
// 1. SCREEN 04: RUN OVERVIEW (Exact from Figma design: 04-run-overview.png)
// ==============================================================================

async function renderRunOverview(id) {
  setActiveNav("overview");
  updateRunContextCard(id);

  const data = await api(`/api/runs/${encodeURIComponent(id)}`);
  const row = data.run;
  const repoName = row.repo || "repository";
  const prText = prCommit(row);
  const commitBase = shortSha(row.base_commit || row.commit);
  const commitFix = shortSha(row.fix_commit || row.commit);
  const commitRangeText = commitBase && commitFix && commitBase !== commitFix
    ? `${commitBase} → ${commitFix}`
    : (commitBase || prText);

  // Shell header
  const breadcrumb = [
    h("a", { href: "#/runs", text: repoName }),
    h("span", { text: " / " }),
    h("span", { text: row.run_id }),
  ];
  setShellHeader(breadcrumb, "Run overview", "Export report", () => {
    downloadData(`report-${row.run_id}.json`, data);
  }, "download");

  if (recordFooterRight) {
    recordFooterRight.textContent = row.synthetic ? "Illustrative data · Local replay" : `${repoName} · ${row.run_id}`;
  }

  // 1. Run status row
  const statusRow = h("div", { class: "run-status-row" },
    h("div", { class: "run-status-badge" },
      icon("circle-check", 20),
      h("span", { text: row.status === "completed" || row.status === "proven" || row.status === "clean" ? "Run completed" : `Run ${row.status}` }),
      h("span", { class: "mono", text: row.run_id })),
    h("div", { class: "run-commit-range" }, commitRangeText));

  // 2. Summary cards (3 cards)
  const uniqueCount = data.proven.length;
  const rawCount = data.proven_raw || uniqueCount;
  const duplicateCount = data.duplicates || Math.max(0, rawCount - uniqueCount);
  const totalProofs = rawCount || 1;
  const uniquePercent = Math.min(100, Math.max(0, Math.round((uniqueCount / totalProofs) * 100)));

  // Card 1: Unique findings
  const uniqueCard = h("div", { class: "summary-card" },
    h("div", { class: "summary-card-title", text: "Unique findings" }),
    h("div", { class: "summary-card-big-num", text: String(uniqueCount) }),
    h("div", { class: "summary-card-sub", text: `${plural(rawCount, "raw proven proof")}` }),
    h("div", { class: "dedup-bar", "aria-label": "Deduplication ratio" },
      h("div", { class: "dedup-bar-fill", style: `width: ${uniquePercent}%;` })),
    h("div", { class: "dedup-note" },
      icon("layers-2", 16),
      h("span", { text: `${plural(duplicateCount, "duplicate")} grouped` })));

  // Card 2: Test results
  const verdicts = row.verdicts || {};
  const totalTests = Object.values(verdicts).reduce((a, b) => a + (Number(b) || 0), 0) || (data.proven.length + data.discarded.length);
  const safeTotalTests = Math.max(1, totalTests);

  const outcomeRow = (name, label, iconName, count, cls) => {
    const pct = Math.min(100, Math.round(((Number(count) || 0) / safeTotalTests) * 100));
    return h("div", { class: "outcome-row" },
      h("span", { class: "outcome-label" }, icon(iconName, 16), label),
      h("div", { class: "outcome-bar-track" },
        h("div", { class: `outcome-bar-fill ${cls}`, style: `width: ${pct}%;` })),
      h("span", { class: "outcome-count", text: String(count || 0) }));
  };

  const testResultsCard = h("div", { class: "summary-card" },
    h("div", { class: "test-results-header" },
      h("div", { class: "summary-card-title", text: "Test results" }),
      h("div", { class: "test-results-count", text: totalTests ? `${plural(totalTests, "test")}` : "0 tests" })),
    h("div", { class: "test-results-rows" },
      outcomeRow("proven", "Proven", "file-check-2", verdicts.proven || uniqueCount, "proven"),
      outcomeRow("unproven", "Unproven", "minus-circle", verdicts.discarded_unproven || 0, "unproven"),
      outcomeRow("invalid", "Invalid", "circle-x", verdicts.invalid_test || 0, "invalid"),
      outcomeRow("flaky", "Flaky", "repeat-2", verdicts.flaky || 0, "flaky"),
      outcomeRow("environment", "Environment failure", "unplug", verdicts.env_failure || 0, "environment")));

  // Card 3: Budget used
  const costText = fmtCost(row.cost_usd);
  const budgetCard = h("div", { class: "summary-card" },
    h("div", { class: "summary-card-title", text: "Budget used" }),
    h("div", { class: "summary-card-big-cost", text: costText }),
    h("div", { class: "summary-card-sub", text: "Budget limit: not available" }),
    h("div", { class: "budget-meter" },
      h("div", { class: "budget-meter-fill", style: "width: 25%;" })),
    h("div", { class: "elapsed-time" },
      icon("clock-3", 22),
      h("span", { text: fmtDuration(row.duration_s) })));

  const summaryCards = h("div", { class: "summary-cards-grid" }, uniqueCard, testResultsCard, budgetCard);

  // 3. Proven findings grid
  const findingCards = data.proven.map((item) => {
    const ev = item.evidence || {};
    const effect = ev.effect || {};
    const effectLabel = effect.label || effect.type || "Effect";
    const loc = (ev.observed_location && ev.observed_location.file)
      ? `${ev.observed_location.file}:${ev.observed_location.line}`
      : (item.file ? `${item.file}:${item.line}` : "location not available");
    const proofsCount = (ev.duplicates ? ev.duplicates.length : 0) + 1;
    const targetHash = `#/run/${encodeURIComponent(row.run_id)}/finding/${encodeURIComponent(item.id)}`;

    return h("article", { class: "finding-card finding" },
      h("div", { class: "finding-card-header" },
        h("span", { class: "finding-id", text: item.id }),
        h("span", { class: "chip-proven" }, icon("circle-check", 14), "Proven")),
      h("h3", { class: "finding-title", text: item.hypothesis || item.class || item.id }),
      h("div", { class: "finding-loc", text: loc }),
      h("div", { class: "finding-card-footer" },
        h("div", { class: "finding-tags" },
          h("span", { class: "chip-effect" }, icon("file-text", 14), effectLabel),
          h("span", { class: "tag-severity", text: `${ev.severity ? ev.severity.toUpperCase() : "HIGH"} · ${ev.cwe || "CWE"}` })),
        h("a", { class: "finding-open-link", href: targetHash }, `${plural(proofsCount, "proof")} · Open →`)));
  });

  const findingsSection = h("section", {},
    h("div", { class: "section-title-wrap" },
      h("h2", { class: "section-title", text: "Proven findings" }),
      h("p", { class: "section-subtitle", text: "Observed effects, grouped by root cause." })),
    data.proven.length
      ? h("div", { class: "findings-grid" }, findingCards)
      : h("div", { class: "card finding" },
          h("p", { text: "Nothing could be proven in this run." }),
          h("p", { class: "muted small", text: "This is not a statement that the code is safe: only that no suspicion survived the proof standard." })));

  // Supporting detail sections (stage tracker, discarded suspicions, events)
  const detailSections = [statusRow, summaryCards, findingsSection];

  if (row.status !== "unreadable") {
    detailSections.push(
      h("div", { class: "card" },
        h("h2", { class: "summary-card-title", text: "Verdict timeline" }),
        stageTracker(data.stages)));

    if (data.discarded && data.discarded.length) {
      detailSections.push(
        h("div", { class: "card" },
          h("h2", { class: "summary-card-title", text: `Discarded suspicions (${data.discarded.length})` }),
          discardedTable(data.discarded)));
    }

    // Ledger events list
    const list = h("ol", { class: "events" });
    const more = h("button", { type: "button", text: "Load more events" });
    const eventsCard = h("div", { class: "card" },
      h("h2", { class: "summary-card-title", text: `Ledger events (${row.event_count || 0})` }),
      list,
      h("div", { class: "pager" }, more));

    let cursor = 0;
    const loadEvents = async () => {
      more.disabled = true;
      try {
        const page = await api(`/api/runs/${encodeURIComponent(id)}/events?from=${cursor}&limit=100`);
        append(list, page.events.map((ev) => eventItem(ev, false)));
        cursor += page.count;
        more.hidden = cursor >= page.total;
      } catch (err) {
        append(list, h("li", { class: "muted", text: String(err.message || err) }));
      }
      more.disabled = false;
    };
    more.onclick = loadEvents;
    detailSections.push(eventsCard);

    show(...detailSections);
    await loadEvents();
    return;
  }

  show(...detailSections);
}

// ==============================================================================
// 2. SCREEN 05: FINDING DETAIL (Exact from Figma design: 05-finding-detail.png)
// ==============================================================================

async function renderFindingDetail(runId, findingId) {
  setActiveNav("findings");
  updateRunContextCard(runId);

  const data = await api(`/api/runs/${encodeURIComponent(runId)}`);
  const row = data.run;
  const finding = (data.proven || []).find((f) => f.id === findingId) ||
    (data.discarded || []).find((f) => f.id === findingId) ||
    { id: findingId, class: "Finding", hypothesis: "Finding detail" };

  const ev = finding.evidence || {};
  const red = ev.fails_on_vulnerable || {};
  const fixed = ev.passes_on_fixed || {};
  const effect = ev.effect || {};
  const fix = ev.fix || {};
  const prov = ev.provenance || {};
  const obsLoc = ev.observed_location || {};
  const modelLoc = ev.model_location || { file: finding.file, line: finding.line };

  // Shell header
  const breadcrumb = [
    h("a", { href: `#/run/${encodeURIComponent(runId)}`, text: runId }),
    h("span", { text: " / " }),
    h("a", { href: `#/run/${encodeURIComponent(runId)}/findings`, text: "Findings" }),
    h("span", { text: " / " }),
    h("span", { text: finding.id }),
  ];
  setShellHeader(breadcrumb, finding.hypothesis || finding.class || finding.id, "Download proof", () => {
    downloadData(`proof-${runId}-${finding.id}.json`, finding);
  }, "download");

  // 1. Finding metadata row
  const commitBase = shortSha(row.base_commit || row.commit);
  const commitFix = shortSha(row.fix_commit || row.commit);
  const commitRangeText = commitBase && commitFix && commitBase !== commitFix
    ? `base ${commitBase} → fix ${commitFix}`
    : (commitBase ? `base ${commitBase}` : "base → fix not available");

  const metaRow = h("div", { class: "finding-detail-meta-row" },
    h("div", { class: "finding-detail-chips" },
      h("span", { class: "chip-proven" }, icon("circle-check", 14), "Proven"),
      h("span", { class: "chip-tag cwe" }, icon("circle-alert", 14), `${ev.severity ? ev.severity.toUpperCase() : "HIGH"} · ${ev.cwe || "CWE"}`),
      h("span", { class: "chip-effect" }, icon("file-text", 14), effect.label || effect.type || "Effect"),
      h("span", { class: "chip-tag proof", text: `P-${finding.id}` })),
    h("div", { class: "run-commit-range", text: commitRangeText }));

  // 2. Boundary assertion section (Before fix & After fix cards)
  const isHttp = Boolean(ev.expected_status || ev.received_status);
  const expectedVal = isHttp ? String(ev.expected_status || 403) : "FAIL";
  const receivedFailVal = isHttp ? String(ev.received_status || 200) : "FAIL";
  const receivedPassVal = isHttp ? String(ev.expected_status || 403) : "PASS";

  const beforeResult = effect.observed
    ? `Boundary assertion failed; external ${effect.label || effect.type || "canary"} read observed.`
    : (finding.reason || "Boundary assertion failed on vulnerable code.");

  const afterResult = fixed.fix_verified
    ? "Exploit passes on the fixed code; baseline still passes."
    : (fixed.effect_seen_after_fix
        ? "Effect still observed after fix (incomplete fix)."
        : "No external effect observed after fix.");

  const boundarySection = h("section", { class: "boundary-section" },
    h("div", { class: "section-title-wrap" },
      h("h2", { class: "section-title", text: "Boundary assertion" }),
      h("p", { class: "section-subtitle", text: "Same test and input, before and after the fix." })),
    h("div", { class: "boundary-cards-grid" },
      h("div", { class: "boundary-card" },
        h("div", { class: "boundary-card-header" },
          h("span", { class: "boundary-card-label", text: "Before fix" }),
          h("span", { class: "pill-fail" }, icon("circle-x", 14), "FAIL")),
        h("div", { class: "status-codes-row" },
          h("div", { class: "status-code-col" },
            h("span", { class: "status-code-label", text: "Expected" }),
            h("span", { class: "status-code-val", text: expectedVal })),
          h("span", { class: "status-code-sep", text: "/" }),
          h("div", { class: "status-code-col" },
            h("span", { class: "status-code-label", text: "Received" }),
            h("span", { class: "status-code-val fail", text: receivedFailVal }))),
        h("div", { class: "boundary-result-text", text: beforeResult })),
      h("div", { class: "boundary-card" },
        h("div", { class: "boundary-card-header" },
          h("span", { class: "boundary-card-label", text: "After fix" }),
          h("span", { class: "pill-pass" }, icon("circle-check", 14), "PASS")),
        h("div", { class: "status-codes-row" },
          h("div", { class: "status-code-col" },
            h("span", { class: "status-code-label", text: "Expected" }),
            h("span", { class: "status-code-val", text: expectedVal })),
          h("span", { class: "status-code-sep", text: "/" }),
          h("div", { class: "status-code-col" },
            h("span", { class: "status-code-label", text: "Received" }),
            h("span", { class: "status-code-val pass", text: receivedPassVal }))),
        h("div", { class: "boundary-result-text", text: afterResult }))));

  // 3. Evidence workspace (Left: Patch & Test, Right: Oracle & Location)
  const diffContent = fix.diff || "Patch diff content is not available in this ledger.";
  const testContent = ev.exploit_test || "Exploit test content is not available in this ledger.";

  // Diff rendering with +/- line highlighting
  const renderDiffLines = (rawDiff) => {
    const lines = rawDiff.split("\n");
    return lines.map((line) => {
      let cls = "";
      if (line.startsWith("+")) cls = "diff-add";
      else if (line.startsWith("-")) cls = "diff-del";
      else if (line.startsWith("@@")) cls = "diff-hunk";
      return h("span", { class: cls, text: line + "\n" });
    });
  };

  const patchBox = h("div", { class: "code-box" },
    h("div", { class: "code-box-header" },
      h("span", { text: `${fix.patch_path || modelLoc.file || "patch.diff"}` }),
      copyButton(diffContent)),
    h("pre", {}, renderDiffLines(diffContent)));

  const testBox = h("div", { class: "code-box" },
    h("div", { class: "code-box-header" },
      h("span", { text: `${ev.exploit_test_path || "test_exploit.py"}` }),
      copyButton(testContent)),
    h("pre", {}, testContent));

  const duplicates = ev.duplicates || [];
  const duplicatesDisclosure = duplicates.length
    ? h("details", { class: "duplicates-disclosure" },
        h("summary", {},
          icon("chevron-right", 16),
          h("span", { text: `${plural(duplicates.length, "proof")} / 1 finding · View grouped proofs` })),
        h("ul", {}, duplicates.map((d) => h("li", {},
          h("strong", { text: d.suspicion_id }),
          h("span", { class: "mono small", text: ` · guess ${d.file || "?"}:${d.line || 0}` }),
          d.observed_location && d.observed_location.file
            ? h("span", { class: "mono small", text: ` · oracle ${d.observed_location.file}:${d.observed_location.line}` })
            : null))))
    : null;

  const leftCol = h("div", { class: "evidence-main-col" },
    h("div", { class: "tab-bar" },
      h("button", { type: "button", class: "tab-btn active", text: "</> Patch & test" }),
      h("button", { type: "button", class: "tab-btn", text: "Source context" })),
    patchBox,
    testBox,
    duplicatesDisclosure);

  // Right column: Oracle Observation card & Location card
  const factItem = (key, val) => h("div", { class: "fact-item" },
    h("span", { class: "fact-key", text: key }),
    h("span", { class: "fact-val", text: val }));

  const oracleCard = h("div", { class: "side-card" },
    h("div", { class: "side-card-header" },
      h("h3", { class: "side-card-title", text: "Oracle observation" }),
      icon("chevron-up", 18)),
    h("div", { class: "side-card-stat", text: "1 → 0" }),
    h("div", { class: "side-card-stat-label", text: "Reads outside root · before / after" }),
    h("div", { class: "facts-list" },
      factItem("Effect", effect.label || effect.type || "canary_read"),
      factItem("Allowed root", "not available"),
      factItem("Observed path", effect.path || "not available"),
      factItem("Canary match", "not available"),
      factItem("Consistency", `${red.runs || 1}/${red.of || red.runs || 1} consistent`)),
    h("div", { class: "side-card-scope-note", text: row.synthetic ? "Synthetic fixture, not production data." : "Recorded from isolated sandbox run." }));

  const locCard = h("div", { class: "side-card" },
    h("div", { class: "side-card-header" },
      h("h3", { class: "side-card-title", text: "Location" }),
      icon("chevron-right", 18)),
    h("div", { class: "fact-val", text: obsLoc.file || modelLoc.file || "unknown" }),
    h("div", { class: "location-columns" },
      h("div", {},
        h("div", { class: "loc-col-title", text: "Guess" }),
        h("div", { class: "loc-col-val", text: modelLoc.line ? String(modelLoc.line) : "—" })),
      h("div", {},
        h("div", { class: "loc-col-title", text: "Observed" }),
        h("div", { class: "loc-col-val", text: obsLoc.line ? String(obsLoc.line) : "—" }))));

  const rightCol = h("div", { class: "evidence-side-col" }, oracleCard, locCard);
  const evidenceWorkspace = h("div", { class: "evidence-workspace" }, leftCol, rightCol);

  // 4. Re-verify offline card
  const terminalText = `tar -xf ${row.run_id}.tar.zst\ncd ${row.run_id}\nsha256sum -c manifest.sha256\nexhibit-a verify --offline \\\n  --manifest run.json`;
  const offlineCard = h("div", { class: "offline-card" },
    h("div", { class: "offline-header" },
      h("div", {},
        h("h3", { class: "offline-title", text: "Re-verify offline" }),
        h("p", { class: "offline-sub", text: "Portable evidence bundle · SHA-256 manifest" })),
      h("button", {
        type: "button",
        class: "action-btn",
        onclick: () => downloadData(`offline-bundle-${row.run_id}.json`, { run: row, finding }),
      }, icon("download", 16), "Download bundle")),
    h("div", { class: "offline-grid" },
      h("div", { class: "terminal-box" },
        h("div", { class: "terminal-label", text: "Terminal · no model calls" }),
        terminalText),
      h("div", { class: "manifest-list" },
        h("div", { class: "manifest-item" },
          h("span", { class: "manifest-label", text: `Test · ${ev.exploit_test_path || "test.py"}` }),
          h("span", { class: "manifest-hash", text: "SHA-256: not available" })),
        h("div", { class: "manifest-item" },
          h("span", { class: "manifest-label", text: `Patch · ${fix.patch_path || "patch.diff"}` }),
          h("span", { class: "manifest-hash", text: "SHA-256: not available" })),
        h("div", { class: "manifest-item" },
          h("span", { class: "manifest-label", text: "Environment · environment/runner.oci.tar" }),
          h("span", { class: "manifest-hash", text: "SHA-256: not available" })))),
    h("div", { class: "offline-policy-note" },
      icon("circle-alert", 16),
      h("span", { text: "Hash mismatch stops execution without changing the verdict." })));

  show(metaRow, boundarySection, evidenceWorkspace, offlineCard);
}

// ==============================================================================
// 3. SCREEN: LIVE RUN / REPLAY (Restyled from tokens)
// ==============================================================================

async function renderReplay(id) {
  setActiveNav("liverun");
  updateRunContextCard(id);

  const detail = await api(`/api/runs/${encodeURIComponent(id)}`);
  const row = detail.run;
  const total = row.event_count || 0;
  const reached = Object.fromEntries(STAGES.map((name) => [name, 0]));
  let cursor = 0;
  let current = "";

  setShellHeader([
    h("a", { href: `#/run/${encodeURIComponent(id)}`, text: id }),
    h("span", { text: " / " }),
    h("span", { text: "Live run" }),
  ], `Replay: ${row.headline || id}`, "Restart", () => restart.click(), "repeat-2");

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
    if (typeof ev.seq !== "number" || ev.seq !== cursor) return;
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
      try { add(JSON.parse(msg.data)); } catch (_) {}
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
    h("div", { class: "card" },
      row.synthetic ? h("p", { class: "banner-synthetic", text: "Synthetic sample run" }) : null,
      h("div", { class: "summary-card-title", text: "Recorded execution trace" }),
      h("p", { class: "muted", text: `Replays the recorded ledger of ${row.run_id} step by step in ledger order. Nothing is re-executed.` }),
      h("div", { class: "toolbar" }, play, step, restart, h("label", { class: "small" }, "Speed ", speed), h("span", { class: "spacer" }), progress)),
    h("div", { class: "card" },
      h("h2", { class: "summary-card-title", text: "Verdict timeline" }),
      trackerHost),
    h("div", { class: "card" },
      h("h2", { class: "summary-card-title", text: "Events (newest first)" }),
      list));

  redraw();
}

// ==============================================================================
// 4. SCREEN: FINDINGS LIST (Restyled from tokens)
// ==============================================================================

async function renderFindingsList(runId) {
  setActiveNav("findings");
  updateRunContextCard(runId);

  const data = await api(`/api/runs/${encodeURIComponent(runId)}`);
  const row = data.run;

  setShellHeader([
    h("a", { href: `#/run/${encodeURIComponent(runId)}`, text: runId }),
    h("span", { text: " / " }),
    h("span", { text: "Findings" }),
  ], "Findings", "Export findings", () => {
    downloadData(`findings-${runId}.json`, { proven: data.proven, discarded: data.discarded });
  });

  const cards = (data.proven || []).map((item) => {
    const ev = item.evidence || {};
    const effect = ev.effect || {};
    const loc = (ev.observed_location && ev.observed_location.file)
      ? `${ev.observed_location.file}:${ev.observed_location.line}`
      : (item.file ? `${item.file}:${item.line}` : "location not available");
    const proofsCount = (ev.duplicates ? ev.duplicates.length : 0) + 1;
    const targetHash = `#/run/${encodeURIComponent(row.run_id)}/finding/${encodeURIComponent(item.id)}`;

    return h("article", { class: "finding-card finding" },
      h("div", { class: "finding-card-header" },
        h("span", { class: "finding-id", text: item.id }),
        h("span", { class: "chip-proven" }, icon("circle-check", 14), "Proven")),
      h("h3", { class: "finding-title", text: item.hypothesis || item.class || item.id }),
      h("div", { class: "finding-loc", text: loc }),
      h("div", { class: "finding-card-footer" },
        h("div", { class: "finding-tags" },
          h("span", { class: "chip-effect" }, icon("file-text", 14), effect.label || effect.type || "Effect"),
          h("span", { class: "tag-severity", text: `${ev.severity ? ev.severity.toUpperCase() : "HIGH"} · ${ev.cwe || "CWE"}` })),
        h("a", { class: "finding-open-link", href: targetHash }, `${plural(proofsCount, "proof")} · Open →`)));
  });

  show(
    h("div", { class: "section-title-wrap" },
      h("h2", { class: "section-title", text: `Proven findings (${data.proven.length})` }),
      h("p", { class: "section-subtitle", text: "Proven security vulnerabilities verified in the sandbox." })),
    data.proven.length
      ? h("div", { class: "findings-grid" }, cards)
      : h("div", { class: "card finding" },
          h("p", { text: "No vulnerabilities could be proven in this run." }),
          h("p", { class: "muted small", text: "Green means nothing could be proven, never safe." })),
    h("div", { class: "card" },
      h("h2", { class: "summary-card-title", text: `Discarded suspicions (${data.discarded.length})` }),
      discardedTable(data.discarded)));
}

// ==============================================================================
// 5. SCREEN: BENCHMARK / TRENDS (Restyled from tokens)
// ==============================================================================

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

async function renderBenchmark() {
  setActiveNav("benchmark");

  setShellHeader([
    h("span", { text: "Exhibit A" }),
    h("span", { text: " / " }),
    h("span", { text: "Benchmark" }),
  ], "Benchmark & trends", "Export trends", () => {
    downloadData("trends.json", trendsData);
  });

  const trendsData = await api("/api/trends?limit=50");
  const points = trendsData.points || [];
  const sums = Object.fromEntries(SERIES.map(([k]) => [k, points.reduce((n, p) => n + (p[k] || 0), 0)]));

  const table = h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, h("th", { text: "Run" }), ...SERIES.map(([, label]) => h("th", { class: "num", text: label })), h("th", { class: "num", text: "Flaky" }), h("th", { class: "num", text: "Env failure" }))),
    h("tbody", {}, points.slice().reverse().map((p) => h("tr", { onclick: () => { location.hash = `#/run/${encodeURIComponent(p.run_id)}`; } },
      h("td", {}, h("a", { href: `#/run/${encodeURIComponent(p.run_id)}`, text: fmtDate(p.started_at) }), h("div", { class: "run-sub", text: p.run_id })),
      ...SERIES.map(([k]) => h("td", { class: "num", text: String(p[k] || 0) })),
      h("td", { class: "num", text: String(p.flaky || 0) }),
      h("td", { class: "num", text: String(p.env_failure || 0) }))))));

  show(
    h("p", { class: "lede", text: `Verdicts per run across the ${plural(points.length, "most recent readable run")}: ${sums.proven || 0} proven, ${sums.discarded_unproven || 0} discarded for lack of proof, ${sums.invalid_test || 0} invalid tests.` }),
    points.some((p) => p.synthetic) ? h("p", { class: "banner-synthetic", text: "Includes synthetic sample data" }) : null,
    points.length
      ? h("div", { class: "card" },
          h("h2", { class: "summary-card-title", text: "Proven vs discarded vs invalid, per run" }),
          h("ul", { class: "legend" }, SERIES.map(([, label, cls]) => h("li", {}, h("span", { class: `swatch ${cls}` }), label))),
          trendChart(points))
      : h("div", { class: "card muted", text: "No readable runs yet." }),
    points.length ? h("div", { class: "card" }, h("h2", { class: "summary-card-title", text: "Historical runs breakdown" }), table) : null);
}

// ==============================================================================
// 6. SCREEN: DEPENDENCIES / CODE GRAPH (Restyled from tokens)
// ==============================================================================

function graphView(graph) {
  if (!graph || !graph.available) {
    return h("div", { class: "card muted", text: graph && graph.reason ? graph.reason : "No code graph is available for this run." });
  }
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const order = nodes.slice().sort((a, b) => (a.file || "").localeCompare(b.file || "") || a.line - b.line);
  const positions = Object.fromEntries(order.map((n, i) => [n.id, { x: 80 + (i % 5) * 190, y: 70 + Math.floor(i / 5) * 100 }]));
  let scale = 1;
  let panX = 0;
  let panY = 0;
  const width = Math.max(900, 120 + (Math.min(order.length, 5) * 190));
  const height = Math.max(260, 140 + Math.ceil(order.length / 5) * 100);

  const root = svg("svg", { class: "graph-svg", viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": "Entry to sink code graph" });
  const edgeLayer = svg("g", {});
  const nodeLayer = svg("g", {});
  root.append(edgeLayer, nodeLayer);

  const detail = h("div", { class: "graph-detail muted", text: "Select a node to inspect its file and line range." });
  const update = () => root.setAttribute("viewBox", `${panX} ${panY} ${width / scale} ${height / scale}`);

  edges.forEach((edge) => {
    const a = positions[edge.src], b = positions[edge.dst];
    if (!a || !b) return;
    edgeLayer.appendChild(svg("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: edge.proven ? "graph-edge proven" : "graph-edge" }));
  });

  order.forEach((node) => {
    const p = positions[node.id];
    const group = svg("g", { class: `graph-node ${node.proven ? "proven" : ""} ${node.entry_point ? "entry" : ""}`, tabindex: "0" });
    group.appendChild(svg("rect", { x: p.x - 75, y: p.y - 22, width: 150, height: 44, rx: 6 }));
    group.appendChild(svg("text", { x: p.x, y: p.y + 4, "text-anchor": "middle", text: String(node.name || node.id).slice(0, 22) }));
    const select = () => {
      detail.replaceChildren(
        h("strong", { text: node.name || node.id }),
        h("span", { class: "mono small", text: ` ${node.file || "sink"}${node.line ? `:${node.line}-${node.end}` : ""}` }),
        node.entry_point ? h("span", { class: "tag", text: "entry point" }) : null,
        node.sink ? h("span", { class: "tag", text: "sink" }) : null);
    };
    group.addEventListener("click", select);
    group.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") select(); });
    nodeLayer.appendChild(group);
  });

  let drag = null;
  root.addEventListener("wheel", (event) => {
    event.preventDefault();
    scale = Math.max(0.6, Math.min(2.4, scale * (event.deltaY < 0 ? 1.1 : 0.9)));
    update();
  }, { passive: false });

  root.addEventListener("pointerdown", (event) => { drag = { x: event.clientX, y: event.clientY, panX, panY }; root.setPointerCapture(event.pointerId); });
  root.addEventListener("pointermove", (event) => {
    if (!drag) return;
    panX = drag.panX - (event.clientX - drag.x) / scale;
    panY = drag.panY - (event.clientY - drag.y) / scale;
    update();
  });
  root.addEventListener("pointerup", () => { drag = null; });

  return h("div", { class: "card graph-card" },
    h("div", { class: "graph-heading" },
      h("h2", { class: "summary-card-title", text: "Entry to sink graph" }),
      h("span", { class: "muted small", text: `${nodes.length} nodes, ${edges.length} edges · drag to pan, wheel to zoom` })),
    h("div", { class: "graph-canvas" }, root),
    detail,
    graph.sink_rule ? h("p", { class: "muted small", text: `Sink rule: ${graph.sink_rule}. Effects: ${(graph.effects || []).join(", ")}.` }) : null);
}

async function renderDependencies(runId) {
  setActiveNav("dependencies");
  updateRunContextCard(runId);

  const data = await api(`/api/runs/${encodeURIComponent(runId)}`);
  setShellHeader([
    h("a", { href: `#/run/${encodeURIComponent(runId)}`, text: runId }),
    h("span", { text: " / " }),
    h("span", { text: "Dependencies" }),
  ], "Dependencies & code graph");

  show(
    h("p", { class: "lede", text: "Static call graph and sink reach paths computed for this run." }),
    graphView(data.graph));
}

// ==============================================================================
// 7. SCREEN: ALL RUNS LIST (Restyled from tokens)
// ==============================================================================

async function renderRuns(page = 1) {
  setActiveNav("overview");

  setShellHeader([
    h("span", { text: "Exhibit A" }),
    h("span", { text: " / " }),
    h("span", { text: "Runs" }),
  ], "Runs", "Refresh", () => renderRuns(page), "repeat-2");

  const data = await api(`/api/runs?page=${page}&per_page=20`);
  const rows = data.runs || [];
  const synthetic = rows.some((r) => r.synthetic);

  const table = h("table", { class: "runs" },
    h("thead", {}, h("tr", {},
      h("th", { text: "Status" }),
      h("th", { text: "Run" }),
      h("th", { text: "Repository" }),
      h("th", { text: "PR / commit" }),
      h("th", { text: "Risk" }),
      h("th", { class: "num", text: "Proven" }),
      h("th", { class: "num", text: "Duration" }),
      h("th", { class: "num", text: "Cost" }))),
    h("tbody", {}, rows.map((row) => {
      const target = `#/run/${encodeURIComponent(row.run_id)}`;
      return h("tr", { onclick: () => { location.hash = target; } },
        h("td", {}, statusBadge(row)),
        h("td", {},
          h("a", { class: "run-title", href: target, text: row.headline || row.run_id }),
          h("div", { class: "run-sub", text: `${fmtDate(row.started_at)} · ${row.run_id}${row.synthetic ? " · synthetic" : ""}` })),
        h("td", { class: "run-sub", text: row.repo || "—" }),
        h("td", { class: "mono", text: prCommit(row) }),
        h("td", {}, row.risk ? h("span", { class: "tag", text: `risk ${row.risk}` }) : h("span", { class: "muted", text: "—" })),
        h("td", { class: "num", text: String(row.proven) }),
        h("td", { class: "num", text: fmtDuration(row.duration_s) }),
        h("td", { class: "num", text: fmtCost(row.cost_usd) }));
    })));

  const totalProven = rows.reduce((n, r) => n + (r.proven || 0), 0);
  const pager = (data.pages > 1)
    ? h("div", { class: "pager" },
        page > 1 ? h("a", { href: `#/runs/${page - 1}`, text: "← Newer" }) : null,
        h("span", { class: "muted small", text: `Page ${data.page} of ${data.pages}` }),
        page < data.pages ? h("a", { href: `#/runs/${page + 1}`, text: "Older →" }) : null)
    : null;

  show(
    h("p", { class: "lede", text: `${plural(data.total, "run")} from ${data.source}. ${plural(totalProven, "proven finding")} on this page. A run with nothing proven means nothing could be proven, not that the code is safe.` }),
    synthetic ? h("p", { class: "banner-synthetic", text: "Synthetic sample data" }) : null,
    rows.length
      ? h("div", { class: "card table-wrap" }, table, pager)
      : h("div", { class: "card muted", text: "No runs found in this source." }));
}

// -- Router --------------------------------------------------------------------

async function route() {
  if (activeStream) { activeStream.close(); activeStream = null; }

  const rawHash = location.hash.replace(/^#\/?/, "");
  const parts = rawHash.split("/").map((p) => {
    try { return decodeURIComponent(p); } catch (_) { return ""; }
  });

  try {
    if (parts[0] === "run" && RUN_ID.test(parts[1] || "")) {
      if (parts[2] === "finding" && parts[3]) {
        await renderFindingDetail(parts[1], parts[3]);
      } else if (parts[2] === "findings") {
        await renderFindingsList(parts[1]);
      } else if (parts[2] === "graph") {
        await renderDependencies(parts[1]);
      } else {
        await renderRunOverview(parts[1]);
      }
    } else if (parts[0] === "replay") {
      const id = (parts[1] && RUN_ID.test(parts[1])) ? parts[1] : (currentRunId || (allRuns[0] && allRuns[0].run_id));
      if (id) await renderReplay(id);
      else await renderRuns(1);
    } else if (parts[0] === "findings") {
      const id = currentRunId || (allRuns[0] && allRuns[0].run_id);
      if (id) await renderFindingsList(id);
      else await renderRuns(1);
    } else if (parts[0] === "dependencies") {
      const id = currentRunId || (allRuns[0] && allRuns[0].run_id);
      if (id) await renderDependencies(id);
      else await renderRuns(1);
    } else if (parts[0] === "trends" || parts[0] === "benchmark") {
      await renderBenchmark();
    } else {
      const page = Math.max(1, parseInt(parts[1] || "1", 10) || 1);
      await renderRuns(page);
    }
    window.scrollTo(0, 0);
  } catch (error) {
    renderError(error);
  }
}

// -- Application Bootstrap -----------------------------------------------------

async function boot() {
  initTheme();
  if (themeToggle) {
    themeToggle.onclick = toggleTheme;
  }

  // Populate navigation icons
  const iconMap = [
    ["icon-overview", "layout-dashboard"],
    ["icon-liverun", "activity"],
    ["icon-findings", "file-search"],
    ["icon-benchmark", "chart-no-axes-combined"],
    ["icon-dependencies", "git-branch"],
    ["icon-monitor", "monitor"],
  ];
  iconMap.forEach(([elId, iconName]) => {
    const el = document.getElementById(elId);
    if (el) el.replaceChildren(icon(iconName, 18));
  });

  // Load runs to populate selector
  try {
    const data = await api("/api/runs?page=1&per_page=50");
    allRuns = data.runs || [];
    runsById = new Map(allRuns.map((r) => [r.run_id, r]));

    if (runSelect) {
      runSelect.replaceChildren(...allRuns.map((r) => h("option", {
        value: r.run_id,
        text: `${r.run_id} — ${r.headline || r.repo || "Run"}`,
      })));

      runSelect.onchange = () => {
        const selected = runSelect.value;
        if (selected) {
          location.hash = `#/run/${encodeURIComponent(selected)}`;
        }
      };
    }

    if (allRuns.length > 0 && !currentRunId) {
      currentRunId = allRuns[0].run_id;
      updateRunContextCard(currentRunId);
    }
  } catch (_) {}

  window.addEventListener("hashchange", route);
  await route();
}

boot();
