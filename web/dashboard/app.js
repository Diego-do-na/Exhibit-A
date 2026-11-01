/* Exhibit A dashboard client. Plain JavaScript, no build step, no CDN.
 *
 * Every string shown here comes from a ledger or from GitHub and is
 * untrusted. It reaches the page only through textContent / createTextNode
 * (via h() below); innerHTML is never used. Links are limited to internal
 * "#/" routes and https://github.com/ URLs.
 *
 * Numbers are never invented: when the API has no value, the UI says
 * "not available". A run with nothing proven means nothing could be proven,
 * never that the code is safe.
 */
"use strict";

const STAGES = ["BASELINE", "SUSPECT", "EXPLOIT", "RUN", "VERDICT", "FIX", "VERIFY", "PACKAGE"];
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const REPO_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const SERIES = [
  ["proven", "Proven", "s1"],
  ["discarded_unproven", "Discarded (unproven)", "s2"],
  ["invalid_test", "Invalid test", "s3"],
];
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const NA = "not available";
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
const envBranch = document.getElementById("env-branch");

const state = {
  runs: [],
  runsById: new Map(),
  currentRunId: null,
  sourceLabel: "",
  teardown: [], // callbacks run before the next route renders (streams, animation loops)
  // Aborted when the next navigation starts, so a slow, stale render never paints over
  // the view the user navigated to.
  routeAbort: new AbortController(),
};

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

// The server's CSP (style-src 'self') blocks style="" attributes, so declarations
// from code (bar widths) are applied through the CSSOM, which the CSP allows.
function applyStyle(el, css) {
  for (const decl of css.split(";")) {
    const i = decl.indexOf(":");
    if (i < 1) continue;
    el.style.setProperty(decl.slice(0, i).trim(), decl.slice(i + 1).trim());
  }
}

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") el.className = value;
    else if (key === "text") el.textContent = String(value);
    else if (key === "href") el.setAttribute("href", safeHref(value));
    else if (key === "style") applyStyle(el, String(value));
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

function onTeardown(fn) {
  state.teardown.push(fn);
}

function runTeardown() {
  const pending = state.teardown.splice(0);
  for (const fn of pending) {
    try { fn(); } catch (_) { /* a failed cleanup must not block navigation */ }
  }
}

// -- Lucide-style SVG icons (paths drawn here, no icon package) ----------------

function icon(name, size = 18, cls = "") {
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
    class: cls || null,
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
    case "check":
      p("path", { d: "M20 6 9 17l-5-5" });
      break;
    case "house":
      p("path", { d: "M15 21v-8a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v8" });
      p("path", { d: "M3 10a2 2 0 0 1 .709-1.528l7-5.999a2 2 0 0 1 2.582 0l7 5.999A2 2 0 0 1 21 10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" });
      break;
    case "list":
      p("path", { d: "M3 5h.01" });
      p("path", { d: "M3 12h.01" });
      p("path", { d: "M3 19h.01" });
      p("path", { d: "M8 5h13" });
      p("path", { d: "M8 12h13" });
      p("path", { d: "M8 19h13" });
      break;
    case "chevrons-up-down":
      p("path", { d: "m7 15 5 5 5-5" });
      p("path", { d: "m7 9 5-5 5 5" });
      break;
    case "git-pull-request":
      p("circle", { cx: "18", cy: "18", r: "3" });
      p("circle", { cx: "6", cy: "6", r: "3" });
      p("path", { d: "M13 6h3a2 2 0 0 1 2 2v7" });
      p("line", { x1: "6", x2: "6", y1: "9", y2: "21" });
      break;
    case "search":
      p("circle", { cx: "11", cy: "11", r: "8" });
      p("path", { d: "m21 21-4.3-4.3" });
      break;
    case "x":
      p("path", { d: "M18 6 6 18" });
      p("path", { d: "m6 6 12 12" });
      break;
    case "crosshair":
      p("circle", { cx: "12", cy: "12", r: "10" });
      p("line", { x1: "22", x2: "18", y1: "12", y2: "12" });
      p("line", { x1: "6", x2: "2", y1: "12", y2: "12" });
      p("line", { x1: "12", x2: "12", y1: "6", y2: "2" });
      p("line", { x1: "12", x2: "12", y1: "22", y2: "18" });
      break;
    case "triangle-alert":
      p("path", { d: "m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3" });
      p("path", { d: "M12 9v4" });
      p("path", { d: "M12 17h.01" });
      break;
    case "shield-check":
      p("path", { d: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" });
      p("path", { d: "m9 12 2 2 4-4" });
      break;
    case "coins":
      p("circle", { cx: "8", cy: "8", r: "6" });
      p("path", { d: "M18.09 10.37A6 6 0 1 1 10.34 18" });
      p("path", { d: "M7 6h1v4" });
      p("path", { d: "m16.71 13.88.7.71-2.82 2.82" });
      break;
    case "network":
      p("rect", { x: "16", y: "16", width: "6", height: "6", rx: "1" });
      p("rect", { x: "2", y: "16", width: "6", height: "6", rx: "1" });
      p("rect", { x: "9", y: "2", width: "6", height: "6", rx: "1" });
      p("path", { d: "M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3" });
      p("path", { d: "M12 12V8" });
      break;
    case "maximize":
      p("path", { d: "M8 3H5a2 2 0 0 0-2 2v3" });
      p("path", { d: "M21 8V5a2 2 0 0 0-2-2h-3" });
      p("path", { d: "M3 16v3a2 2 0 0 0 2 2h3" });
      p("path", { d: "M16 21h3a2 2 0 0 0 2-2v-3" });
      break;
    case "plus":
      p("path", { d: "M5 12h14" });
      p("path", { d: "M12 5v14" });
      break;
    case "minus":
      p("path", { d: "M5 12h14" });
      break;
    case "arrow-right":
      p("path", { d: "M5 12h14" });
      p("path", { d: "m12 5 7 7-7 7" });
      break;
    default:
      p("circle", { cx: "12", cy: "12", r: "8" });
      break;
  }
  return el;
}

// -- Formatting ----------------------------------------------------------------

function isNum(value) {
  return typeof value === "number" && isFinite(value);
}

function fmtDuration(seconds) {
  if (!isNum(seconds)) return NA;
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  if (m < 60) return `${String(m).padStart(2, "0")}m ${String(s).padStart(2, "0")}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

function fmtCost(value) {
  if (!isNum(value)) return NA;
  if (value === 0) return "$0.00";
  if (value < 0.01) return `$${value.toFixed(4)}`;
  if (value < 10) return `$${value.toFixed(3)}`;
  return `$${value.toFixed(2)}`;
}

function fmtTokens(value) {
  if (!isNum(value)) return NA;
  if (value >= 1e6) return `${(value / 1e6).toFixed(1)}M`;
  if (value >= 1e3) return `${(value / 1e3).toFixed(1)}k`;
  return String(value);
}

function fmtDate(value, withTime = true) {
  const date = new Date(String(value || ""));
  if (isNaN(date.getTime())) return value ? String(value) : NA;
  const opts = withTime
    ? { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }
    : { month: "short", day: "numeric" };
  return date.toLocaleString(undefined, opts);
}

function fmtRelative(value) {
  const date = new Date(String(value || ""));
  if (isNaN(date.getTime())) return NA;
  const days = Math.round((Date.now() - date.getTime()) / 86400000);
  if (days <= 0) return `today, ${fmtDate(value)}`;
  if (days === 1) return `yesterday, ${fmtDate(value, false)}`;
  if (days < 30) return `${days} days ago, ${fmtDate(value, false)}`;
  return fmtDate(value, false);
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

function plural(n, word, many) {
  return `${n} ${n === 1 ? word : (many || `${word}s`)}`;
}

function prLabel(row) {
  const pr = String((row && row.pr) || "").replace(/^#/, "");
  return pr ? `PR #${pr}` : "";
}

function prCommit(row) {
  const parts = [];
  if (row.pr) parts.push(prLabel(row));
  if (row.commit) parts.push(shortSha(row.commit));
  else if (row.branch) parts.push(row.branch);
  return parts.join(" · ") || NA;
}

function repoShort(name) {
  const text = String(name || "").replace(/\s*\(synthetic\)\s*$/, "");
  return text || "unknown repository";
}

const ACRONYMS = { sql: "SQL", cwe: "CWE", url: "URL", xss: "XSS", ssrf: "SSRF", idor: "IDOR", xxe: "XXE", ssti: "SSTI", crlf: "CRLF", dos: "DoS", redos: "ReDoS", http: "HTTP", api: "API", pr: "PR" };

function humanize(value) {
  const text = String(value || "").replace(/_/g, " ").trim();
  if (!text) return "";
  const words = text.split(/\s+/).map((w) => ACRONYMS[w.toLowerCase()] || w);
  const first = words[0];
  words[0] = first === first.toLowerCase() ? first.charAt(0).toUpperCase() + first.slice(1) : first;
  return words.join(" ");
}

function severityOf(evidence) {
  const sev = String((evidence && evidence.severity) || "").toLowerCase();
  return SEVERITY_RANK[sev] ? sev : "";
}

function severityText(evidence) {
  const sev = severityOf(evidence);
  const cwe = evidence && evidence.cwe ? String(evidence.cwe) : "";
  const parts = [sev ? humanize(sev) : "Severity not available"];
  if (cwe) parts.push(cwe);
  return parts.join(" · ");
}

function findingTitle(item) {
  return humanize(item.class) || item.id;
}

function findingLocation(item) {
  const ev = item.evidence || {};
  const obs = ev.observed_location || {};
  if (obs.file) return `${obs.file}${obs.line ? `:${obs.line}` : ""}`;
  if (item.file) return `${item.file}${item.line ? `:${item.line}` : ""}`;
  return "location not available";
}

function pct(part, whole) {
  if (!isNum(part) || !isNum(whole) || whole <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((part / whole) * 100)));
}

// -- API -----------------------------------------------------------------------

class AuthError extends Error {}

async function api(path) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
    signal: state.routeAbort.signal,
  });
  if (response.status === 401) throw new AuthError("not signed in");
  let body = null;
  try { body = await response.json(); } catch (_) { body = null; }
  if (!response.ok) throw new Error((body && typeof body.error === "string") ? body.error : `HTTP ${response.status}`);
  return body;
}

function renderError(error) {
  if (error instanceof AuthError) {
    setShellHeader([{ text: "Exhibit A" }], "Sign in");
    show(h("div", { class: "notice" },
      h("h2", { class: "card-title", text: "Open the one-time link" }),
      h("p", { text: "This dashboard needs the session set by the bootstrap link printed in the terminal where you started it." }),
      h("p", { class: "muted", text: "Each link works once. If it was already used, stop the dashboard and start it again for a new one." })));
    return;
  }
  show(h("div", { class: "notice error" }, h("strong", { text: "Could not load: " }), String(error.message || error)));
}

// -- Shell & navigation --------------------------------------------------------

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

function runHref(id, tail = "") {
  return `#/run/${encodeURIComponent(id)}${tail}`;
}

function updateShellNavLinks() {
  const id = state.currentRunId;
  const links = {
    "nav-overview": id ? runHref(id) : "#/runs",
    "nav-liverun": id ? `#/replay/${encodeURIComponent(id)}` : "#/replay",
    "nav-findings": id ? runHref(id, "/findings") : "#/runs",
    "nav-dependencies": id ? runHref(id, "/graph") : "#/dependencies",
    "nav-benchmark": "#/trends",
  };
  for (const [elId, href] of Object.entries(links)) {
    const el = document.getElementById(elId);
    if (el) el.setAttribute("href", safeHref(href));
  }
}

// crumbs: [{ text, href? }, ...]; the last one is the current page.
function setShellHeader(crumbs, title, actionText = null, actionHandler = null, actionIconName = "download") {
  const nodes = [];
  crumbs.forEach((crumb, i) => {
    if (i > 0) nodes.push(h("span", { class: "crumb-sep", "aria-hidden": "true", text: "/" }));
    const last = i === crumbs.length - 1;
    nodes.push(crumb.href && !last
      ? h("a", { class: "crumb", href: crumb.href, text: crumb.text, title: crumb.text })
      : h("span", { class: `crumb${last ? " crumb-current" : ""}`, text: crumb.text, title: crumb.text, "aria-current": last ? "page" : null }));
  });
  headerBreadcrumb.replaceChildren(...nodes);
  pageTitle.textContent = title;
  pageTitle.title = title;
  document.title = `${title} · Exhibit A`;
  if (actionText && actionHandler) {
    actionBtnText.textContent = actionText;
    actionBtnIcon.replaceChildren(icon(actionIconName, 18));
    actionBtn.onclick = actionHandler;
    actionBtn.hidden = false;
  } else {
    actionBtn.onclick = null;
    actionBtn.hidden = true;
  }
}

function repoIdOf(row) {
  return (row && row.repo_id) || "";
}

function repoCrumb(row) {
  const id = repoIdOf(row);
  const text = repoShort(row && row.repo);
  return id ? { text, href: `#/repo/${encodeURIComponent(id)}` } : { text, href: "#/" };
}

function runCrumb(row) {
  const label = [prLabel(row), row.ledger_run_id || row.run_id].filter(Boolean).join(" · ");
  return { text: label || row.run_id, href: runHref(row.run_id) };
}

function setFooter(text) {
  if (recordFooterRight) recordFooterRight.textContent = text;
}

function updateRunContextCard(runId) {
  state.currentRunId = runId;
  updateShellNavLinks();
  if (runSelect && runId && [...runSelect.options].some((o) => o.value === runId)) runSelect.value = runId;
  const row = runId ? state.runsById.get(runId) : null;
  if (!runId) {
    runCurrentId.textContent = "No run selected";
    runCurrentSub.textContent = "Proof before accusation";
    return;
  }
  const shown = (row && row.ledger_run_id) || runId;
  runCurrentId.textContent = shown;
  runCurrentId.title = runId;
  if (row) {
    const sub = [repoShort(row.repo), prLabel(row)].filter(Boolean).join(" · ");
    runCurrentSub.textContent = row.synthetic ? `${sub} · illustrative` : sub;
    runCurrentSub.title = row.repo || "";
    if (envBranch) envBranch.textContent = row.branch || NA;
  } else {
    runCurrentSub.textContent = "Run not in the first page of the list";
  }
}

function populateRunSelect() {
  if (!runSelect) return;
  const groups = new Map();
  for (const row of state.runs) {
    const key = repoShort(row.repo);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(row);
  }
  const children = [];
  for (const [repo, rows] of groups) {
    children.push(h("optgroup", { label: repo }, rows.map((r) => {
      const status = r.proven ? plural(r.proven, "proven finding") : (r.status === "unreadable" ? "unreadable" : "nothing proven");
      const text = [prLabel(r), r.title || r.headline, status].filter(Boolean).join(" · ");
      return h("option", { value: r.run_id, text });
    })));
  }
  runSelect.replaceChildren(...children);
  runSelect.setAttribute("aria-label", "Current run");
  runSelect.onchange = () => {
    if (runSelect.value) location.hash = runHref(runSelect.value);
  };
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
  } catch (_) { /* downloads can be blocked; nothing to recover */ }
}

// -- Theme toggle (stored only in localStorage, inside try/catch) --------------
// The theme never follows the operating system: light unless the user picks dark.

function initTheme() {
  let saved = null;
  try {
    saved = localStorage.getItem("exhibit_a_theme");
  } catch (_) {
    saved = null;
  }
  document.documentElement.setAttribute("data-theme", saved === "dark" ? "dark" : "light");
  updateThemeIcon();
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try {
    localStorage.setItem("exhibit_a_theme", next);
  } catch (_) { /* storage blocked: the choice lasts for this page only */ }
  updateThemeIcon();
}

function updateThemeIcon() {
  const iconHost = document.getElementById("icon-theme");
  if (!iconHost) return;
  const isDark = document.documentElement.getAttribute("data-theme") === "dark";
  iconHost.replaceChildren(icon(isDark ? "sun" : "moon", 18));
  if (themeToggle) themeToggle.setAttribute("aria-label", isDark ? "Switch to light theme" : "Switch to dark theme");
}

// -- Shared components ---------------------------------------------------------

function statusBadge(row) {
  if (row.status === "unreadable") return h("span", { class: "badge warn", text: "unreadable" });
  if (row.proven > 0) {
    return h("span", { class: "badge proven", text: plural(row.proven, "proven", "proven") });
  }
  const labels = { aborted: "aborted", timed_out: "timed out", not_run: "not run", skipped: "skipped" };
  if (labels[row.status]) return h("span", { class: "badge warn", text: labels[row.status] });
  return h("span", { class: "badge plain", text: "nothing proven" });
}

function stageTracker(stages, activeName) {
  return h("ol", { class: "stages", "aria-label": "Verification loop stages" },
    stages.map((stage) => h("li", {
      class: `${stage.reached ? "reached" : ""} ${stage.name === activeName ? "active" : ""}`.trim(),
      title: stage.reached ? `${stage.name}: ${plural(stage.count, "event")}` : `${stage.name}: not reached`,
    }, stage.name, h("span", { class: "count", text: stage.reached ? String(stage.count) : "–" }))));
}

function discardedTable(items) {
  if (!items.length) return h("p", { class: "muted", text: "No suspicions were discarded." });
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, h("th", { text: "Suspicion" }), h("th", { text: "Verdict" }), h("th", { text: "Location" }), h("th", { text: "Why it was not proven" }))),
    h("tbody", {}, items.map((item) => h("tr", {},
      h("td", {}, h("div", { class: "cell-stack" }, h("strong", { class: "mono", text: item.id }), h("span", { class: "run-sub", text: humanize(item.class) }))),
      h("td", {}, h("span", { class: "badge plain", text: humanize(item.verdict) })),
      h("td", { class: "mono small", text: item.file ? `${item.file}:${item.line}` : NA }),
      h("td", { class: "small", text: item.reason || NA }))))));
}

function eventItem(ev, fresh) {
  return h("li", { class: fresh ? "fresh" : "" },
    h("span", { class: "ts", text: fmtTime(ev.ts) }),
    h("span", { class: "stage", text: ev.stage || ev.type }),
    h("span", { class: "text" }, ev.summary, ev.role ? h("span", { class: "muted small", text: ` · ${ev.role}` }) : null));
}

function copyButton(textToCopy, label = "Copy") {
  const btn = h("button", { type: "button", class: "code-copy-btn", title: label, "aria-label": label }, icon("copy", 16));
  btn.onclick = async () => {
    try {
      await navigator.clipboard.writeText(textToCopy);
      btn.replaceChildren(icon("circle-check", 16));
      setTimeout(() => btn.replaceChildren(icon("copy", 16)), 1500);
    } catch (_) { /* clipboard blocked */ }
  };
  return btn;
}

function emptyState(title, detail) {
  return h("div", { class: "empty" }, h("strong", { text: title }), detail ? h("span", { text: detail }) : null);
}

function nothingProven(scope) {
  return emptyState(`Nothing could be proven in this ${scope}.`,
    "This is not a statement that the code is safe: no suspicion survived the proof standard.");
}

function syntheticBanner(rows) {
  return rows.some((r) => r && r.synthetic)
    ? h("p", { class: "banner-synthetic" }, icon("circle-alert", 14), "Synthetic sample data, not results of real runs")
    : null;
}

function findingCard(row, item) {
  const ev = item.evidence || {};
  const effect = ev.effect || {};
  const sev = severityOf(ev);
  const proofs = ((ev.duplicates || []).length) + 1;
  const target = runHref(row.run_id, `/finding/${encodeURIComponent(item.id)}`);
  return h("article", { class: "finding-card finding" },
    h("div", { class: "finding-card-header" },
      h("span", { class: "finding-id", text: item.id }),
      h("span", { class: "chip-proven" }, icon("file-check-2", 14), "Proven")),
    h("h3", { class: "finding-title", text: findingTitle(item), title: item.hypothesis || null }),
    h("div", { class: "finding-loc", text: findingLocation(item), title: findingLocation(item) }),
    h("div", { class: "finding-card-footer" },
      h("div", { class: "finding-tags" },
        h("span", { class: "chip-effect" }, icon("file-text", 14), effect.label || humanize(effect.type) || "Effect not available"),
        h("span", { class: `tag-severity sev-${sev || "low"}`, text: severityText(ev) })),
      h("a", { class: "finding-open-link", href: target }, `${plural(proofs, "proof")} · Open →`)));
}

// ==============================================================================
// Home: repository overview
// ==============================================================================

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"];

function sparkline(trend) {
  // Proven findings per run, oldest to newest. Bars, not a line: the runs are discrete.
  const width = 160;
  const height = 36;
  const points = trend.slice(-24);
  const max = Math.max(1, ...points.map((p) => p.proven || 0));
  const slot = width / Math.max(points.length, 1);
  const bar = Math.max(2, Math.min(10, slot * 0.62));
  const label = points.length
    ? `Proven findings per run, oldest to newest: ${points.map((p) => p.proven || 0).join(", ")}`
    : "No readable runs";
  const root = svg("svg", { class: "sparkline", viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": label, preserveAspectRatio: "none" });
  root.appendChild(svg("line", { class: "spark-base", x1: 0, x2: width, y1: height - 0.5, y2: height - 0.5 }));
  points.forEach((p, i) => {
    const value = p.proven || 0;
    const barH = value ? Math.max(3, (value / max) * (height - 4)) : 1.5;
    root.appendChild(svg("rect", {
      class: value ? "spark-bar proven" : "spark-bar",
      x: slot * i + (slot - bar) / 2, y: height - barH, width: bar, height: barH, rx: Math.min(1.5, bar / 2),
    }));
  });
  return root;
}

function severityMix(mix, compact = false) {
  const total = SEVERITY_ORDER.reduce((n, k) => n + (mix[k] || 0), 0);
  const bar = h("div", { class: "mix-bar", role: "img", "aria-label": total
    ? `Severity of proven findings: ${SEVERITY_ORDER.filter((k) => mix[k]).map((k) => `${mix[k]} ${k}`).join(", ")}`
    : "No proven findings" });
  if (total) {
    for (const key of SEVERITY_ORDER) {
      if (!mix[key]) continue;
      bar.appendChild(h("span", { class: `mix-seg mix-${key}`, style: `flex-grow: ${mix[key]}` }));
    }
  }
  const legend = compact ? null : h("ul", { class: "mix-legend" },
    SEVERITY_ORDER.filter((k) => mix[k]).map((k) => h("li", {}, h("span", { class: `swatch mix-${k}` }), `${mix[k]} ${k}`)));
  return h("div", { class: "mix" }, bar, total ? legend : h("span", { class: "mix-empty", text: "No proven findings" }));
}

function repoCard(repo, selected) {
  const [owner, ...rest] = repoShort(repo.name).split("/");
  const last = repo.last_run || {};
  return h("a", {
    class: `repo-card${selected ? " selected" : ""}`,
    href: `#/repo/${encodeURIComponent(repo.id)}`,
    "aria-current": selected ? "true" : null,
    "aria-label": `${repoShort(repo.name)}: ${plural(repo.runs, "run")}, ${plural(repo.proven, "proven finding")}`,
  },
    h("div", { class: "repo-card-head" },
      h("div", { class: "repo-name" },
        rest.length ? h("span", { class: "repo-owner", text: `${owner}/` }) : null,
        h("span", { class: "repo-leaf", text: rest.length ? rest.join("/") : owner })),
      repo.synthetic ? h("span", { class: "tag", text: "synthetic" }) : null),
    h("dl", { class: "repo-stats" },
      h("div", {}, h("dt", { text: "Runs" }), h("dd", { text: String(repo.runs) })),
      h("div", {}, h("dt", { text: "Proven" }), h("dd", { class: repo.proven ? "proven" : "", text: String(repo.proven) })),
      h("div", { class: "repo-last" }, h("dt", { text: "Last run" }), h("dd", { text: last.started_at ? fmtRelative(last.started_at) : NA }))),
    h("div", { class: "repo-card-foot" },
      h("div", { class: "repo-trend" }, h("span", { class: "micro-label", text: "Proven per run" }), sparkline(repo.trend || [])),
      h("div", { class: "repo-mix" }, h("span", { class: "micro-label", text: "Risk mix" }), severityMix(repo.severity_mix || {}, true))));
}

function metricTile(label, value, note, cls = "") {
  return h("div", { class: `metric-tile ${cls}`.trim() },
    h("span", { class: "metric-label", text: label }),
    h("span", { class: "metric-value", text: value }),
    note ? h("span", { class: "metric-note", text: note }) : null);
}

function fixStatusChip(status) {
  if (status === "bypassed") return h("span", { class: "badge fail", text: "fix bypassed" });
  if (status === "verified") return h("span", { class: "badge ok", text: "fix verified" });
  return h("span", { class: "badge warn", text: "fix not verified" });
}

function prRow(row) {
  const target = runHref(row.run_id);
  return h("li", { class: "pr-row" },
    h("a", { class: "pr-link", href: target },
      h("span", { class: "pr-number mono", text: prLabel(row) || "no PR" }),
      h("span", { class: "pr-main" },
        h("span", { class: "pr-title", text: row.title || row.headline || row.run_id, title: row.title || null }),
        h("span", { class: "pr-sub", text: `${fmtDate(row.started_at)} · ${shortSha(row.commit) || row.branch || NA}` })),
      h("span", { class: "pr-status" }, statusBadge(row)),
      h("span", { class: "pr-arrow", "aria-hidden": "true" }, icon("chevron-right", 16))));
}

function seriousRow(f) {
  const target = runHref(f.run_id, `/finding/${encodeURIComponent(f.finding_id)}`);
  const sev = f.severity || "";
  return h("li", { class: "serious-row" },
    h("a", { class: "serious-link", href: target },
      h("span", { class: `sev-dot mix-${sev || "unknown"}`, "aria-hidden": "true" }),
      h("span", { class: "serious-main" },
        h("span", { class: "serious-title" },
          h("span", { text: humanize(f.class) || f.finding_id }),
          h("span", { class: `sev sev-${sev || "low"}`, text: ` · ${sev ? humanize(sev) : "Severity not available"}${f.cwe ? ` · ${f.cwe}` : ""}` })),
        h("span", { class: "serious-loc mono", text: `${f.file || NA}${f.line ? `:${f.line}` : ""}` }),
        h("span", { class: "serious-sub", text: `${prLabel(f) || "no PR"}${f.title ? ` · ${f.title}` : ""} · ${f.occurrences > 1 ? `seen in ${f.occurrences} runs` : "seen in 1 run"}` })),
      h("span", { class: "serious-side" }, h("span", { class: "chip-effect small-chip", text: f.effect_label || humanize(f.effect) || NA }), fixStatusChip(f.fix_status))));
}

async function renderHome(repoId) {
  setActiveNav("home");
  const index = await api("/api/repos");
  const repos = index.repos || [];
  if (!repos.length) {
    setShellHeader([{ text: "All repositories" }], "Home");
    show(emptyState("No runs found in this source.", "Run exhibit-a on a pull request, then point the dashboard at its runs folder."));
    return;
  }
  const selected = repos.find((r) => r.id === repoId) || repos[0];
  const detail = await api(`/api/repos/${encodeURIComponent(selected.id)}`);
  const m = detail.metrics || {};
  const name = repoShort(selected.name);
  setShellHeader([{ text: name, href: `#/repo/${encodeURIComponent(selected.id)}` }, { text: "Home" }], name.split("/").pop() || name,
    "Export overview", () => downloadData(`repository-${selected.id}.json`, detail));
  setFooter(`${state.sourceLabel || index.source || "Local replay"} · ${plural(index.runs_considered || 0, "run")} read`);

  const last = selected.last_run || {};
  const lastRunId = last.run_id || "";
  const current = state.runsById.get(state.currentRunId);
  // Keep the sidebar's run views inside the selected repository.
  if (lastRunId && (!current || current.repo_id !== selected.id)) updateRunContextCard(lastRunId);

  const cards = h("section", { class: "section-stack" },
    h("div", { class: "section-head" },
      h("div", { class: "section-title-wrap" },
        h("h2", { class: "section-title", text: "Repositories" }),
        h("p", { class: "section-subtitle", text: `${plural(repos.length, "repository", "repositories")} across ${plural(index.runs_considered || 0, "run")}. Pick one to see its pull requests and findings.` }))),
    h("div", { class: "repo-grid" }, repos.map((r) => repoCard(r, r.id === selected.id))));

  const runsNote = `${plural(m.runs || 0, "run")}${(index.runs_total || 0) > (index.runs_considered || 0) ? ` (newest ${index.runs_considered} of ${index.runs_total} read)` : ""}`;
  const metrics = h("div", { class: "metric-row" },
    metricTile("Proven findings", String(m.proven || 0), `across ${runsNote}`, m.proven ? "is-proven" : ""),
    metricTile("Unique root causes", String(m.root_causes || 0), "same effect, CWE and code"),
    metricTile("Fixes verified", String(m.fixes_verified || 0), m.fixes_bypassed ? `${m.fixes_bypassed} bypassed by a variant` : `of ${plural(m.proven || 0, "proven finding")}`),
    metricTile("Discarded suspicions", String(m.discarded || 0), "not proven; not evidence of safety"),
    metricTile("Cost", fmtCost(m.cost_usd), `${fmtTokens(m.tokens_in)} tokens in · ${fmtTokens(m.tokens_out)} out`));

  const prs = detail.pull_requests || [];
  const serious = detail.top_findings || [];
  const prCard = h("section", { class: "card list-card" },
    h("div", { class: "card-head" },
      h("h3", { class: "card-title", text: "Recent pull requests" }),
      h("a", { class: "card-link", href: "#/runs", text: "All runs →" })),
    prs.length ? h("ul", { class: "pr-list" }, prs.slice(0, 8).map(prRow)) : emptyState("No runs for this repository."));
  const seriousCard = h("section", { class: "card list-card" },
    h("div", { class: "card-head" },
      h("h3", { class: "card-title", text: "Most serious findings" }),
      h("span", { class: "muted small", text: "by severity, then fix status" })),
    serious.length
      ? h("ul", { class: "serious-list" }, serious.slice(0, 6).map(seriousRow))
      : nothingProven("repository"),
    serious.length ? h("p", { class: "list-note", text: "Merge status is not recorded in the ledger: a verified fix may not be merged yet." }) : null);

  show(
    syntheticBanner([selected]),
    cards,
    h("section", { class: "section-stack" },
      h("div", { class: "section-head" },
        h("div", { class: "section-title-wrap" },
          h("h2", { class: "section-title", text: name }),
          h("p", { class: "section-subtitle", text: last.started_at ? `Last run ${fmtRelative(last.started_at)}: ${prLabel(last) ? `${prLabel(last)} · ` : ""}${last.headline || ""}` : "No runs recorded." })),
        h("div", { class: "section-aside" }, h("span", { class: "micro-label", text: "Risk mix" }), severityMix(selected.severity_mix || {}))),
      metrics,
      h("div", { class: "home-columns" }, prCard, seriousCard)));
}

// ==============================================================================
// Run overview (frame 04)
// ==============================================================================

async function renderRunOverview(id) {
  setActiveNav("overview");
  updateRunContextCard(id);

  const data = await api(`/api/runs/${encodeURIComponent(id)}`);
  const row = data.run;
  setShellHeader([repoCrumb(row), runCrumb(row), { text: "Overview" }], "Run overview", "Export report", () => {
    downloadData(`report-${row.run_id}.json`, data);
  });
  setFooter(row.synthetic ? "Illustrative data · Local replay" : `${repoShort(row.repo)} · ${row.run_id}`);

  const statusText = { completed: "Run completed", aborted: "Run aborted", timed_out: "Run timed out", not_run: "Run not started", skipped: "Exploits skipped (risk gate)", unreadable: "Run could not be read" };
  const statusRow = h("div", { class: "run-status-row" },
    h("div", { class: "run-status-badge" },
      icon(row.status === "completed" ? "circle-check" : "circle-alert", 20),
      h("span", { text: statusText[row.status] || `Run ${row.status}` }),
      h("span", { class: "mono", text: row.ledger_run_id || row.run_id })),
    h("div", { class: "run-commit-range", text: prCommit(row) }));

  if (row.status === "unreadable") {
    show(statusRow, h("div", { class: "notice error", text: row.error || "The ledger could not be read; nothing is shown." }));
    return;
  }

  const uniqueCount = data.proven.length;
  const rawCount = isNum(data.proven_raw) ? data.proven_raw : uniqueCount;
  const duplicateCount = isNum(data.duplicates) ? data.duplicates : Math.max(0, rawCount - uniqueCount);

  const uniqueCard = h("div", { class: "summary-card" },
    h("div", { class: "summary-card-title", text: "Unique findings" }),
    h("div", { class: "summary-card-big-num", text: String(uniqueCount) }),
    h("div", { class: "summary-card-sub", text: plural(rawCount, "raw proven proof") }),
    h("div", { class: "dedup-bar", role: "img", "aria-label": `${uniqueCount} unique of ${rawCount} proofs` },
      h("div", { class: "dedup-bar-fill", style: `width: ${rawCount ? pct(uniqueCount, rawCount) : 0}%` })),
    h("div", { class: "dedup-note" }, icon("layers-2", 16), h("span", { text: `${plural(duplicateCount, "duplicate")} grouped` })));

  const verdicts = row.verdicts || {};
  const totalTests = Object.values(verdicts).reduce((a, b) => a + (Number(b) || 0), 0);
  const outcomeRow = (label, iconName, count, cls) => h("div", { class: "outcome-row" },
    h("span", { class: "outcome-label" }, icon(iconName, 18, cls), label),
    h("div", { class: "outcome-bar-track" }, h("div", { class: `outcome-bar-fill ${cls}`, style: `width: ${pct(Number(count) || 0, totalTests)}%` })),
    h("span", { class: "outcome-count", text: String(Number(count) || 0) }));

  const testResultsCard = h("div", { class: "summary-card" },
    h("div", { class: "test-results-header" },
      h("div", { class: "summary-card-title", text: "Test results" }),
      h("div", { class: "test-results-count", text: plural(totalTests, "verdict") })),
    h("div", { class: "test-results-rows" },
      outcomeRow("Proven", "file-check-2", verdicts.proven, "proven"),
      outcomeRow("Unproven", "minus-circle", verdicts.discarded_unproven, "unproven"),
      outcomeRow("Invalid", "circle-x", verdicts.invalid_test, "invalid"),
      outcomeRow("Flaky", "repeat-2", verdicts.flaky, "flaky"),
      outcomeRow("Environment failure", "unplug", verdicts.env_failure, "environment")));

  const budgetCard = h("div", { class: "summary-card" },
    h("div", { class: "summary-card-title", text: "Budget used" }),
    h("div", { class: "summary-card-big-cost", text: fmtCost(row.cost_usd) }),
    h("div", { class: "summary-card-sub", text: "Budget limit: not available" }),
    h("div", { class: "summary-card-sub small", text: `${fmtTokens(row.tokens_in)} tokens in · ${fmtTokens(row.tokens_out)} out` }),
    h("div", { class: "elapsed-time" }, icon("clock-3", 22), h("span", { text: fmtDuration(row.duration_s) })));

  const findingsSection = h("section", { class: "section-stack" },
    h("div", { class: "section-title-wrap" },
      h("h2", { class: "section-title", text: "Proven findings" }),
      h("p", { class: "section-subtitle", text: "Observed effects, grouped by root cause." })),
    data.proven.length
      ? h("div", { class: "findings-grid" }, data.proven.map((item) => findingCard(row, item)))
      : h("div", { class: "finding" }, nothingProven("run")));

  const list = h("ol", { class: "events" });
  const more = h("button", { type: "button", class: "btn", text: "Load more events" });
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

  show(
    statusRow,
    syntheticBanner([row]),
    h("div", { class: "summary-cards-grid" }, uniqueCard, testResultsCard, budgetCard),
    findingsSection,
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", { class: "card-title", text: "Verdict timeline" })), stageTracker(data.stages)),
    data.discarded && data.discarded.length
      ? h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", { class: "card-title", text: "Discarded suspicions" }), h("span", { class: "muted", text: plural(data.discarded.length, "suspicion") })), discardedTable(data.discarded))
      : null,
    h("div", { class: "card" },
      h("div", { class: "card-head" }, h("h2", { class: "card-title", text: "Ledger events" }), h("span", { class: "muted", text: plural(row.event_count || 0, "event") })),
      list,
      h("div", { class: "pager" }, more)));
  await loadEvents();
}

// ==============================================================================
// Finding detail (frame 05)
// ==============================================================================

async function renderFindingDetail(runId, findingId) {
  setActiveNav("findings");
  updateRunContextCard(runId);

  const data = await api(`/api/runs/${encodeURIComponent(runId)}`);
  const row = data.run;
  const finding = (data.proven || []).find((f) => f.id === findingId) ||
    (data.discarded || []).find((f) => f.id === findingId);
  if (!finding) {
    setShellHeader([repoCrumb(row), runCrumb(row), { text: "Findings", href: runHref(runId, "/findings") }, { text: findingId }], "Finding not found");
    show(emptyState("This run has no finding with that id.", "Open the findings list to pick one."));
    return;
  }

  const ev = finding.evidence || {};
  const red = ev.fails_on_vulnerable || {};
  const fixed = ev.passes_on_fixed || {};
  const effect = ev.effect || {};
  const fix = ev.fix || {};
  const prov = ev.provenance || {};
  const bypass = ev.bypass || {};
  const obsLoc = ev.observed_location || {};
  const modelLoc = ev.model_location || { file: finding.file, line: finding.line };
  const proven = finding.verdict === "proven";
  const sev = severityOf(ev);

  setShellHeader([repoCrumb(row), runCrumb(row), { text: "Findings", href: runHref(runId, "/findings") }, { text: finding.id }],
    findingTitle(finding), "Download proof", () => downloadData(`proof-${runId}-${finding.id}.json`, finding));
  setFooter(row.synthetic ? `Illustrative data · ${finding.id}` : `${repoShort(row.repo)} · ${finding.id}`);

  const metaRow = h("div", { class: "finding-detail-meta-row" },
    h("div", { class: "finding-detail-chips" },
      proven ? h("span", { class: "chip-proven" }, icon("file-check-2", 14), "Proven")
        : h("span", { class: "chip-tag warn", text: humanize(finding.verdict) }),
      proven ? h("span", { class: `chip-tag cwe sev-${sev || "low"}` }, icon("triangle-alert", 14), severityText(ev)) : null,
      proven ? h("span", { class: "chip-effect" }, icon("file-text", 14), effect.label || humanize(effect.type) || "Effect not available") : null,
      h("span", { class: "chip-tag proof", text: finding.id })),
    h("div", { class: "run-commit-range", text: prCommit(row) }));

  const hypothesis = finding.hypothesis
    ? h("p", { class: "lede", text: finding.hypothesis })
    : null;

  if (!proven) {
    show(metaRow, hypothesis, h("div", { class: "card" },
      h("div", { class: "card-head" }, h("h2", { class: "card-title", text: "Why it was not proven" })),
      h("p", { text: finding.reason || NA }),
      h("p", { class: "muted small", text: "A discarded suspicion is not evidence of safety; it only failed the proof standard." })));
    return;
  }

  // Before / after: oracle effects observed on the vulnerable and the fixed code.
  const before = isNum(red.oracle_events) ? red.oracle_events : null;
  const fixedRuns = isNum(fixed.runs) ? fixed.runs : 0;
  const after = fixedRuns > 0 ? (fixed.effect_seen_after_fix ? null : 0) : null;
  const afterText = fixedRuns > 0 ? (fixed.effect_seen_after_fix ? "seen" : "0") : NA;
  const statCol = (label, value, cls) => h("div", { class: "status-code-col" },
    h("span", { class: "status-code-label", text: label }),
    h("span", { class: `status-code-val ${cls}`, text: value }));

  const runsText = red.runs ? `${red.runs}${red.of ? `/${red.of}` : ""}` : NA;
  const beforeCard = h("div", { class: "boundary-card" },
    h("div", { class: "boundary-card-header" },
      h("span", { class: "boundary-card-label", text: "Before fix" }),
      h("span", { class: "pill-fail" }, icon("x", 14), "FAIL")),
    h("div", { class: "status-codes-row" },
      statCol("Expected effects", "0", ""),
      h("span", { class: "status-code-sep", "aria-hidden": "true", text: "/" }),
      statCol("Observed", before === null ? NA : String(before), before === null ? "na" : "fail")),
    h("div", { class: "boundary-result-text", text: effect.observed
      ? `Exploit failed in ${runsText} runs; the oracle saw ${effect.label || humanize(effect.type) || "the effect"}${effect.path ? ` of ${effect.path}` : ""}.`
      : (finding.reason || "Exploit failed on the vulnerable code.") }));

  const bypassed = (bypass.variants || []).filter((v) => v.bypassed);
  const afterPill = bypassed.length
    ? h("span", { class: "pill-fail" }, icon("x", 14), "BYPASSED")
    : (fixed.fix_verified
      ? h("span", { class: "pill-pass" }, icon("check", 14), "PASS")
      : h("span", { class: "pill-neutral", text: "NOT VERIFIED" }));
  const afterCard = h("div", { class: "boundary-card" },
    h("div", { class: "boundary-card-header" },
      h("span", { class: "boundary-card-label", text: "After fix" }),
      afterPill),
    h("div", { class: "status-codes-row" },
      statCol("Expected effects", "0", ""),
      h("span", { class: "status-code-sep", "aria-hidden": "true", text: "/" }),
      statCol("Observed", afterText, after === 0 ? "pass" : (afterText === NA ? "na" : "fail"))),
    h("div", { class: "boundary-result-text", text: bypassed.length
      ? `The original exploit passes on the fixed code, but ${plural(bypassed.length, "bypass variant")} defeated the fix: ${bypassed.map((v) => v.name || "unnamed").join(", ")}.`
      : fixed.fix_verified
      ? `Exploit passes on the fixed code in ${plural(fixedRuns, "run")}; the baseline still passes.`
      : (fixed.effect_seen_after_fix ? "The effect was still observed after the fix (incomplete fix)." : "The fix was not verified in this run.") }));

  const boundarySection = h("section", { class: "boundary-section" },
    h("div", { class: "section-title-wrap" },
      h("h2", { class: "section-title", text: "Boundary assertion" }),
      h("p", { class: "section-subtitle", text: "Same test and input, before and after the fix." })),
    h("div", { class: "boundary-cards-grid" }, beforeCard, afterCard));

  const renderDiffLines = (raw) => raw.split("\n").map((line) => {
    let cls = "";
    if (line.startsWith("+")) cls = "diff-add";
    else if (line.startsWith("-")) cls = "diff-del";
    else if (line.startsWith("@@")) cls = "diff-hunk";
    return h("span", { class: cls, text: `${line}\n` });
  });

  const diffText = fix.diff || "";
  const patchBox = h("div", { class: "code-box" },
    h("div", { class: "code-box-header" },
      h("span", { text: fix.patch_path || (modelLoc.file ? `${modelLoc.file} · patch` : "patch") }),
      diffText ? copyButton(diffText, "Copy patch") : null),
    h("pre", {}, diffText ? renderDiffLines(diffText) : `Patch text is ${NA} in this ledger.${fix.proposed ? (fix.applied ? " A fix was proposed and applied." : " A fix was proposed but not applied.") : ""}`));
  const testBox = h("div", { class: "code-box" },
    h("div", { class: "code-box-header" }, h("span", { text: ev.exploit_test || "exploit test" })),
    h("pre", {}, `Exploit test source is ${NA} in this ledger.${ev.exploit_test ? `\nRecorded path: ${ev.exploit_test}` : ""}`));

  const duplicates = ev.duplicates || [];
  const duplicatesDisclosure = duplicates.length
    ? h("details", { class: "duplicates-disclosure" },
        h("summary", {}, icon("chevron-right", 16), h("span", { text: `${plural(duplicates.length + 1, "proof")} / 1 finding · View grouped proofs` })),
        h("ul", {}, duplicates.map((d) => h("li", {},
          h("strong", { class: "mono", text: d.suspicion_id }),
          h("span", { class: "mono small", text: ` · guess ${d.file || "?"}:${d.line || 0}` }),
          d.observed_location && d.observed_location.file
            ? h("span", { class: "mono small", text: ` · oracle ${d.observed_location.file}:${d.observed_location.line}` })
            : null))))
    : null;

  const frames = (prov.frames || []).filter((f) => f.admitted);
  const provenanceBox = h("div", { class: "code-box" },
    h("div", { class: "code-box-header" }, h("span", { text: `Provenance · entry ${prov.entry_point || NA}` })),
    h("pre", {}, frames.length
      ? frames.map((f) => h("span", { class: f.entry_point ? "diff-hunk" : "", text: `${f.qualname || f.function}  ${f.file}:${f.line || "?"}\n` }))
      : `Admitted application frames are ${NA}.`));

  const tabs = [["Patch & test", [patchBox, testBox]], ["Provenance", [provenanceBox]]];
  const tabPanel = h("div", { class: "evidence-main-col", role: "tabpanel" });
  const tabButtons = tabs.map(([label, content], i) => {
    const b = h("button", { type: "button", class: `tab-btn${i === 0 ? " active" : ""}`, role: "tab", "aria-selected": i === 0 ? "true" : "false", text: label });
    b.onclick = () => {
      tabButtons.forEach((other) => { other.classList.remove("active"); other.setAttribute("aria-selected", "false"); });
      b.classList.add("active");
      b.setAttribute("aria-selected", "true");
      tabPanel.replaceChildren(...content, duplicatesDisclosure || h("span"));
    };
    return b;
  });
  tabPanel.replaceChildren(patchBox, testBox, duplicatesDisclosure || h("span"));
  const leftCol = h("div", { class: "evidence-main-col" }, h("div", { class: "tab-bar", role: "tablist" }, tabButtons), tabPanel);

  const factItem = (key, val) => h("div", { class: "fact-item" },
    h("span", { class: "fact-key", text: key }),
    h("span", { class: `fact-val${val ? "" : " na"}`, text: val || NA }));
  const oracleCard = h("div", { class: "side-card" },
    h("div", { class: "side-card-header" }, h("h3", { class: "side-card-title", text: "Oracle observation" })),
    h("div", { class: "side-card-stat", text: `${before === null ? "?" : before} → ${afterText}` }),
    h("div", { class: "side-card-stat-label", text: "Effects observed · before / after" }),
    h("div", { class: "facts-list" },
      factItem("Effect", effect.label ? `${effect.label} (${effect.type})` : effect.type),
      factItem("Allowed root", ""),
      factItem("Observed path", effect.path),
      factItem("Open mode", effect.mode),
      factItem("Runs failing", red.runs ? `${red.runs}${red.of ? ` of ${red.of}` : ""}` : ""),
      factItem("Bypass variants", isNum(bypass.tried) ? `${bypass.tried} tried, ${bypass.succeeded || 0} bypassed the fix` : "")),
    h("div", { class: "side-card-scope-note", text: row.synthetic ? "Synthetic fixture, not production data." : "Recorded from an isolated, resource-limited sandbox run." }));

  const locCard = h("div", { class: "side-card" },
    h("div", { class: "side-card-header" }, h("h3", { class: "side-card-title", text: "Location" })),
    h("div", { class: "fact-val", text: obsLoc.file || modelLoc.file || NA }),
    h("div", { class: "location-columns" },
      h("div", {}, h("div", { class: "loc-col-title", text: "Guess" }), h("div", { class: "loc-col-val", text: modelLoc.line ? String(modelLoc.line) : NA })),
      h("div", {}, h("div", { class: "loc-col-title", text: "Observed" }), h("div", { class: "loc-col-val observed", text: obsLoc.line ? String(obsLoc.line) : NA }))),
    h("a", { class: "finding-open-link", href: runHref(runId, "/graph") }, "Show in code graph →"));

  const evidenceWorkspace = h("div", { class: "evidence-workspace" }, leftCol, h("div", { class: "evidence-side-col" }, oracleCard, locCard));

  const pkg = ev.package || "";
  const terminalText = pkg
    ? `exhibit-a verify ${pkg}\nexhibit-a reproduce ${pkg}`
    : "Package path not recorded in this ledger.";
  const offlineCard = h("div", { class: "offline-card" },
    h("div", { class: "offline-header" },
      h("div", {},
        h("h3", { class: "offline-title", text: "Re-verify offline" }),
        h("p", { class: "offline-sub", text: "Portable evidence bundle · SHA-256 manifest" })),
      h("button", { type: "button", class: "btn", onclick: () => downloadData(`offline-bundle-${row.run_id}.json`, { run: row, finding }) },
        icon("download", 16), "Download bundle")),
    h("div", { class: "offline-grid" },
      h("div", { class: "terminal-box" },
        h("div", { class: "terminal-label", text: "Terminal · no model calls" }),
        h("pre", {}, terminalText)),
      h("div", { class: "manifest-list" },
        h("div", { class: "manifest-item" }, h("span", { class: "manifest-label", text: `Test · ${ev.exploit_test || NA}` }), h("span", { class: "manifest-hash", text: `SHA-256: ${NA}` })),
        h("div", { class: "manifest-item" }, h("span", { class: "manifest-label", text: `Patch · ${fix.patch_path || NA}` }), h("span", { class: "manifest-hash", text: `SHA-256: ${NA}` })),
        h("div", { class: "manifest-item" }, h("span", { class: "manifest-label", text: `Package · ${pkg || NA}` }), h("span", { class: "manifest-hash", text: "Hashes live in the package manifest; verify checks them." })))),
    h("div", { class: "offline-policy-note" }, icon("circle-alert", 16), h("span", { text: "Hash mismatch stops execution without changing the verdict." })));

  show(metaRow, hypothesis, boundarySection, evidenceWorkspace, offlineCard);
}

// ==============================================================================
// Live run / replay
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
  let stream = null;

  const trackerHost = h("div", {});
  const list = h("ol", { class: "events" });
  const progress = h("span", { class: "muted small" });
  const speed = h("select", { class: "select", "aria-label": "Replay speed" },
    ["0.5", "1", "2", "4", "8"].map((v) => h("option", { value: v, text: `${v}×` })));
  speed.value = "2";
  const play = h("button", { type: "button", class: "primary", text: "Play" });
  const step = h("button", { type: "button", text: "Step" });
  const restart = h("button", { type: "button", text: "Restart" });

  setShellHeader([repoCrumb(row), runCrumb(row), { text: "Live run" }], "Live run", "Restart", () => restart.click(), "repeat-2");

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
    if (stream) { stream.close(); stream = null; }
    if (cursor < total) play.textContent = "Play";
  };
  onTeardown(stop);

  play.addEventListener("click", () => {
    if (stream) { stop(); return; }
    stream = new EventSource(`/api/runs/${encodeURIComponent(id)}/replay?speed=${encodeURIComponent(speed.value)}&from=${cursor}`);
    play.textContent = "Pause";
    stream.addEventListener("step", (msg) => {
      try { add(JSON.parse(msg.data)); } catch (_) { /* malformed frame: skip */ }
    });
    stream.addEventListener("done", stop);
    stream.onerror = stop;
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

  speed.addEventListener("change", () => { if (stream) { stop(); play.click(); } });

  show(
    syntheticBanner([row]),
    h("div", { class: "card" },
      h("div", { class: "card-head" }, h("h2", { class: "card-title", text: "Recorded execution trace" })),
      h("p", { class: "muted", text: `Replays the recorded ledger of ${row.run_id} step by step, in ledger order. Nothing is re-executed.` }),
      h("div", { class: "toolbar" }, play, step, restart, h("label", { class: "small" }, "Speed ", speed), h("span", { class: "spacer" }), progress)),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", { class: "card-title", text: "Verdict timeline" })), trackerHost),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", { class: "card-title", text: "Events, newest first" })), list));

  redraw();
}

// ==============================================================================
// Findings list
// ==============================================================================

async function renderFindingsList(runId) {
  setActiveNav("findings");
  updateRunContextCard(runId);

  const data = await api(`/api/runs/${encodeURIComponent(runId)}`);
  const row = data.run;
  setShellHeader([repoCrumb(row), runCrumb(row), { text: "Findings" }], "Findings", "Export findings", () => {
    downloadData(`findings-${runId}.json`, { proven: data.proven, discarded: data.discarded });
  });

  show(
    syntheticBanner([row]),
    h("div", { class: "section-title-wrap" },
      h("h2", { class: "section-title", text: `Proven findings (${data.proven.length})` }),
      h("p", { class: "section-subtitle", text: "Each one failed on the vulnerable code for the oracle-observed reason and passed after a verified fix." })),
    data.proven.length
      ? h("div", { class: "findings-grid" }, data.proven.map((item) => findingCard(row, item)))
      : h("div", { class: "finding" }, nothingProven("run")),
    h("div", { class: "card" },
      h("div", { class: "card-head" }, h("h2", { class: "card-title", text: "Discarded suspicions" }), h("span", { class: "muted", text: plural(data.discarded.length, "suspicion") })),
      discardedTable(data.discarded)));
}

// ==============================================================================
// Benchmark / trends
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
      tip.style.setProperty("left", `${left}px`);
      tip.style.setProperty("top", "0px");
    };

    hit.addEventListener("mouseenter", showTip);
    hit.addEventListener("focus", showTip);
    hit.addEventListener("click", () => { location.hash = runHref(p.run_id); });
    hit.addEventListener("keydown", (e) => { if (e.key === "Enter") location.hash = runHref(p.run_id); });
    hit.addEventListener("mouseleave", () => { tip.hidden = true; });
    hit.addEventListener("blur", () => { tip.hidden = true; });
    root.appendChild(hit);
  });

  return append(wrap, [root, tip]);
}

async function renderBenchmark() {
  setActiveNav("benchmark");
  const trendsData = await api("/api/trends?limit=50");
  setShellHeader([{ text: "All repositories", href: "#/" }, { text: "Benchmark" }], "Benchmark & trends", "Export trends", () => {
    downloadData("trends.json", trendsData);
  });
  const points = trendsData.points || [];
  const sums = Object.fromEntries(SERIES.map(([k]) => [k, points.reduce((n, p) => n + (p[k] || 0), 0)]));

  const table = h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, h("th", { text: "Run" }), ...SERIES.map(([, label]) => h("th", { class: "num", text: label })), h("th", { class: "num", text: "Flaky" }), h("th", { class: "num", text: "Env failure" }))),
    h("tbody", {}, points.slice().reverse().map((p) => h("tr", {},
      h("td", {}, h("div", { class: "cell-stack" }, h("a", { class: "run-title", href: runHref(p.run_id), text: fmtDate(p.started_at) }), h("span", { class: "run-sub mono", text: p.run_id }))),
      ...SERIES.map(([k]) => h("td", { class: "num", text: String(p[k] || 0) })),
      h("td", { class: "num", text: String(p.flaky || 0) }),
      h("td", { class: "num", text: String(p.env_failure || 0) }))))));

  show(
    h("p", { class: "lede", text: `Verdicts per run across the ${plural(points.length, "most recent readable run")}: ${sums.proven || 0} proven, ${sums.discarded_unproven || 0} discarded for lack of proof, ${sums.invalid_test || 0} invalid tests.` }),
    syntheticBanner(points),
    points.length
      ? h("div", { class: "card" },
          h("div", { class: "card-head" }, h("h2", { class: "card-title", text: "Proven vs discarded vs invalid, per run" })),
          h("ul", { class: "legend" }, SERIES.map(([, label, cls]) => h("li", {}, h("span", { class: `swatch ${cls}` }), label))),
          trendChart(points))
      : emptyState("No readable runs yet."),
    points.length ? h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", { class: "card-title", text: "Runs" })), table) : null);
}

// ==============================================================================
// Code graph (entry to sink)
// ==============================================================================

function graphView(graph) {
  if (!graph || !graph.available) {
    return emptyState("No code graph is available for this run.", graph && graph.reason ? graph.reason : null);
  }
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const order = nodes.slice().sort((a, b) => (a.file || "").localeCompare(b.file || "") || a.line - b.line);
  const positions = Object.fromEntries(order.map((n, i) => [n.id, { x: 80 + (i % 5) * 190, y: 70 + Math.floor(i / 5) * 100 }]));
  const width = Math.max(900, 120 + (Math.min(order.length, 5) * 190));
  const height = Math.max(260, 140 + Math.ceil(order.length / 5) * 100);
  const root = svg("svg", { class: "graph-svg", viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": "Entry to sink code graph" });
  edges.forEach((edge) => {
    const a = positions[edge.src], b = positions[edge.dst];
    if (!a || !b) return;
    root.appendChild(svg("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: edge.proven ? "graph-edge proven" : "graph-edge" }));
  });
  order.forEach((node) => {
    const p = positions[node.id];
    const group = svg("g", { class: `graph-node ${node.proven ? "proven" : ""} ${node.entry_point ? "entry" : ""}` });
    group.appendChild(svg("rect", { x: p.x - 75, y: p.y - 22, width: 150, height: 44, rx: 6 }));
    group.appendChild(svg("text", { x: p.x, y: p.y + 4, "text-anchor": "middle", text: String(node.name || node.id).slice(0, 22) }));
    root.appendChild(group);
  });
  return h("div", { class: "card graph-card" },
    h("div", { class: "card-head" }, h("h2", { class: "card-title", text: "Entry to sink graph" }), h("span", { class: "muted", text: `${nodes.length} nodes, ${edges.length} edges` })),
    h("div", { class: "graph-canvas" }, root));
}

async function renderDependencies(runId) {
  setActiveNav("dependencies");
  updateRunContextCard(runId);
  const data = await api(`/api/runs/${encodeURIComponent(runId)}`);
  const row = data.run;
  setShellHeader([repoCrumb(row), runCrumb(row), { text: "Code graph" }], "Code graph");
  show(h("p", { class: "lede", text: "Static call graph and sink reach paths computed for this run." }), graphView(data.graph));
}

// ==============================================================================
// All runs
// ==============================================================================

async function renderRuns(page = 1) {
  setActiveNav("runs");
  const data = await api(`/api/runs?page=${page}&per_page=25`);
  setShellHeader([{ text: "All repositories", href: "#/" }, { text: "Runs" }], "All runs", "Refresh", () => route(), "repeat-2");
  setFooter(state.sourceLabel || "Local replay");
  const rows = data.runs || [];

  const table = h("table", { class: "runs" },
    h("colgroup", {},
      h("col", { class: "col-status" }), h("col", { class: "col-run" }), h("col", { class: "col-repo" }),
      h("col", { class: "col-risk" }), h("col", { class: "col-proven" }), h("col", { class: "col-duration" }), h("col", { class: "col-cost" })),
    h("thead", {}, h("tr", {},
      h("th", { scope: "col", text: "Status" }),
      h("th", { scope: "col", text: "Pull request" }),
      h("th", { scope: "col", text: "Repository · commit" }),
      h("th", { scope: "col", text: "Risk" }),
      h("th", { scope: "col", class: "num", text: "Proven" }),
      h("th", { scope: "col", class: "num", text: "Duration" }),
      h("th", { scope: "col", class: "num", text: "Cost" }))),
    h("tbody", {}, rows.map((row) => {
      const target = runHref(row.run_id);
      const title = row.title || row.headline || row.run_id;
      return h("tr", { onclick: (e) => { if (!(e.target instanceof HTMLAnchorElement)) location.hash = target; } },
        h("td", {}, statusBadge(row)),
        h("td", {}, h("div", { class: "cell-stack" },
          h("a", { class: "run-title", href: target, text: title, title }),
          h("span", { class: "run-sub", text: `${fmtDate(row.started_at)} · ${row.headline}`, title: row.run_id }))),
        h("td", {}, h("div", { class: "cell-stack" },
          h("span", { class: "run-title", text: repoShort(row.repo), title: row.repo || null }),
          h("span", { class: "run-sub mono", text: prCommit(row) }))),
        h("td", {}, row.risk ? h("span", { class: "tag", text: row.risk }) : h("span", { class: "muted small", text: NA })),
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
    h("p", { class: "lede", text: `${plural(data.total, "run")} from ${data.source}; ${plural(totalProven, "proven finding")} on this page. A run with nothing proven means nothing could be proven, not that the code is safe.` }),
    syntheticBanner(rows),
    rows.length
      ? h("div", { class: "card table-card" }, h("div", { class: "table-wrap" }, table), pager)
      : emptyState("No runs found in this source."));
}

// -- Router --------------------------------------------------------------------

function fallbackRunId() {
  return state.currentRunId || (state.runs[0] && state.runs[0].run_id) || null;
}

function isAbort(error) {
  return Boolean(error) && error.name === "AbortError";
}

async function route() {
  runTeardown();
  state.routeAbort.abort();
  state.routeAbort = new AbortController();
  const signal = state.routeAbort.signal;
  const rawHash = location.hash.replace(/^#\/?/, "");
  const parts = rawHash.split("/").map((p) => {
    try { return decodeURIComponent(p); } catch (_) { return ""; }
  });

  try {
    if (parts[0] === "run" && RUN_ID.test(parts[1] || "")) {
      if (parts[2] === "finding" && parts[3]) await renderFindingDetail(parts[1], parts[3]);
      else if (parts[2] === "findings") await renderFindingsList(parts[1]);
      else if (parts[2] === "graph") await renderDependencies(parts[1]);
      else await renderRunOverview(parts[1]);
    } else if (parts[0] === "replay") {
      const id = (parts[1] && RUN_ID.test(parts[1])) ? parts[1] : fallbackRunId();
      if (id) await renderReplay(id);
      else await renderRuns(1);
    } else if (parts[0] === "findings" || parts[0] === "dependencies") {
      const id = fallbackRunId();
      if (!id) await renderRuns(1);
      else if (parts[0] === "findings") await renderFindingsList(id);
      else await renderDependencies(id);
    } else if (parts[0] === "trends" || parts[0] === "benchmark") {
      await renderBenchmark();
    } else if (parts[0] === "runs") {
      const page = Math.max(1, parseInt(parts[1] || "1", 10) || 1);
      await renderRuns(page);
    } else if (parts[0] === "repo" && REPO_ID.test(parts[1] || "")) {
      await renderHome(parts[1]);
    } else {
      await renderHome(null);
    }
    if (!signal.aborted) window.scrollTo(0, 0);
  } catch (error) {
    if (isAbort(error) || signal.aborted) return; // a newer navigation owns the view
    renderError(error);
  }
}

// -- Bootstrap -----------------------------------------------------------------

// The backdrop's drift is CSS animation on transforms only; stop it while nobody can see it.
function initBackdrop() {
  const backdrop = document.getElementById("backdrop");
  if (!backdrop) return;
  const sync = () => backdrop.classList.toggle("is-paused", document.hidden);
  document.addEventListener("visibilitychange", sync);
  sync();
}

async function boot() {
  initTheme();
  initBackdrop();
  if (themeToggle) themeToggle.onclick = toggleTheme;

  const iconMap = [
    ["icon-home", "house"],
    ["icon-runs", "list"],
    ["icon-overview", "layout-dashboard"],
    ["icon-liverun", "activity"],
    ["icon-findings", "file-search"],
    ["icon-benchmark", "chart-no-axes-combined"],
    ["icon-dependencies", "git-branch"],
    ["icon-monitor", "monitor"],
    ["icon-chevron", "chevrons-up-down"],
  ];
  for (const [elId, iconName] of iconMap) {
    const el = document.getElementById(elId);
    if (el) el.replaceChildren(icon(iconName, 18));
  }

  try {
    const data = await api("/api/runs?page=1&per_page=100");
    state.runs = data.runs || [];
    state.sourceLabel = data.source || "";
    state.runsById = new Map(state.runs.map((r) => [r.run_id, r]));
    populateRunSelect();
    if (state.runs.length && !state.currentRunId) updateRunContextCard(state.runs[0].run_id);
  } catch (_) { /* the route below shows the error (or the sign-in notice) */ }

  window.addEventListener("hashchange", route);
  await route();
}

boot();
