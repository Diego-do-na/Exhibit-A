/* Exhibit A live view: a thin window into the engine, no framework.
 *
 * The page renders ledger events from three sources: the live SSE stream,
 * the replay SSE stream, or a recorded .jsonl file opened locally (which
 * needs no server at all). Rendering mirrors src/exhibit_a/live/summary.py.
 */
"use strict";

const KNOWN_TYPES = [
  "pr_opened", "scan_done", "baseline_done", "suspicion_raised",
  "exploit_written", "run_started", "oracle_event", "verdict",
  "fix_proposed", "bypass_attempt", "bypass_result", "packaged",
];
const OUTPUT_KEYS = ["stdout", "stderr", "output", "log"];

const state = { events: [], source: null };

const $ = (id) => document.getElementById(id);

function esc(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function short(value, limit) {
  const flat = String(value).split(/\s+/).join(" ");
  return flat.length <= limit ? flat : flat.slice(0, limit - 1) + "…";
}

function suspicionRef(payload) {
  const cand = payload && typeof payload.suspicion === "object" && payload.suspicion !== null
    ? payload.suspicion
    : payload || {};
  const loc = cand.location && typeof cand.location === "object" ? cand.location : {};
  return {
    suspicion_id: String(cand.id || ""),
    class: String(cand.class || ""),
    file: String(loc.file || ""),
    line: Number.isInteger(loc.line) ? loc.line : 0,
  };
}

function testPathOf(payload) {
  if (payload.evidence && typeof payload.evidence.test_path === "string") {
    return payload.evidence.test_path;
  }
  return typeof payload.test_path === "string" ? payload.test_path : "";
}

function summarize(ev) {
  const p = ev.payload || {};
  switch (ev.type) {
    case "pr_opened": {
      const diff = typeof p.diff === "string" ? p.diff : "";
      if (diff) return `PR opened (${diff.split("\n").length} diff lines)`;
      return `PR opened: ${short(p.pr || "unknown", 60)}`;
    }
    case "scan_done":
      return `Scan done: ${p.language || "unknown language"} / ${p.test_cmd || "unknown test cmd"}`;
    case "baseline_done":
      return `Baseline: ${p.passed || 0} passed, ${p.failed || 0} failed`;
    case "suspicion_raised": {
      const ref = suspicionRef(p);
      const where = ref.file ? `${ref.file}:${ref.line}` : "unknown";
      return `Suspicion ${ref.suspicion_id || "?"}: ${ref.class || "unknown"} at ${where}`;
    }
    case "exploit_written":
      return `Exploit written: ${p.test_path || "unknown test"} for ${p.suspicion_id || "?"}`;
    case "run_started":
      return `Run started: ${p.test_path || "unknown test"}`;
    case "oracle_event": {
      const seen = p.observed ? "observed" : "not observed";
      return `Oracle: ${p.effect || "intended effect"} ${seen} (exit ${p.exit_code ?? "?"})`;
    }
    case "verdict":
      return `Verdict ${p.suspicion_id || "?"}: ${p.verdict || "?"}`;
    case "fix_proposed":
      return `Fix proposed: ${p.patch_path || "patch"}`;
    case "bypass_attempt":
      return `Bypass attempt: ${short(p.variant || "variant", 80)}`;
    case "bypass_result":
      return `Bypass ${short(p.variant || "variant", 60)}: ${p.succeeded ? "succeeded" : "failed"}`;
    case "packaged":
      return `Packaged: ${p.dir || "evidence bundle"}`;
    default:
      return String(ev.type || "event");
  }
}

/* ---------- state ---------- */

function reset() {
  state.events = [];
  renderAll();
}

function addEvent(ev) {
  if (!ev || typeof ev.type !== "string") return;
  state.events.push(ev);
  renderAll();
}

function closeStream() {
  if (state.source) {
    state.source.close();
    state.source = null;
  }
}

function setStatus(text) {
  $("status").textContent = text;
}

/* ---------- derived panels ---------- */

function currentDiff() {
  for (const ev of state.events) {
    if (ev.type === "pr_opened" && ev.payload && typeof ev.payload.diff === "string") {
      return ev.payload.diff;
    }
  }
  return "";
}

function currentSuspects() {
  const out = [];
  for (const ev of state.events) {
    if (ev.type === "suspicion_raised") out.push(suspicionRef(ev.payload || {}));
  }
  return out;
}

function redGreen() {
  let redAt = null;
  let redTest = "";
  let fixIndex = null;
  let greenAt = null;
  state.events.forEach((ev, i) => {
    const p = ev.payload || {};
    if (ev.type === "verdict" && p.verdict === "proven" && redAt === null) {
      redAt = ev.ts;
      redTest = testPathOf(p);
    }
    if (ev.type === "fix_proposed" && redAt !== null && fixIndex === null) fixIndex = i;
    if (
      fixIndex !== null && greenAt === null &&
      (ev.type === "packaged" ||
        (ev.type === "oracle_event" && p.observed === false) ||
        p.exploit_passes === true)
    ) {
      greenAt = ev.ts;
    }
  });
  return { red: redAt !== null, green: greenAt !== null, redAt, greenAt, redTest };
}

function verdictCounts() {
  const counts = {};
  let dropped = 0;
  const wall = [];
  for (const ev of state.events) {
    if (ev.type !== "verdict") continue;
    const v = (ev.payload || {}).verdict;
    if (typeof v !== "string") continue;
    counts[v] = (counts[v] || 0) + 1;
    if (v === "discarded_unproven") dropped += 1;
    if (v === "proven") {
      wall.push({
        suspicion_id: String(ev.payload.suspicion_id || ""),
        test_path: testPathOf(ev.payload),
        ts: ev.ts,
      });
    }
  }
  return { counts, dropped, wall };
}

/* ---------- rendering ---------- */

function renderDiff() {
  const diff = currentDiff();
  const suspects = currentSuspects();
  const box = $("diff");
  if (!diff) {
    box.textContent = state.events.length
      ? "No diff in these events yet."
      : "No diff yet. Load the sample or watch a run.";
  } else {
    box.innerHTML = highlightDiff(diff, suspects);
  }
  $("diff-count").textContent = diff ? `(${diff.split("\n").length} lines)` : "";
  const list = $("suspects");
  list.innerHTML = "";
  for (const ref of suspects) {
    const li = document.createElement("li");
    li.textContent = `${ref.suspicion_id || "?"} · ${ref.class || "unknown"} · ${ref.file || "unknown"}:${ref.line}`;
    list.appendChild(li);
  }
}

function highlightDiff(diff, suspects) {
  // Track the new-file line number through hunks so added lines that match
  // a suspect file:line get the suspect highlight.
  const byFile = {};
  for (const ref of suspects) {
    if (!ref.file) continue;
    if (!byFile[ref.file]) byFile[ref.file] = new Set();
    byFile[ref.file].add(ref.line);
  }
  let file = "";
  let lineNo = 0;
  return diff.split("\n").map((line) => {
    let cls = "ctx";
    if (line.startsWith("+++ b/")) {
      file = line.slice("+++ b/".length);
      cls = "meta";
    } else if (line.startsWith("+++ ")) {
      file = line.slice(4);
      cls = "meta";
    } else if (line.startsWith("@@ ")) {
      const match = /\+(\d+)/.exec(line);
      lineNo = match ? parseInt(match[1], 10) : 0;
      cls = "meta";
    } else if (line.startsWith("+") && !line.startsWith("+++")) {
      cls = "add";
      if (byFile[file] && byFile[file].has(lineNo)) cls = "add suspect";
      lineNo += 1;
    } else if (line.startsWith("-") && !line.startsWith("---")) {
      cls = "del";
    } else if (line.startsWith("diff ") || line.startsWith("--- ")) {
      cls = "meta";
    } else {
      lineNo += 1;
    }
    return `<span class="${cls}">${esc(line) || " "}</span>`;
  }).join("\n");
}

function renderTimeline() {
  const list = $("timeline");
  list.innerHTML = "";
  state.events.forEach((ev, seq) => {
    const li = document.createElement("li");
    const badge = document.createElement("span");
    badge.className = `badge t-${esc(ev.type)}`;
    badge.textContent = ev.type;
    const text = document.createElement("span");
    text.innerHTML = ` <span class="muted">${esc(ev.ts || "")}</span> ${esc(summarize(ev))}`;
    li.appendChild(badge);
    li.appendChild(text);
    li.dataset.seq = String(seq);
    list.appendChild(li);
  });
  $("event-count").textContent = state.events.length ? `(${state.events.length} events)` : "";
  list.scrollTop = list.scrollHeight;
}

function renderSandbox() {
  const parts = [];
  state.events.forEach((ev, seq) => {
    const p = ev.payload || {};
    for (const key of OUTPUT_KEYS) {
      if (typeof p[key] === "string" && p[key]) {
        parts.push(`[${String(seq).padStart(3, "0")} ${ev.type}] ${key}:\n${p[key].replace(/\n+$/, "")}`);
      }
    }
  });
  $("sandbox").textContent = parts.length ? parts.join("\n") : "No sandbox output yet.";
}

function renderRedGreen() {
  const rg = redGreen();
  const red = $("red");
  const green = $("green");
  red.className = `dot ${rg.red ? "on-red" : "pending"}`;
  green.className = `dot ${rg.green ? "on-green" : "pending"}`;
  let text = "Waiting for events.";
  if (rg.red && rg.green) {
    text = `Red at ${rg.redAt}, green at ${rg.greenAt}${rg.redTest ? ` — ${rg.redTest}` : ""}.`;
  } else if (rg.red) {
    text = `Red at ${rg.redAt}${rg.redTest ? ` — ${rg.redTest}` : ""}. No fix verified yet.`;
  } else if (state.events.length) {
    text = "No proven finding in these events.";
  }
  $("redgreen-text").textContent = text;
}

function renderWall() {
  const { counts, dropped, wall } = verdictCounts();
  const box = $("wall");
  box.innerHTML = "";
  if (!wall.length) {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = "Proven exploits accumulate here as regression tests.";
    box.appendChild(p);
  }
  for (const item of wall) {
    const card = document.createElement("div");
    card.className = "card";
    card.innerHTML =
      `<strong>${esc(item.test_path || "unknown test")}</strong>` +
      `<span class="muted">${esc(item.suspicion_id)} · ${esc(item.ts || "")}</span>`;
    box.appendChild(card);
  }
  $("wall-count").textContent = wall.length ? `(${wall.length} tests)` : "";
  $("dropped").textContent = String(dropped);
  const breakdown = Object.entries(counts).map(([k, v]) => `${k}: ${v}`).join(" · ");
  $("verdicts").textContent = breakdown;
}

function renderAll() {
  renderDiff();
  renderTimeline();
  renderSandbox();
  renderRedGreen();
  renderWall();
}

/* ---------- sources ---------- */

function selectedRun() {
  return $("run").value;
}

function streamUrl(mode) {
  const run = encodeURIComponent(selectedRun());
  const speed = encodeURIComponent($("speed").value);
  if (mode === "replay") return `/events?run_id=${run}&replay=1&speed=${speed}`;
  return `/events?run_id=${run}&follow=1`;
}

function listen(url, doneText) {
  closeStream();
  reset();
  setStatus("connecting…");
  const source = new EventSource(url);
  state.source = source;
  const onEvent = (ev) => {
    try {
      addEvent(JSON.parse(ev.data));
      setStatus(`streaming (${state.events.length} events)`);
    } catch (err) {
      setStatus(`bad event data: ${err}`);
    }
  };
  for (const name of KNOWN_TYPES) source.addEventListener(name, onEvent);
  source.onmessage = onEvent;
  source.addEventListener("done", (ev) => {
    setStatus(`${doneText} (${state.events.length} events)`);
    closeStream();
  });
  source.addEventListener("error", () => {
    if (state.events.length) {
      setStatus(`stream ended (${state.events.length} events)`);
    } else {
      setStatus("stream error: is the server running?");
    }
  });
}

function parseLedgerText(text) {
  const events = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i].trim();
    if (!raw) continue;
    let ev;
    try {
      ev = JSON.parse(raw);
    } catch (err) {
      throw new Error(`line ${i + 1}: not valid JSON`);
    }
    if (!ev || typeof ev.type !== "string" || typeof ev.run_id !== "string") {
      throw new Error(`line ${i + 1}: not a ledger event`);
    }
    ev.payload = ev.payload && typeof ev.payload === "object" ? ev.payload : {};
    events.push(ev);
  }
  return events;
}

function showEvents(events, label) {
  closeStream();
  reset();
  for (const ev of events) state.events.push(ev);
  renderAll();
  setStatus(`${label} (${events.length} events)`);
}

async function loadRuns() {
  if (location.protocol === "file:") return; // no server when opened as a file
  try {
    const res = await fetch("/api/runs");
    if (!res.ok) return;
    const body = await res.json();
    const select = $("run");
    select.innerHTML = '<option value="">(all runs)</option>';
    for (const id of body.runs || []) {
      const opt = document.createElement("option");
      opt.value = id;
      opt.textContent = id;
      select.appendChild(opt);
    }
    if ((body.runs || []).length === 1) select.value = body.runs[0];
  } catch (err) {
    setStatus("no server: open a ledger file to render it");
  }
}

async function loadSample() {
  try {
    const res = await fetch("sample-ledger.jsonl");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    showEvents(parseLedgerText(await res.text()), "sample ledger");
  } catch (err) {
    setStatus(`cannot load sample: ${err} (open the file manually below)`);
  }
}

function loadFile(file) {
  const reader = new FileReader();
  reader.onload = () => {
    try {
      showEvents(parseLedgerText(String(reader.result || "")), file.name);
    } catch (err) {
      setStatus(`cannot parse ${file.name}: ${err}`);
    }
  };
  reader.onerror = () => setStatus(`cannot read ${file.name}`);
  reader.readAsText(file);
}

/* ---------- wiring ---------- */

$("connect").addEventListener("click", () => listen(streamUrl("live"), "live"));
$("replay").addEventListener("click", () => listen(streamUrl("replay"), "replay finished"));
$("sample").addEventListener("click", loadSample);
$("file").addEventListener("change", (ev) => {
  if (ev.target.files && ev.target.files[0]) loadFile(ev.target.files[0]);
});
$("speed").addEventListener("input", (ev) => {
  $("speed-label").textContent = `${ev.target.value}×`;
});
$("run").addEventListener("change", () => {
  closeStream();
  setStatus("run changed: press Watch live or Replay");
});

loadRuns();
renderAll();
