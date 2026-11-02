"""Static dashboard export built from the same projections as the live server."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .model import (
    build_code_graph,
    build_graph_view,
    build_repo_detail,
    build_repo_index,
    build_trends,
    event_view,
    group_by_repo,
    run_detail,
    run_row,
)
from .sources import LEDGER_NAME, RESULT_NAME, RUN_ID_RE, LocalRunsSource, SourceError


def _json_bytes(value: Any) -> bytes:
    text = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    return (text.translate(str.maketrans({"<": "\\u003c", ">": "\\u003e", "&": "\\u0026"})) + "\n").encode("ascii")


def _safe_child(root: Path, name: str) -> Path:
    if not RUN_ID_RE.fullmatch(name):
        raise SourceError("run id must contain only letters, numbers, '.', '_' and '-'")
    target = (root / name).resolve()
    if target.parent != root.resolve():
        raise SourceError("run id escapes the runs directory")
    return target


def _copy_tree(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for item in sorted(source.iterdir(), key=lambda path: path.name):
        destination = target / item.name
        if item.is_dir() and not item.is_symlink():
            _copy_tree(item, destination)
        elif item.is_file() and not item.is_symlink():
            destination.parent.mkdir(parents=True, exist_ok=True)
            if item.suffix in {".html", ".js", ".css"}:
                text = item.read_text(encoding="utf-8")
                text = text.replace("https://github.com", "#")
                text = text.replace("http://www.w3.org/2000/svg", "urn:exhibit-a:svg")
                destination.write_text(text, encoding="utf-8", newline="\n")
            else:
                shutil.copyfile(item, destination)


def _static_script(bundle: dict[str, Any]) -> str:
    payload = json.dumps(bundle, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    payload = payload.translate(str.maketrans({"<": "\\u003c", ">": "\\u003e", "&": "\\u0026"}))
    return f"""/* Offline adapter for an Exhibit A static dashboard export. */
"use strict";
const STATIC = {payload};
const nativeFetch = window.fetch.bind(window);
function staticResponse(value) {{
  return Promise.resolve(new Response(JSON.stringify(value), {{
    status: 200, headers: {{ "Content-Type": "application/json; charset=utf-8" }}
  }}));
}}
function staticPath(path) {{
  const url = new URL(path, window.location.href);
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts[0] !== "api") return null;
  if (parts[1] === "info") return STATIC.info;
  if (parts[1] === "trends") return STATIC.trends;
  if (parts[1] === "repos") {{
    if (!parts[2]) return STATIC.repos;
    return STATIC.reposById[decodeURIComponent(parts[2])] || {{ error: "unknown repository" }};
  }}
  if (parts[1] !== "runs") return null;
  if (!parts[2]) return STATIC.runs;
  const id = decodeURIComponent(parts[2]);
  const run = STATIC.runsById[id];
  if (!run) return {{ error: "unknown run" }};
  if (parts[3] === "events") return run.events;
  if (parts[3] === "replay") return run.replay;
  if (parts[3] === "graph") return run.graph;
  if (parts[3] === "codegraph") return run.codegraph;
  if (!parts[3]) return run.detail;
  return {{ error: "not found" }};
}}
window.fetch = (input, init) => {{
  const path = typeof input === "string" ? input : input.url;
  const value = staticPath(path);
  return value === null ? nativeFetch(input, init) : staticResponse(value);
}};
class StaticEventSource {{
  constructor(path) {{
    this.onopen = null; this.onmessage = null; this.onerror = null;
    this.listeners = {{}};
    const value = staticPath(path) || {{ events: [] }};
    queueMicrotask(() => {{
      if (this.onopen) this.onopen();
      for (const event of (value.events || [])) this.emit({{ type: "step", data: JSON.stringify(event), lastEventId: String(event.seq) }});
      this.emit({{ type: "done", data: JSON.stringify({{ count: (value.events || []).length }}) }});
    }});
  }}
  addEventListener(name, callback) {{ (this.listeners[name] ||= []).push(callback); }}
  emit(event) {{ for (const callback of this.listeners[event.type] || []) callback(event); }}
  close() {{}}
}}
window.EventSource = StaticEventSource;
const script = document.createElement("script");
script.src = "app.js";
document.head.appendChild(script);
"""


def export_dashboard(
    source: LocalRunsSource,
    destination: str | Path,
    *,
    run_id: str | None = None,
    web_dir: str | Path | None = None,
) -> Path:
    """Write a deterministic, self-contained export for one local run."""
    refs = sorted(source.list_runs(), key=lambda ref: (ref.started_at, ref.run_id), reverse=True)
    if not refs:
        raise SourceError("no readable run folders found")
    selected = run_id or refs[0].run_id
    _safe_child(source.root, selected)
    data = source.load_run(selected)
    if data.error:
        raise SourceError(f"run {selected!r} could not be read: {data.error}")

    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    ui = Path(web_dir) if web_dir else Path(__file__).resolve().parents[3] / "web" / "dashboard"
    if not ui.is_dir():
        raise SourceError(f"dashboard UI directory not found: {ui}")
    _copy_tree(ui, root)

    run_dir = _safe_child(root / "runs", selected)
    run_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = _safe_child(source.root, selected) / LEDGER_NAME
    if ledger_path.is_symlink() or not ledger_path.is_file():
        raise SourceError("selected run ledger is missing or is a symlink")
    shutil.copyfile(ledger_path, run_dir / LEDGER_NAME)
    result_path = _safe_child(source.root, selected) / RESULT_NAME
    if result_path.is_file() and not result_path.is_symlink():
        shutil.copyfile(result_path, run_dir / RESULT_NAME)

    rows = [run_row(data)]
    detail = run_detail(data)
    entries = [(rows[0], detail)]
    repos = {
        rid: {**build_repo_detail(rid, group), "runs_considered": 1, "runs_total": 1}
        for rid, group in group_by_repo(entries).items()
    }
    events = {"run_id": selected, "from": 0, "events": [event_view(i, event) for i, event in enumerate(data.events)],
              "count": len(data.events), "total": len(data.events)}
    bundle = {
        "info": {"source": source.label, "stages_note": "nothing could be proven is not safe"},
        "runs": {"source": source.label, "runs": rows, "page": 1, "per_page": max(1, len(rows)), "total": len(rows),
                 "pages": 1},
        "trends": {"points": build_trends(rows), "limit": len(rows), "total": len(rows)},
        "repos": {"source": source.label, "repos": build_repo_index(entries), "runs_considered": 1, "runs_total": 1},
        "reposById": repos,
        "runsById": {
            selected: {
                "detail": detail,
                "events": events,
                "replay": {"events": events["events"]},
                "ledger": f"runs/{selected}/{LEDGER_NAME}",
                "graph": build_graph_view(data),
                "codegraph": build_code_graph(data),
            }
        },
    }
    (root / "data").mkdir(exist_ok=True)
    for name in ("info", "runs", "trends"):
        (root / "data" / f"{name}.json").write_bytes(_json_bytes(bundle[name]))
    (root / "data" / "run.json").write_bytes(_json_bytes(bundle["runsById"][selected]))
    (root / "static.js").write_text(_static_script(bundle), encoding="utf-8", newline="\n")
    index = (root / "index.html").read_text(encoding="utf-8")
    index = index.replace('<script src="app.js"></script>', '<script src="static.js"></script>')
    (root / "index.html").write_text(index, encoding="utf-8", newline="\n")
    return root
