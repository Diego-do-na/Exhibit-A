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
"""


def export_dashboard(
    source: LocalRunsSource,
    destination: str | Path,
    *,
    run_id: str | None = None,
    web_dir: str | Path | None = None,
) -> Path:
    """Write a deterministic, self-contained static export.

    With ``run_id`` only that run is exported; without it every readable
    run is exported, so a full history (for example 134 PR runs) can be
    hosted on GitHub Pages with no backend server or API key.
    """
    refs = sorted(source.list_runs(), key=lambda ref: (ref.started_at, ref.run_id), reverse=True)
    if not refs:
        raise SourceError("no readable run folders found")
    if run_id is not None:
        _safe_child(source.root, run_id)
        refs = [ref for ref in refs if ref.run_id == run_id]
        if not refs:
            raise SourceError(f"unknown run {run_id!r}")

    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    if web_dir:
        ui = Path(web_dir)
    else:
        from .server import default_web_dir

        ui = default_web_dir()
    if not ui.is_dir():
        raise SourceError(f"dashboard UI directory not found: {ui}")
    _copy_tree(ui, root)

    rows: list[dict[str, Any]] = []
    entries: list[tuple[dict[str, Any], Any]] = []
    runs_by_id: dict[str, Any] = {}
    for ref in refs:
        rid = ref.run_id
        data = source.load_run(rid)
        if data.error:
            if run_id is not None:
                raise SourceError(f"run {rid!r} could not be read: {data.error}")
            continue
        run_dir = _safe_child(root / "runs", rid)
        run_dir.mkdir(parents=True, exist_ok=True)
        ledger_path = _safe_child(source.root, rid) / LEDGER_NAME
        if ledger_path.is_symlink() or not ledger_path.is_file():
            if run_id is not None:
                raise SourceError("selected run ledger is missing or is a symlink")
            continue
        shutil.copyfile(ledger_path, run_dir / LEDGER_NAME)
        result_path = _safe_child(source.root, rid) / RESULT_NAME
        if result_path.is_file() and not result_path.is_symlink():
            shutil.copyfile(result_path, run_dir / RESULT_NAME)
        row = run_row(data)
        detail = run_detail(data)
        rows.append(row)
        entries.append((row, detail))
        events = {"run_id": rid, "from": 0,
                  "events": [event_view(i, event) for i, event in enumerate(data.events)],
                  "count": len(data.events), "total": len(data.events)}
        runs_by_id[rid] = {
            "detail": detail,
            "events": events,
            "replay": {"events": events["events"]},
            "ledger": f"runs/{rid}/{LEDGER_NAME}",
            "graph": build_graph_view(data),
            "codegraph": build_code_graph(data),
        }
    if not runs_by_id:
        raise SourceError("no readable run folders found")
    selected = run_id or refs[0].run_id
    if selected not in runs_by_id:
        selected = next(iter(runs_by_id))
    total = len(rows)
    repos = {
        rid: {**build_repo_detail(rid, group), "runs_considered": total, "runs_total": total}
        for rid, group in group_by_repo(entries).items()
    }
    bundle = {
        "info": {"source": source.label, "stages_note": "nothing could be proven is not safe"},
        "runs": {"source": source.label, "runs": rows, "page": 1, "per_page": max(1, total), "total": total,
                 "pages": 1},
        "trends": {"points": build_trends(rows), "limit": total, "total": total},
        "repos": {"source": source.label, "repos": build_repo_index(entries), "runs_considered": total, "runs_total": total},
        "reposById": repos,
        "runsById": runs_by_id,
    }
    (root / "data").mkdir(exist_ok=True)
    for name in ("info", "runs", "trends", "repos"):
        (root / "data" / f"{name}.json").write_bytes(_json_bytes(bundle[name]))
    (root / "data" / "run.json").write_bytes(_json_bytes(bundle["runsById"][selected]))
    for rid, run_bundle in runs_by_id.items():
        (root / "data" / f"run-{rid}.json").write_bytes(_json_bytes(run_bundle))
    (root / "static.js").write_text(_static_script(bundle), encoding="utf-8", newline="\n")
    # Load the offline adapter on every page before the view logic runs.
    for html_path in sorted(root.glob("*.html")):
        html = html_path.read_text(encoding="utf-8")
        if "static.js" not in html:
            html = html.replace(
                '<script src="dc-lite.js"></script>',
                '<script src="static.js"></script>\n<script src="dc-lite.js"></script>',
                1,
            )
        html_path.write_text(html, encoding="utf-8", newline="\n")
    return root
