"""View-models for the dashboard: runs list rows, run detail, trends.

These functions are pure: validated events (plus the optional CI result) in,
JSON-ready dicts out. Status and verdict counts come from
``exhibit_a.ci.summary.build_result`` so the dashboard and the CI comment can
never disagree; the CI result file only contributes facts the ledger cannot
hold (engine exit code, risk gate, skip reason).

Wording rule (SPEC.md section 1): a run with nothing proven says "nothing
could be proven", never "safe".

Two payload shapes are understood: the real loop's (``loop/pipeline.py``:
``oracle_event`` carries an ``event`` with the canary path, mode and stack;
``packaged`` carries ``fix_verified``) and the live-view sample's (``verdict``
carries ``evidence``; ``oracle_event`` carries ``effect``/``observed``).
Every lookup tolerates missing or mistyped keys.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any
from typing import get_args

from ..ci.summary import build_result
from ..graph import build_graph, find_paths, functions_in
from ..oracle.oracle import Effect
from ..schemas import Event, EventType, VerdictValue
from ..schemas.graph import CodeGraph, ReachPath
from ..ledger.trace import trace_events, trace_to_dict
from .sources import RunData

#: The verdict loop stages shown on the run timeline, in order.
STAGES = ("BASELINE", "SUSPECT", "EXPLOIT", "RUN", "VERDICT", "FIX", "VERIFY", "PACKAGE")

#: Verdicts plotted on the trends chart.
TREND_VERDICTS = (
    VerdictValue.PROVEN.value,
    VerdictValue.DISCARDED_UNPROVEN.value,
    VerdictValue.INVALID_TEST.value,
)

#: Display caps applied to everything sent to the browser.
MAX_STRING = 2000
MAX_ITEMS = 200
MAX_DEPTH = 8
MAX_FRAMES = 60

_GRAPH_CACHE: dict[str, tuple[str, dict[str, Any]]] = {}
EFFECTS = tuple(get_args(Effect))

_WRITE_MODE = set("wax+")
_SHA = re.compile(r"^[0-9a-f]{7,64}\Z")

_HEADLINES = {
    "completed": "Nothing could be proven",
    "aborted": "Run aborted (baseline failed or a step was rejected): nothing could be proven",
    "timed_out": "Run timed out: nothing could be proven in the time allowed",
    "not_run": "No verdicts recorded: nothing could be proven",
    "skipped": "Exploits not run (risk gate): nothing could be proven",
}


# -- small helpers ----------------------------------------------------------------------


def clean(value: Any, depth: int = 0) -> Any:
    """Bound an untrusted JSON value for display: depth, item count, string length."""
    if isinstance(value, str):
        return value if len(value) <= MAX_STRING else value[: MAX_STRING - 1] + "…"
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    if depth >= MAX_DEPTH:
        return "…"
    if isinstance(value, dict):
        items = list(value.items())[:MAX_ITEMS]
        return {clean(str(k)): clean(v, depth + 1) for k, v in items}
    if isinstance(value, (list, tuple)):
        return [clean(v, depth + 1) for v in list(value)[:MAX_ITEMS]]
    return clean(str(value), depth)


def _text(value: Any, limit: int = 300) -> str:
    if isinstance(value, bool) or value is None:
        return ""
    text = value if isinstance(value, str) else str(value) if isinstance(value, (int, float)) else ""
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _parse_ts(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return parsed if parsed.tzinfo is not None else None


def _duration(events: Sequence[Event]) -> float | None:
    if not events:
        return None
    start, end = _parse_ts(events[0].ts), _parse_ts(events[-1].ts)
    if start is None or end is None or end < start:
        return None
    return round((end - start).total_seconds(), 3)


def _sid(event: Event) -> str:
    return _text(event.payload.get("suspicion_id"), 128)


def stage_of(event: Event) -> str:
    """The loop stage an event belongs to ("" for pre-loop events)."""
    kind, payload = event.type, event.payload
    if kind == EventType.BASELINE_DONE:
        return "VERIFY" if payload.get("on") == "fixed" or "suspicion_id" in payload else "BASELINE"
    if kind == EventType.SUSPICION_RAISED:
        return "SUSPECT"
    if kind == EventType.EXPLOIT_WRITTEN:
        return "EXPLOIT"
    if kind in (EventType.RUN_STARTED, EventType.ORACLE_EVENT):
        fixed = payload.get("on") == "fixed" or payload.get("after_fix") is True
        return "VERIFY" if fixed else "RUN"
    if kind == EventType.VERDICT:
        return "VERDICT"
    if kind == EventType.FIX_PROPOSED:
        return "FIX"
    if kind in (EventType.BYPASS_ATTEMPT, EventType.BYPASS_RESULT):
        return "VERIFY"
    if kind == EventType.PACKAGED:
        return "PACKAGE"
    return ""


def _effect_type(oracle: dict[str, Any]) -> str:
    """canary_read / canary_write from an oracle event's open mode."""
    mode = _text(oracle.get("mode"), 16).lower()
    if any(char in _WRITE_MODE for char in mode):
        return "canary_write"
    declared = _text(oracle.get("type"), 32)
    if declared in ("canary_read", "canary_write"):
        return declared
    return "canary_read" if "r" in mode else "unknown"


def event_line(event: Event) -> str:
    """One human-readable line for the timeline and the replay."""
    p = event.payload
    kind = event.type.value
    sid = _sid(event) or "?"
    if kind == "pr_opened":
        pr = _text(p.get("pr"), 64)
        label = f"#{pr.lstrip('#')}" if pr.lstrip("#").isdigit() else pr
        return f"PR opened: {' '.join(x for x in (label, _text(p.get('title'), 160)) if x) or 'unknown'}"
    if kind == "scan_done":
        return f"Scan: {_text(p.get('language')) or 'unknown language'} / {_text(p.get('test_cmd')) or 'unknown test command'}"
    if kind == "baseline_done":
        if "ok" in p:
            ok = "passed" if p.get("ok") is True else "did not pass"
            where = " on the fixed code" if stage_of(event) == "VERIFY" else ""
            return f"Baseline{where} {ok}" + (f" ({_text(p.get('outcome'))})" if _text(p.get("outcome")) else "")
        return f"Baseline: {_int(p.get('passed')) or 0} passed, {_int(p.get('failed')) or 0} failed"
    if kind == "suspicion_raised":
        s = _dict(p.get("suspicion")) or p
        loc = _dict(s.get("location"))
        where = f"{_text(loc.get('file'))}:{_int(loc.get('line')) or 0}" if _text(loc.get("file")) else "unknown location"
        return f"Suspicion {_text(s.get('id')) or '?'}: {_text(s.get('class')) or 'unknown class'} at {where}"
    if kind == "exploit_written":
        return f"Exploit test written for {sid}"
    if kind == "run_started":
        target = "fixed" if stage_of(event) == "VERIFY" else "vulnerable"
        run, of = _int(p.get("run")) or _int(p.get("attempt")), _int(p.get("of"))
        count = f" {run}/{of}" if run and of else (f" {run}" if run else "")
        return f"Run{count} on {target} code ({sid})"
    if kind == "oracle_event":
        inner = _dict(p.get("event"))
        if inner:
            return f"Oracle: {_effect_type(inner)} of {_text(inner.get('path'), 160) or '?'} ({sid})"
        seen = "observed" if p.get("observed") is True else "not observed"
        return f"Oracle: {_text(p.get('effect')) or 'intended effect'} {seen} ({sid})"
    if kind == "verdict":
        reason = _text(p.get("reason"), 160)
        return f"Verdict {sid}: {_text(p.get('verdict')) or '?'}" + (f" ({reason})" if reason else "")
    if kind == "fix_proposed":
        if p.get("applied") is False:
            return f"Fix for {sid} rejected: {_text(p.get('error'), 160) or 'invalid patch'}"
        return f"Fix proposed for {sid}"
    if kind == "bypass_attempt":
        return f"Bypass variant {_text(p.get('name') or p.get('variant'), 120) or '?'} for {sid}"
    if kind == "bypass_result":
        name = _text(p.get("name") or p.get("variant"), 120) or "?"
        if p.get("error") is True:
            return f"Bypass {name}: could not run"
        won = p.get("bypassed") is True or p.get("succeeded") is True
        return f"Bypass {name}: {'BYPASSED the fix' if won else 'fix held'}"
    if kind == "packaged":
        verified = "fix verified" if p.get("fix_verified") is True else "fix not verified"
        return f"Packaged {sid} ({verified})"
    return kind


# -- runs list ---------------------------------------------------------------------


def _ledger_meta(events: Sequence[Event]) -> dict[str, Any]:
    for event in events:
        if event.type == EventType.PR_OPENED:
            p = event.payload
            commit = _text(p.get("commit"), 64)
            return {
                "repo": _text(p.get("repo"), 140),
                "pr": _text(p.get("pr"), 64),
                "commit": commit if _SHA.match(commit) else "",
                "branch": _text(p.get("branch"), 200),
                "synthetic": p.get("synthetic") is True,
            }
    return {}


def _headline(status: str, proven: int) -> str:
    if status == "unreadable":
        return "Run could not be read: nothing is shown"
    if proven:
        return f"{proven} proven finding{'s' if proven != 1 else ''}"
    return _HEADLINES.get(status, "Nothing could be proven")


def run_row(data: RunData) -> dict[str, Any]:
    """One row of the runs list."""
    ref = data.ref
    meta = _ledger_meta(data.events)
    row: dict[str, Any] = {
        "run_id": ref.run_id,
        "ledger_run_id": "",
        "repo": ref.repo or meta.get("repo", ""),
        "pr": ref.pr or meta.get("pr", ""),
        "commit": ref.commit or meta.get("commit", ""),
        "branch": ref.branch or meta.get("branch", ""),
        "url": ref.url,
        "synthetic": ref.synthetic or bool(meta.get("synthetic")),
        "started_at": ref.started_at or (data.events[0].ts if data.events else ""),
        "duration_s": _duration(data.events),
        "error": data.error,
        "risk": "",
        "status": "unreadable",
        "proven": 0,
        "verdicts": {v.value: 0 for v in VerdictValue},
        "suspicions_raised": 0,
        "dropped": 0,
        "flags": {},
        "ablated": False,
        "tokens_in": 0,
        "tokens_out": 0,
        "cost_usd": 0.0,
        "event_count": len(data.events),
    }
    if not data.error:
        extra = data.result or {}
        try:
            result = build_result(
                data.events,
                run_id=data.events[-1].run_id if data.events else None,
                engine_exit=extra.get("engine_exit"),
                risk=extra.get("risk"),
                skipped_reason=extra.get("skipped_reason") or "",
            )
        except (TypeError, ValueError, AttributeError):
            # Valid Event lines whose payloads have shapes the CI projection rejects
            # (e.g. ``flags`` that is not an object): unreadable, never partial.
            row["error"] = "ledger payloads do not have the expected shapes"
            row["headline"] = _headline("unreadable", 0)
            return row
        if not data.events and extra.get("status") in ("skipped", "timed_out"):
            result["status"] = extra["status"]
        row.update(
            {
                "ledger_run_id": _text(result["run_id"], 128),
                "status": result["status"],
                "proven": result["proven"],
                "verdicts": {_text(k, 64): v for k, v in result["verdicts"].items()},
                "suspicions_raised": result["suspicions_raised"],
                "dropped": result["dropped"],
                "flags": clean(result["flags"]),
                "ablated": result["ablated"],
                "risk": _text((result.get("risk") or {}).get("risk"), 16),
                "skipped_reason": _text(result.get("skipped_reason"), 300),
                "tokens_in": result["tokens_in"],
                "tokens_out": result["tokens_out"],
                "cost_usd": result["cost_usd"],
            }
        )
    row["headline"] = _headline(row["status"], row["proven"])
    return row


# -- run detail ---------------------------------------------------------------------


def _stages(events: Sequence[Event]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {name: {"name": name, "count": 0, "first_ts": "", "first_seq": None} for name in STAGES}
    for seq, event in enumerate(events):
        stage = stage_of(event)
        if not stage:
            continue
        slot = seen[stage]
        slot["count"] += 1
        if slot["first_seq"] is None:
            slot["first_seq"] = seq
            slot["first_ts"] = event.ts
    return [{**slot, "reached": slot["count"] > 0} for slot in seen.values()]


def _frames(stack: Any, entry_point: str) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    for raw in (stack if isinstance(stack, list) else [])[:MAX_FRAMES]:
        frame = _dict(raw)
        qualname = _text(frame.get("qualname"), 200)
        function = _text(frame.get("function"), 200)
        frames.append(
            {
                "file": _text(frame.get("file"), 300),
                "function": function,
                "qualname": qualname,
                "line": _int(frame.get("line")),
                "admitted": frame.get("admitted") if isinstance(frame.get("admitted"), bool) else None,
                "entry_point": bool(entry_point) and entry_point in (qualname, function),
            }
        )
    return frames


def _evidence(sid: str, entry_point: str, events: Sequence[Event], verdict: dict[str, Any]) -> dict[str, Any]:
    """Collect the proof of one proven suspicion from its events."""
    own = [e for e in events if _sid(e) == sid]
    declared = _dict(verdict.get("evidence"))
    vulnerable_runs = [e for e in own if e.type == EventType.RUN_STARTED and stage_of(e) == "RUN"]
    fixed_runs = [e for e in own if e.type == EventType.RUN_STARTED and stage_of(e) == "VERIFY"]
    oracle_vuln = [e for e in own if e.type == EventType.ORACLE_EVENT and stage_of(e) == "RUN"]
    oracle_fixed = [e for e in own if e.type == EventType.ORACLE_EVENT and stage_of(e) == "VERIFY"]

    effect: dict[str, Any] = {"type": "unknown", "path": "", "mode": "", "via_symlink": False, "observed": bool(oracle_vuln)}
    frames: list[dict[str, Any]] = []
    if oracle_vuln:
        first = oracle_vuln[0].payload
        inner = _dict(first.get("event"))
        if inner:
            effect.update(
                type=_effect_type(inner),
                path=_text(inner.get("path"), 300),
                mode=_text(inner.get("mode"), 16),
                via_symlink=inner.get("via_symlink") is True,
            )
            frames = _frames(inner.get("stack"), entry_point)
        else:
            effect.update(type=_text(first.get("effect"), 120) or "unknown", observed=first.get("observed") is True)
    declared_oracle = _dict(declared.get("oracle"))
    if not frames and declared_oracle.get("events"):
        events_list = declared_oracle.get("events")
        inner = _dict(events_list[0]) if isinstance(events_list, list) and events_list else {}
        frames = _frames(inner.get("stack"), entry_point)

    fixes = [e for e in own if e.type == EventType.FIX_PROPOSED]
    exploits = [e for e in own if e.type == EventType.EXPLOIT_WRITTEN]
    fix = fixes[-1].payload if fixes else {}
    fixed_baselines = [e for e in own if e.type == EventType.BASELINE_DONE]
    packaged = [e for e in own if e.type == EventType.PACKAGED]
    pkg = packaged[-1].payload if packaged else {}
    fixed_still_observed = any(
        e.payload.get("observed") is True or bool(_dict(e.payload.get("event"))) for e in oracle_fixed
    )
    if "fix_verified" in pkg:
        fix_verified = pkg.get("fix_verified") is True
    else:
        fix_verified = declared.get("passes_on") == "fixed" and bool(packaged)

    bypasses = [
        {
            "name": _text(e.payload.get("name") or e.payload.get("variant"), 200),
            "bypassed": e.payload.get("bypassed") is True or e.payload.get("succeeded") is True,
            "error": e.payload.get("error") is True,
        }
        for e in own
        if e.type == EventType.BYPASS_RESULT
    ]
    provenance = _dict(declared.get("provenance"))
    return {
        "fails_on_vulnerable": {
            "runs": len(vulnerable_runs) or _int(declared.get("runs")) or 0,
            "of": _int(vulnerable_runs[0].payload.get("of")) if vulnerable_runs else _int(declared.get("runs")),
            "oracle_events": len(oracle_vuln),
        },
        "effect": effect,
        "provenance": {
            "entry_point": entry_point or _text(provenance.get("entry_point"), 200),
            "frames": frames,
            "frames_truncated": len(frames) >= MAX_FRAMES,
        },
        "fix": {
            "proposed": bool(fixes),
            "applied": bool(fixes) and fix.get("applied") is not False,
            "error": _text(fix.get("error"), 300),
            "patch_path": _text(fix.get("patch_path"), 300),
            "diff": _text(fix.get("patch") or fix.get("diff"), MAX_STRING),
        },
        "exploit_test": _text(exploits[-1].payload.get("test_path"), 300) if exploits else _text(declared.get("test_path"), 300),
        "passes_on_fixed": {
            "runs": len(fixed_runs),
            "effect_seen_after_fix": fixed_still_observed,
            "baseline_ok": (fixed_baselines[-1].payload.get("ok") is True) if fixed_baselines else None,
            "fix_verified": fix_verified,
        },
        "bypass": {
            "tried": len(bypasses),
            "succeeded": sum(1 for b in bypasses if b["bypassed"]),
            "variants": bypasses[:50],
        },
        "package": _text(pkg.get("path") or pkg.get("dir"), 300),
        "cwe": _text(verdict.get("cwe") or declared.get("cwe"), 80),
    }


def _costs(events: Sequence[Event]) -> dict[str, Any]:
    roles: dict[str, dict[str, Any]] = {}
    stages: dict[str, dict[str, Any]] = {}
    for event in events:
        role = _text(event.role, 64) or "engine"
        stage = stage_of(event) or "INTAKE"
        for bucket, key in ((roles, role), (stages, stage)):
            item = bucket.setdefault(key, {"cost_usd": 0.0, "tokens_in": 0, "tokens_out": 0, "events": 0})
            item["cost_usd"] += event.cost_usd
            item["tokens_in"] += event.tokens_in
            item["tokens_out"] += event.tokens_out
            item["events"] += 1
    for bucket in (roles, stages):
        for item in bucket.values():
            item["cost_usd"] = round(item["cost_usd"], 8)
    return {"by_role": roles, "by_stage": stages}


def _tree_key(tree: Path | None) -> str:
    if tree is None:
        return ""
    try:
        stat = tree.stat()
        return f"{tree}:{stat.st_mtime_ns}:{stat.st_size}"
    except OSError:
        return str(tree)


def _node_dump(node: Any, *, entry: bool = False, sink: bool = False, proven: bool = False) -> dict[str, Any]:
    return {
        "id": node.id,
        "kind": "sink" if sink else node.kind,
        "module": "" if sink else node.module,
        "name": node.name if not sink else node.id,
        "file": "" if sink else node.file,
        "line": 0 if sink else node.line,
        "start": 0 if sink else node.start,
        "end": 0 if sink else node.end,
        "entry_point": entry,
        "sink": sink,
        "proven": proven,
    }


def build_graph_view(data: RunData) -> dict[str, Any]:
    """Build the small entry-to-sink graph shown for a run.

    The graph is AST-only and is cached by run/tree.  A replay from GitHub can
    still show its ledger and findings, but has no local code tree to parse.
    """
    key = f"{data.ref.run_id}:{_tree_key(data.tree)}"
    cached = _GRAPH_CACHE.get(key)
    if cached is not None:
        return cached[1]
    empty = {"available": False, "reason": "run archive has no local code tree", "nodes": [], "edges": [],
             "paths": [], "effects": list(EFFECTS), "sink_rule": "", "entry_points": []}
    if data.error or data.tree is None:
        _GRAPH_CACHE[key] = (key, empty)
        return empty
    try:
        graph = build_graph(data.tree)
    except (OSError, ValueError):
        _GRAPH_CACHE[key] = (key, empty | {"reason": "code tree could not be parsed"})
        return _GRAPH_CACHE[key][1]

    suspicions: list[dict[str, Any]] = []
    proven_ids: set[str] = set()
    for event in data.events:
        if event.type == EventType.SUSPICION_RAISED:
            suspicion = _dict(event.payload.get("suspicion")) or event.payload
            if isinstance(suspicion, dict):
                suspicions.append(suspicion)
        elif event.type == EventType.VERDICT and _sid(event):
            if _text(event.payload.get("verdict"), 40) == VerdictValue.PROVEN.value:
                proven_ids.add(_sid(event))

    reports: list[tuple[str, Any, bool]] = []
    for suspicion in suspicions:
        location = _dict(suspicion.get("location"))
        file = _text(location.get("file"), 300)
        changed = functions_in(graph, file) if file else []
        if not changed:
            continue
        declared = [_text(suspicion.get("entry_point"), 200)] if _text(suspicion.get("entry_point"), 200) else []
        report = find_paths(graph, changed, declared_entries=declared)
        reports.extend((_text(suspicion.get("id"), 128), path, _text(suspicion.get("id"), 128) in proven_ids)
                       for path in report.paths)

    selected: set[str] = set()
    proven_paths: list[dict[str, Any]] = []
    proven_keys: set[tuple[Any, ...]] = set()
    entries: set[str] = set()
    sink_rule = ""
    for _, path, is_proven in reports:
        ids = list(dict.fromkeys(path.to_changed + path.to_sink))
        selected.update(ids)
        entries.add(path.entry)
        sink_rule = path.sink.target
        if is_proven:
            path_key = (path.entry, tuple(ids), path.sink.target, path.sink.line)
            if path_key in proven_keys:
                continue
            proven_keys.add(path_key)
            proven_paths.append({
                "entry": path.entry, "entry_point": path.oracle_entry_point,
                "nodes": ids, "sink": path.sink.target, "effect": path.sink.effect,
                "rule": path.sink.category, "confidence": path.confidence,
            })
    # Include one hop around the relevant path, while retaining only repository nodes.
    for edge in graph.edges:
        if edge.src in selected or edge.dst in selected:
            selected.add(edge.src)
            if edge.dst in {n.id for n in graph.nodes}:
                selected.add(edge.dst)
    nodes_by_id = {node.id: node for node in graph.nodes}
    node_rows = [
        _node_dump(nodes_by_id[node_id], entry=node_id in entries,
                   proven=any(node_id in p["nodes"] for p in proven_paths))
        for node_id in sorted(selected) if node_id in nodes_by_id
    ]
    edge_rows = []
    for edge in graph.edges:
        if edge.src not in selected:
            continue
        dst = edge.dst
        if dst not in selected and not any(p["sink"] == dst for p in proven_paths):
            continue
        if dst not in nodes_by_id and any(p["sink"] == dst for p in proven_paths):
            node_rows.append({"id": dst, "kind": "sink", "module": "", "name": dst, "file": "",
                              "line": 0, "start": 0, "end": 0, "entry_point": False,
                              "sink": True, "proven": True})
        edge_rows.append({"src": edge.src, "dst": dst, "kind": edge.kind, "line": edge.line,
                          "text": _text(edge.text, 200),
                          "proven": any(dst in p["nodes"] and edge.src in p["nodes"] for p in proven_paths)})
    result = {"available": True, "reason": "", "nodes": node_rows, "edges": edge_rows,
              "paths": proven_paths, "effects": list(EFFECTS), "sink_rule": sink_rule,
              "entry_points": sorted(entries), "stats": graph.stats.model_dump()}
    _GRAPH_CACHE[key] = (key, result)
    return result


def run_detail(data: RunData) -> dict[str, Any]:
    """Everything the run detail view shows, except the raw event list."""
    row = run_row(data)
    if row["error"]:
        return {"run": row, "stages": _stages([]), "proven": [], "discarded": [], "latency_ms": 0,
                "trace": trace_to_dict(row["run_id"], []), "costs": _costs([]), "graph": build_graph_view(data)}
    events = data.events
    suspicions: dict[str, dict[str, Any]] = {}
    verdicts: dict[str, dict[str, Any]] = {}
    for event in events:
        if event.type == EventType.SUSPICION_RAISED:
            s = _dict(event.payload.get("suspicion")) or event.payload
            sid = _text(s.get("id"), 128)
            if not sid or sid in suspicions:
                continue
            loc = _dict(s.get("location"))
            suspicions[sid] = {
                "id": sid,
                "class": _text(s.get("class"), 120),
                "file": _text(loc.get("file"), 300),
                "line": _int(loc.get("line")) or 0,
                "entry_point": _text(s.get("entry_point"), 200),
                "hypothesis": _text(s.get("hypothesis"), 600),
            }
        elif event.type == EventType.VERDICT and _sid(event):
            verdicts[_sid(event)] = event.payload  # latest verdict wins, as in ci/summary.py
    items: list[dict[str, Any]] = []
    for sid in list(suspicions) + [v for v in verdicts if v not in suspicions]:
        base = suspicions.get(sid) or {"id": sid, "class": "", "file": "", "line": 0, "entry_point": "", "hypothesis": ""}
        verdict = verdicts.get(sid, {})
        label = _text(verdict.get("verdict"), 64) or "not judged"
        item = {**base, "verdict": label, "reason": _text(verdict.get("reason"), 600), "evidence": None}
        if label == VerdictValue.PROVEN.value:
            item["evidence"] = _evidence(sid, base["entry_point"], events, verdict)
        items.append(item)
    steps = trace_events(events)
    return {
        "run": row,
        "stages": _stages(events),
        "proven": [i for i in items if i["verdict"] == VerdictValue.PROVEN.value],
        "discarded": [i for i in items if i["verdict"] != VerdictValue.PROVEN.value],
        "latency_ms": sum(e.latency_ms for e in events),
        "trace": trace_to_dict(row["run_id"], steps),
        "costs": _costs(events),
        "graph": build_graph_view(data),
    }


def event_view(seq: int, event: Event) -> dict[str, Any]:
    """One bounded event for the events API and the replay stream."""
    return {
        "seq": seq,
        "ts": _text(event.ts, 64),
        "type": event.type.value,
        "stage": stage_of(event),
        "role": _text(event.role, 64),
        "model": _text(event.model, 120),
        "tokens_in": event.tokens_in,
        "tokens_out": event.tokens_out,
        "cost_usd": event.cost_usd,
        "latency_ms": event.latency_ms,
        "summary": event_line(event),
        "payload": clean(event.payload),
    }


# -- trends ---------------------------------------------------------------------------


def build_trends(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Verdict counts per readable run, oldest first."""
    points = []
    for row in rows:
        if row.get("status") == "unreadable":
            continue
        verdicts = row.get("verdicts") or {}
        points.append(
            {
                "run_id": row["run_id"],
                "started_at": row.get("started_at", ""),
                "status": row.get("status", ""),
                "synthetic": bool(row.get("synthetic")),
                **{v.value: int(verdicts.get(v.value, 0)) for v in VerdictValue},
            }
        )
    return sorted(points, key=lambda p: (p["started_at"], p["run_id"]))
