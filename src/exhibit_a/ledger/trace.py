"""The trace of one run: its ledger events as ordered, typed, bounded steps.

``build_trace`` reads the events of one ``run_id`` and returns a ``TraceStep`` per event, in
ledger order, grouped by suspicion (run-level steps such as the baseline come first, then
each suspicion in order of first appearance; inside a group the ledger order is kept). The
ledger already holds every stage of the proof loop; nothing is recomputed or inferred here.

Ledger content is untrusted: ``summary`` and ``details`` are built from model output (a
suspicion's hypothesis, a verdict's reason, a fixer's error text). This module only ever
reads that content as data: it is never evaluated, formatted into code or used as a path.
Every string is stripped of control characters (so it cannot move a terminal cursor or
inject escape sequences) and cut to ``MAX_STRING``; lists, mappings and nesting depth are
capped as well, so a hostile ledger cannot produce an unbounded trace.

Two kinds of time are kept per step. ``latency_ms`` is what the model call reported (zero
for steps that are not model calls). ``wall_ms`` is the wall-clock gap from this event to
the next event of the run, so the wall times of all steps add up to the run's duration.
Totals are summed in ledger order exactly as ``Ledger.totals`` does, so cost and tokens
match ``exhibit-a ledger`` to the last digit.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..schemas import Event, EventType
from .ledger import Ledger

MAX_STRING = 240  # characters kept of any ledger string
MAX_SUMMARY = 200
MAX_ID = 128
MAX_ITEMS = 20  # entries kept of any list or mapping inside details
MAX_DEPTH = 4
MAX_STEPS = 20_000  # a run with more events than this is refused, not truncated

STAGES = (
    "INTAKE", "BASELINE", "SCAN", "SUSPECT", "EXPLOIT", "RUN",
    "FIX", "VERIFY", "VERDICT", "PACKAGE",
)


@dataclass(frozen=True)
class TraceStep:
    """One ledger event, as a step of the run."""

    seq: int  # 1-based position of the event among the events of this run
    stage: str  # one of STAGES
    type: str  # the EventType value
    role: str
    model: str
    suspicion_id: str  # "" for run-level steps
    summary: str
    tokens_in: int
    tokens_out: int
    cost_usd: float
    latency_ms: int
    timestamp: str
    wall_ms: int | None  # gap to the next event of the run; None for the last one
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq, "stage": self.stage, "type": self.type, "role": self.role,
            "model": self.model, "suspicion_id": self.suspicion_id, "summary": self.summary,
            "tokens_in": self.tokens_in, "tokens_out": self.tokens_out,
            "cost_usd": self.cost_usd, "latency_ms": self.latency_ms,
            "timestamp": self.timestamp, "wall_ms": self.wall_ms, "details": self.details,
        }


# -- bounding untrusted text --------------------------------------------------------------


def clean(value: Any, limit: int = MAX_STRING) -> str:
    """A string safe to print on one line: control characters and newlines become spaces."""
    text = value if isinstance(value, str) else ""
    text = "".join(" " if (ord(ch) < 32 or 0x7F <= ord(ch) < 0xA0 or ch in "\u2028\u2029") else ch
                   for ch in text[: limit * 4])
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def bound(value: Any, depth: int = 0) -> Any:
    """A JSON-safe, size-capped copy of ``value``; never evaluates or formats it."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return clean(value)
    if depth >= MAX_DEPTH:
        return "…"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_ITEMS:
                out["…"] = f"{len(value) - MAX_ITEMS} more"
                break
            out[clean(key if isinstance(key, str) else str(key), 64)] = bound(item, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        items = [bound(item, depth + 1) for item in value[:MAX_ITEMS]]
        if len(value) > MAX_ITEMS:
            items.append(f"… {len(value) - MAX_ITEMS} more")
        return items
    return clean(str(value))


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _pick(payload: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {key: bound(payload[key]) for key in keys if key in payload}


# -- one event -> one step ----------------------------------------------------------------


def _suspicion_id(event: Event) -> str:
    payload = event.payload
    sid = payload.get("suspicion_id")
    if not isinstance(sid, str):
        sid = _dict(payload.get("suspicion")).get("id")
    return clean(sid, MAX_ID)


def _stage(event: Event) -> str:
    kind, payload = event.type, event.payload
    if kind == EventType.PR_OPENED:
        return "INTAKE"
    if kind == EventType.SCAN_DONE:
        return "SCAN"
    if kind == EventType.BASELINE_DONE:
        return "VERIFY" if payload.get("on") == "fixed" or "suspicion_id" in payload else "BASELINE"
    if kind == EventType.SUSPICION_RAISED:
        return "SUSPECT"
    if kind == EventType.EXPLOIT_WRITTEN:
        return "EXPLOIT"
    if kind in (EventType.RUN_STARTED, EventType.ORACLE_EVENT):
        fixed = payload.get("on") == "fixed" or payload.get("after_fix") is True
        return "VERIFY" if fixed else "RUN"
    if kind == EventType.FIX_PROPOSED:
        return "FIX"
    if kind in (EventType.BYPASS_ATTEMPT, EventType.BYPASS_RESULT):
        return "VERIFY"
    if kind == EventType.VERDICT:
        return "VERDICT"
    return "PACKAGE"  # EventType.PACKAGED, the last member


def _where(location: dict[str, Any]) -> str:
    file, line = clean(location.get("file"), 100), location.get("line")
    if not file:
        return ""
    return f"{file}:{line}" if isinstance(line, int) and not isinstance(line, bool) else file


def _describe(event: Event) -> tuple[str, dict[str, Any]]:
    """The one-line summary and the bounded details of an event."""
    kind, p = event.type, event.payload

    if kind == EventType.PR_OPENED:
        return "pull request opened", {"payload": bound(p)}

    if kind == EventType.SCAN_DONE:
        status = clean(p.get("status"), 40) or "done"
        reason = clean(p.get("reason"), 120)
        text = f"scan {status}" + (f": {reason}" if reason else "")
        return text, {"payload": bound(p)}

    if kind == EventType.BASELINE_DONE:
        ok = p.get("ok") is True
        outcome = clean(p.get("outcome"), 40)
        on_fixed = p.get("on") == "fixed" or "suspicion_id" in p
        subject = "baseline on the fixed code" if on_fixed else "project baseline"
        text = f"{subject} {'passed' if ok else 'did not pass'}"
        text += f" ({outcome})" if outcome and not (ok and outcome == "passed") else ""
        return text, _pick(p, "ok", "outcome", "on", "flags")

    if kind == EventType.SUSPICION_RAISED:
        s = _dict(p.get("suspicion"))
        where = _where(_dict(s.get("location")))
        text = f"suspicion {clean(s.get('id'), 60) or '?'}: {clean(s.get('class'), 60) or '?'}"
        text += f" at {where}" if where else ""
        entry = clean(s.get("entry_point"), 60)
        text += f" via {entry}" if entry else ""
        details: dict[str, Any] = {"suspicion": bound(s)}
        if "graph" in p:
            details["graph"] = bound(p["graph"])
        return text, details

    if kind == EventType.EXPLOIT_WRITTEN:
        return f"exploit test written: {clean(p.get('test_path'), 120)}", _pick(p, "test_path")

    if kind == EventType.RUN_STARTED:
        n, of = p.get("run"), p.get("of")
        count = f"{n}/{of} " if isinstance(n, int) and isinstance(of, int) else ""
        target = "fixed" if p.get("on") == "fixed" or p.get("after_fix") is True else "vulnerable"
        return f"sandbox run {count}on the {target} code", _pick(p, "run", "of", "on", "after_fix")

    if kind == EventType.ORACLE_EVENT:
        seen = _dict(p.get("event"))
        access = clean(seen.get("access"), 16)
        what = f"{access} access to" if access and access != "unknown" else "access to"
        text = f"oracle saw {what} {clean(seen.get('path'), 80)}"
        if seen.get("mode") is not None:
            text += f" (mode {clean(seen.get('mode'), 16)})"
        if isinstance(p.get("run"), int):
            text += f" in run {p['run']}"
        return text, {**_pick(p, "run", "on", "after_fix"), "event": bound(seen)}

    if kind == EventType.FIX_PROPOSED:
        if p.get("applied") is True:
            text = "fix proposed and applied to a copy of the code"
        else:
            error = clean(p.get("error"), 120)
            text = "fix proposed but not applied" + (f": {error}" if error else "")
        # The ledger records that a fix was applied, not its edits or files; those are in
        # the finding package (fix.patch) of a proven case.
        return text, _pick(p, "applied", "error")

    if kind == EventType.BYPASS_ATTEMPT:
        return f"bypass attempt: {clean(p.get('name'), 100) or '?'}", _pick(p, "name")

    if kind == EventType.BYPASS_RESULT:
        name = clean(p.get("name"), 100) or "?"
        if p.get("error") is True:
            result = "could not run"
        else:
            result = "BYPASSED the fix" if p.get("bypassed") is True else "did not bypass the fix"
        return f"bypass {name}: {result}", _pick(p, "name", "bypassed", "error")

    if kind == EventType.VERDICT:
        verdict = clean(p.get("verdict"), 40) or "?"
        notes = [label for key, label in (("fix_verified", "fix verified"),
                                          ("fix_incomplete", "fix incomplete")) if p.get(key) is True]
        reason = clean(p.get("reason"), 100)
        text = f"verdict {verdict}" + (f" ({', '.join(notes)})" if notes else "")
        text += f": {reason}" if reason else ""
        return text, _pick(p, "verdict", "reason", "reason_code", "effect", "fix_verified",
                           "fix_incomplete", "fix_detail")

    notes = [label for key, label in (("fix_verified", "fix verified"),
                                      ("fix_incomplete", "fix incomplete")) if p.get(key) is True]
    text = f"finding packaged: {clean(p.get('path'), 100)}" + (f" ({', '.join(notes)})" if notes else "")
    return text, _pick(p, "path", "fix_verified", "fix_incomplete")


def _parse_ts(value: str) -> datetime | None:
    try:
        stamp = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    return stamp if stamp.tzinfo is not None else None  # naive and aware stamps do not mix


def _wall_gaps(events: Sequence[Event]) -> list[int | None]:
    stamps = [_parse_ts(event.ts) for event in events]
    gaps: list[int | None] = []
    for current, following in zip(stamps, stamps[1:]):
        if current is None or following is None or following < current:
            gaps.append(None)
        else:
            gaps.append(round((following - current).total_seconds() * 1000))
    gaps.append(None)
    return gaps


# -- the trace ----------------------------------------------------------------------------


def trace_events(events: Sequence[Event]) -> list[TraceStep]:
    """Steps for events already filtered to one run, grouped by suspicion."""
    if len(events) > MAX_STEPS:
        raise ValueError(f"run has {len(events)} events; the trace shows at most {MAX_STEPS}")
    gaps = _wall_gaps(events)
    steps: list[TraceStep] = []
    for index, event in enumerate(events):
        summary, details = _describe(event)
        steps.append(TraceStep(
            seq=index + 1, stage=_stage(event), type=event.type.value,
            role=clean(event.role, 40), model=clean(event.model, 60),
            suspicion_id=_suspicion_id(event), summary=clean(summary, MAX_SUMMARY),
            tokens_in=event.tokens_in, tokens_out=event.tokens_out, cost_usd=event.cost_usd,
            latency_ms=event.latency_ms, timestamp=clean(event.ts, 40), wall_ms=gaps[index],
            details=details,
        ))
    return group_by_suspicion(steps)


def build_trace(ledger_path: str | Path, run_id: str) -> list[TraceStep]:
    """The ordered steps one run took, read from its ledger.

    Raises ``ValueError`` for a corrupt ledger line (as ``Ledger`` does) or a run with more
    than ``MAX_STEPS`` events; an unknown run id gives an empty list.
    """
    events: list[Event] = []
    for event in Ledger(ledger_path).replay(run_id):
        events.append(event)
        if len(events) > MAX_STEPS:
            raise ValueError(f"run {clean(run_id, 60)!r} has more than {MAX_STEPS} events")
    return trace_events(events)


def group_by_suspicion(steps: Sequence[TraceStep]) -> list[TraceStep]:
    """Run-level steps first, then each suspicion's steps; the ledger order is kept inside."""
    order: list[str] = []
    for step in sorted(steps, key=lambda s: s.seq):
        if step.suspicion_id not in order:
            order.append(step.suspicion_id)
    if "" in order:
        order.remove("")
        order.insert(0, "")
    rank = {sid: i for i, sid in enumerate(order)}
    return sorted(steps, key=lambda s: (rank[s.suspicion_id], s.seq))


def groups(steps: Sequence[TraceStep]) -> list[tuple[str, list[TraceStep]]]:
    """``(suspicion_id, steps)`` pairs in trace order; the id is "" for run-level steps."""
    out: list[tuple[str, list[TraceStep]]] = []
    for step in steps:
        if not out or out[-1][0] != step.suspicion_id:
            out.append((step.suspicion_id, []))
        out[-1][1].append(step)
    return out


def totals(steps: Sequence[TraceStep]) -> dict[str, Any]:
    """Tokens, cost and time over ``steps``, summed in ledger order like ``Ledger.totals``."""
    result: dict[str, Any] = {"steps": len(steps), "tokens_in": 0, "tokens_out": 0,
                              "cost_usd": 0.0, "latency_ms": 0, "wall_ms": 0}
    for step in sorted(steps, key=lambda s: s.seq):
        result["tokens_in"] += step.tokens_in
        result["tokens_out"] += step.tokens_out
        result["cost_usd"] += step.cost_usd
        result["latency_ms"] += step.latency_ms
        result["wall_ms"] += step.wall_ms or 0
    return result


def trace_to_dict(run_id: str, steps: Sequence[TraceStep]) -> dict[str, Any]:
    """The JSON form: the steps, one block per suspicion, and the run totals."""
    return {
        "run_id": clean(run_id, 128),
        "steps": [step.to_dict() for step in steps],
        "groups": [
            {"suspicion_id": sid, "seqs": [s.seq for s in group], "totals": totals(group)}
            for sid, group in groups(steps)
        ],
        "totals": totals(steps),
    }


# -- plain text ---------------------------------------------------------------------------

_HEADERS = ("STEP", "STAGE", "ROLE", "MODEL", "TOK IN", "TOK OUT", "COST USD", "LATENCY", "WALL")


def _seconds(ms: int | None) -> str:
    return "-" if ms is None else f"{ms / 1000:.2f}s"


def _row(step: TraceStep) -> list[str]:
    return [
        str(step.seq), step.stage, step.role or "-", step.model or "-",
        str(step.tokens_in) if step.tokens_in else "-",
        str(step.tokens_out) if step.tokens_out else "-",
        f"{step.cost_usd:.6f}" if step.cost_usd else "-",
        _seconds(step.latency_ms) if step.latency_ms else "-",
        _seconds(step.wall_ms),
    ]


def _total_row(label: str, summary: dict[str, Any]) -> list[str]:
    return [
        "", label, "", "", str(summary["tokens_in"]), str(summary["tokens_out"]),
        f"{summary['cost_usd']:.6f}", _seconds(summary["latency_ms"]), _seconds(summary["wall_ms"]),
    ]


def render_text(run_id: str, steps: Sequence[TraceStep]) -> str:
    """Plain aligned text: one block per suspicion with a subtotal, then the run total."""
    title = f"trace of run {clean(run_id, 128)}: {len(steps)} steps"
    if not steps:
        return title + "\n(no events for this run id in the ledger)"
    # (kind, cells, summary): kind is "head", "step", "sub" or "total".
    lines: list[tuple[str, list[str], str]] = []
    for sid, group in groups(steps):
        lines.append(("head", [], f"suspicion {sid}" if sid else "run"))
        lines.extend(("step", _row(step), step.summary) for step in group)
        lines.append(("sub", _total_row("subtotal", totals(group)), ""))
    lines.append(("total", _total_row("TOTAL", totals(steps)), ""))

    rows = [cells for kind, cells, _ in lines if cells]
    widths = [max(len(header), *(len(row[i]) for row in rows)) for i, header in enumerate(_HEADERS)]
    numeric = {0, 4, 5, 6, 7, 8}

    def fmt(cells: Sequence[str]) -> str:
        return "  ".join(
            cell.rjust(widths[i]) if i in numeric else cell.ljust(widths[i])
            for i, cell in enumerate(cells)
        )

    out = [title, "", fmt(_HEADERS) + "  SUMMARY"]
    out.append("  ".join("-" * width for width in widths) + "  -------")
    for kind, cells, summary in lines:
        if kind == "head":
            out.append("")
            out.append(f"[{summary}]")
        elif kind == "step":
            out.append(f"{fmt(cells)}  {summary}")
        else:
            if kind == "total":
                out.append("")
            out.append(fmt(cells).rstrip())
    return "\n".join(out)
