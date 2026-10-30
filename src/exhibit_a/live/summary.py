"""Ledger summary: the view-model behind the live view panels.

``build_summary`` reduces an ordered event list to the pieces the UI shows:
the diff with suspect lines, the timeline, sandbox output, the red-to-green
moment, the wall of regression tests, and the counter of suspicions dropped
for lack of proof. The web client mirrors this logic in plain JS; the server
also exposes it as ``/api/summary`` so tests can assert on it without a
browser.

Payload conventions below are defensive on purpose: the engine is still
growing, so every lookup tolerates a missing key and falls back to "".
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ..schemas import Event, VerdictValue

#: Verdict value counted as "dropped for lack of proof" (SPEC.md section 3).
DROPPED_VALUE = VerdictValue.DISCARDED_UNPROVEN.value

#: Payload keys that carry sandbox output, checked in order.
OUTPUT_KEYS = ("stdout", "stderr", "output", "log")


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _suspicion_ref(payload: dict[str, Any]) -> dict[str, Any]:
    """Extract an id/class/file/line reference from a suspicion payload.

    Accepts both the nested shape ``{"suspicion": {...}}`` and the flat
    suspicion.json shape placed directly in the payload.
    """
    nested = payload.get("suspicion")
    cand = nested if isinstance(nested, dict) else payload
    location = cand.get("location")
    loc = location if isinstance(location, dict) else {}
    line = loc.get("line")
    return {
        "suspicion_id": str(cand.get("id", "")),
        "class": str(cand.get("class", "")),
        "file": str(loc.get("file", "")),
        "line": line if isinstance(line, int) else 0,
    }


def _short(value: str, limit: int = 120) -> str:
    value = " ".join(value.split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def summarize_event(event: Event) -> str:
    """One human-readable line describing an event for the timeline."""
    p = event.payload
    kind = event.type.value
    if kind == "pr_opened":
        diff = _text(p.get("diff"))
        if diff:
            return f"PR opened ({len(diff.splitlines())} diff lines)"
        return f"PR opened: {_short(str(p.get('pr', '')) or 'unknown')}"
    if kind == "scan_done":
        status = _text(p.get("status"))
        if status == "no_suspicions":
            return "Suspect: the adversary raised no usable suspicion"
        if status == "sliced":
            return f"Slice: {len(p.get('paths') or [])} reach path(s) from the code graph"
        lang = p.get("language", "") or "unknown language"
        return f"Scan done: {lang} / {p.get('test_cmd', '') or 'unknown test cmd'}"
    if kind == "baseline_done":
        return f"Baseline: {p.get('passed', 0)} passed, {p.get('failed', 0)} failed"
    if kind == "suspicion_raised":
        ref = _suspicion_ref(p)
        where = f"{ref['file']}:{ref['line']}" if ref["file"] else "unknown"
        label = ref["suspicion_id"] or "?"
        return f"Suspicion {label}: {ref['class'] or 'unknown'} at {where}"
    if kind == "exploit_written":
        return (
            f"Exploit written: {_text(p.get('test_path')) or 'unknown test'} "
            f"for {p.get('suspicion_id', '?')}"
        )
    if kind == "run_started":
        return f"Run started: {_text(p.get('test_path')) or 'unknown test'}"
    if kind == "oracle_event":
        effect = _text(p.get("effect")) or "intended effect"
        seen = "observed" if p.get("observed") else "not observed"
        return f"Oracle: {effect} {seen} (exit {p.get('exit_code', '?')})"
    if kind == "verdict":
        return f"Verdict {p.get('suspicion_id', '?')}: {p.get('verdict', '?')}"
    if kind == "fix_proposed":
        return f"Fix proposed: {_text(p.get('patch_path')) or 'patch'}"
    if kind == "bypass_attempt":
        return f"Bypass attempt: {_short(str(p.get('variant', '')) or 'variant')}"
    if kind == "bypass_result":
        won = "succeeded" if p.get("succeeded") else "failed"
        return f"Bypass {_short(str(p.get('variant', '')) or 'variant')}: {won}"
    if kind == "packaged":
        return f"Packaged: {_text(p.get('dir')) or 'evidence bundle'}"
    return kind


def _test_path_of(payload: dict[str, Any]) -> str:
    evidence = payload.get("evidence")
    if isinstance(evidence, dict) and _text(evidence.get("test_path")):
        return _text(evidence.get("test_path"))
    return _text(payload.get("test_path"))


def build_summary(events: Sequence[Event]) -> dict[str, Any]:
    """Reduce ordered events to the live view panels.

    Red-to-green rule: red is the first ``proven`` verdict (the exploit
    failed on vulnerable code for the right reason); green needs a
    ``fix_proposed`` after red followed by a ``packaged`` event (or an
    explicit ``exploit_passes: true`` hint after the fix).
    """
    ordered = list(events)
    diff = ""
    suspect_lines: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []
    sandbox_parts: list[str] = []
    regression_wall: list[dict[str, Any]] = []
    verdict_counts = {value.value: 0 for value in VerdictValue}
    red_at: str | None = None
    red_test = ""
    fix_index: int | None = None
    green_at: str | None = None

    for seq, event in enumerate(ordered):
        payload = event.payload
        kind = event.type.value
        timeline.append(
            {
                "seq": seq,
                "ts": event.ts,
                "type": kind,
                "role": event.role,
                "summary": summarize_event(event),
            }
        )
        if kind == "pr_opened" and not diff:
            diff = _text(payload.get("diff"))
        if kind == "suspicion_raised":
            suspect_lines.append(_suspicion_ref(payload))
        for key in OUTPUT_KEYS:
            text = _text(payload.get(key))
            if text:
                sandbox_parts.append(f"[{seq:03d} {kind}] {key}:\n{text.rstrip()}")
        if kind == "verdict":
            verdict = payload.get("verdict")
            if isinstance(verdict, str):
                verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
            if verdict == VerdictValue.PROVEN.value and red_at is None:
                red_at = event.ts
                red_test = _test_path_of(payload)
            if verdict == VerdictValue.PROVEN.value:
                regression_wall.append(
                    {
                        "suspicion_id": str(payload.get("suspicion_id", "")),
                        "test_path": _test_path_of(payload),
                        "ts": event.ts,
                    }
                )
        if kind == "fix_proposed" and red_at is not None and fix_index is None:
            fix_index = seq
        if (
            fix_index is not None
            and green_at is None
            and (
                kind == "packaged"
                or (kind == "oracle_event" and payload.get("observed") is False)
                or payload.get("exploit_passes") is True
            )
        ):
            green_at = event.ts

    runs: list[str] = []
    for event in ordered:
        if event.run_id not in runs:
            runs.append(event.run_id)
    return {
        "runs": runs,
        "event_count": len(ordered),
        "diff": diff,
        "suspect_lines": suspect_lines,
        "timeline": timeline,
        "sandbox_output": "\n".join(sandbox_parts),
        "red_to_green": {
            "red": red_at is not None,
            "green": green_at is not None,
            "red_at": red_at,
            "green_at": green_at,
            "test_path": red_test,
        },
        "regression_wall": regression_wall,
        "dropped": verdict_counts.get(DROPPED_VALUE, 0),
        "verdict_counts": verdict_counts,
    }
