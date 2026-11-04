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

import hashlib
import json
import re
import statistics
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any
from typing import get_args

from ..ci.gate import classify as classify_gate
from ..ci.summary import build_result
from ..graph import build_graph, changed_lines, changed_nodes, find_entries, find_paths, functions_in, sink_hits
from ..oracle.oracle import Effect
from ..report.cwe import get_cwe, severity_from_effect
from ..schemas import Event, EventType, VerdictValue
from ..schemas.graph import CodeGraph, ReachPath
from ..ledger.trace import trace_events, trace_to_dict
from .sources import RunData, valid_discussion_url

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
#: Unified diffs shown on the run page (ledger payload.diff or ``gh pr diff``).
MAX_PR_DIFF = 200_000
FIX_OUTSIDE_PR_DIFF = (
    "GitHub cannot attach a suggestion outside the PR diff..."
)

_GRAPH_CACHE: dict[str, tuple[str, dict[str, Any]]] = {}
EFFECTS = tuple(get_args(Effect))
EFFECT_SCHEMA = tuple(
    {
        "value": effect,
        "label": effect.removeprefix("canary_").replace("_", " ").title(),
        "color": f"effect-{effect}",
    }
    for effect in EFFECTS
)

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


def _diff_text(value: Any) -> str:
    """Keep a unified diff as text (NUL-stripped, capped). Never applied."""
    if not isinstance(value, str) or not value.strip():
        return ""
    return value.replace("\x00", "")[:MAX_PR_DIFF]


def diff_files(text: str) -> set[str]:
    """Paths named on ``+++`` lines of a unified diff."""
    files: set[str] = set()
    for line in (text or "").splitlines():
        if line.startswith("+++ b/"):
            path = line[6:].strip()
        elif line.startswith("+++ ") and not line.startswith("+++ /dev/null"):
            path = line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
        else:
            continue
        if path and path != "/dev/null":
            files.add(path[:400])
    return files


def fix_hunks_outside_pr_diff(fix_patch: str, pr_diff: str) -> bool:
    """True when the fix names a file the pull request diff does not change."""
    fix_files = diff_files(fix_patch)
    pr_files = diff_files(pr_diff)
    if not fix_files or not pr_files:
        return False
    return bool(fix_files - pr_files)


def pr_diff_of(data: RunData) -> tuple[str, str]:
    """Return ``(diff, source)`` from the run folder or the ``pr_opened`` payload."""
    folder = _diff_text(data.diff)
    if folder:
        return folder, "file"
    for event in data.events:
        if event.type == EventType.PR_OPENED:
            payload = _diff_text(event.payload.get("diff"))
            if payload:
                return payload, "ledger"
            break
    return "", ""


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
    """The oracle effect of an event: canary_read / canary_write from its open mode,
    otherwise the declared type when it is a known effect (canary_exec, canary_sql, ...)."""
    mode = _text(oracle.get("mode"), 16).lower()
    if any(char in _WRITE_MODE for char in mode):
        return "canary_write"
    declared = _text(oracle.get("type"), 32)
    if declared in EFFECTS:
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
            commit = _text(p.get("commit") or p.get("head_sha") or p.get("head"), 64)
            base = _text(p.get("base") or p.get("base_sha"), 64)
            return {
                "repo": _text(p.get("repo"), 140),
                "pr": _text(p.get("pr"), 64),
                "commit": commit if _SHA.match(commit) else "",
                "base_sha": base if _SHA.match(base) else "",
                "branch": _text(p.get("branch") or p.get("head_branch"), 200),
                "title": _text(p.get("title"), 200),
                "synthetic": p.get("synthetic") is True,
            }
    return {}


#: A repository name that can safely address a github.com pull request URL.
_REPO_URL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}\Z")


def _discussion_url(repo: str, pr: str) -> str:
    """The pull request discussion URL, derived from recorded repo and PR number.

    Empty unless the repo is a plain ``owner/name`` and the PR is a number:
    nothing is invented from untrusted ledger text (a hostile or synthetic
    repo name must never become a link).
    """
    pr_digits = pr.lstrip("#")
    if pr_digits.isdigit() and _REPO_URL_RE.match(repo):
        return f"https://github.com/{repo}/pull/{pr_digits}"
    return ""


def _event_models(events: Sequence[Event]) -> list[str]:
    """Distinct non-empty model names recorded on the ledger, in first-seen order."""
    seen: list[str] = []
    for event in events:
        name = _text(event.model, 120)
        if name and name not in seen:
            seen.append(name)
    return seen[:20]


def _headline(status: str, proven: int) -> str:
    if status == "unreadable":
        return "NOT PROVEN: Run could not be read: nothing is shown"
    if proven:
        return f"PROVEN: {proven} proven finding{'s' if proven != 1 else ''}"
    body = _HEADLINES.get(status, "Nothing could be proven")
    return f"NOT PROVEN: {body}"


def _row_findings_summary(events: Sequence[Event], diff: str = "") -> dict[str, Any]:
    """Summarize proven findings, exploits written, and touched files for a run row."""
    suspicions: dict[str, dict[str, Any]] = {}
    verdicts: dict[str, dict[str, Any]] = {}
    exploit_sids: set[str] = set()
    files: list[str] = []

    def add_file(raw: str) -> None:
        cleaned = _text(raw, 300).removeprefix("/workspace/").lstrip("/")
        if cleaned and cleaned not in files:
            files.append(cleaned)

    if diff:
        for path in changed_lines(diff):
            add_file(path)

    for idx, event in enumerate(events):
        if event.type == EventType.SUSPICION_RAISED:
            s = _dict(event.payload.get("suspicion")) or event.payload
            sid = _text(s.get("id"), 128)
            if not sid or sid in suspicions:
                continue
            loc = _dict(s.get("location"))
            file_path = _text(loc.get("file"), 300)
            add_file(file_path)
            suspicions[sid] = {
                "id": sid,
                "class": _text(s.get("class"), 120),
                "file": file_path,
                "line": _int(loc.get("line")) or 0,
                "entry_point": _text(s.get("entry_point"), 200),
            }
        elif event.type == EventType.EXPLOIT_WRITTEN:
            exploit_sids.add(_sid(event) or f"__idx_{idx}")
        elif event.type == EventType.VERDICT and _sid(event):
            verdicts[_sid(event)] = event.payload

    proven_ids = [
        sid for sid, v in verdicts.items()
        if _text(v.get("verdict"), 64) == VerdictValue.PROVEN.value
    ]
    duplicate_ids: set[str] = set()
    for sid in proven_ids:
        v = verdicts[sid]
        dups = v.get("duplicates")
        if isinstance(dups, list):
            for d in dups[:MAX_ITEMS]:
                did = _text(d, 200)
                if did and did != sid:
                    duplicate_ids.add(did)
        dup_of = _text(v.get("duplicate_of"), 200)
        if dup_of and dup_of in proven_ids and dup_of != sid:
            duplicate_ids.add(sid)

    highest_severity = ""
    effects: list[str] = []
    cwes: list[str] = []
    fixes_verified = 0
    fixes_bypassed = 0

    for sid in proven_ids:
        if sid in duplicate_ids:
            continue
        base = suspicions.get(sid) or {"id": sid, "class": "", "file": "", "line": 0, "entry_point": ""}
        ev = _evidence(sid, base["entry_point"], base["class"], events, verdicts[sid])
        obs_file = _text(_dict(ev.get("observed_location")).get("file"), 300)
        add_file(obs_file or base["file"])
        sev = _text(ev.get("severity"), 32).lower()
        if sev in SEVERITIES:
            highest_severity = _worse(sev, highest_severity)
        eff = _text(_dict(ev.get("effect")).get("type"), 64)
        if eff and eff != "unknown" and eff not in effects:
            effects.append(eff)
        cwe = _text(ev.get("cwe"), 80)
        if cwe and cwe not in cwes:
            cwes.append(cwe)
        fix_st = _fix_status(ev)
        if fix_st == "verified":
            fixes_verified += 1
        elif fix_st == "bypassed":
            fixes_bypassed += 1

    return {
        "highest_severity": highest_severity,
        "effects": effects[:20],
        "cwes": cwes[:20],
        "exploits_written": len(exploit_sids),
        "fixes_verified": fixes_verified,
        "fixes_bypassed": fixes_bypassed,
        "files_touched": files[:50],
    }


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
        "head_sha": ref.commit or meta.get("commit", ""),
        "base_sha": meta.get("base_sha", ""),
        "discussion_url": "",
        "branch": ref.branch or meta.get("branch", ""),
        "title": meta.get("title", ""),
        "models": [],
        # The ledger records model names but no provider: always "" ("not recorded").
        "provider": "",
        "repo_id": "",
        "url": ref.url,
        "synthetic": ref.synthetic or bool(meta.get("synthetic")),
        "started_at": ref.started_at or (data.events[0].ts if data.events else ""),
        "duration_s": _duration(data.events),
        "error": data.error,
        "risk": "",
        "risk_reasons": {},
        "should_run_exploits": None,
        "status": "unreadable",
        "proven": 0,
        "proven_raw": 0,
        "duplicates": 0,
        "verdicts": {v.value: 0 for v in VerdictValue},
        "suspicions_raised": 0,
        "exploits_written": 0,
        "fixes_verified": 0,
        "fixes_bypassed": 0,
        "highest_severity": "",
        "effects": [],
        "cwes": [],
        "files_touched": [],
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
            row["repo_id"] = repo_id(row["repo"])
            return row
        if not data.events and extra.get("status") in ("skipped", "timed_out"):
            result["status"] = extra["status"]
        risk_obj = _dict(result.get("risk"))
        raw_reasons = _dict(risk_obj.get("reasons"))
        if not raw_reasons and data.diff:
            raw_reasons = classify_gate(changed_lines(data.diff).keys()).reasons
        risk_reasons = {
            _text(k, 300): _text(v, 300)
            for k, v in list(raw_reasons.items())[:MAX_ITEMS]
            if _text(k, 300) and _text(v, 300)
        }
        should_run = risk_obj.get("should_run_exploits")
        row.update(
            {
                "ledger_run_id": _text(result["run_id"], 128),
                "status": result["status"],
                "proven": result["proven"],
                "proven_raw": result.get("proven_raw", result["proven"]),
                "duplicates": result.get("duplicates", 0),
                "verdicts": {_text(k, 64): v for k, v in result["verdicts"].items()},
                "suspicions_raised": result["suspicions_raised"],
                "dropped": result["dropped"],
                "flags": clean(result["flags"]),
                "ablated": result["ablated"],
                "risk": _text(risk_obj.get("risk"), 16),
                "risk_reasons": risk_reasons,
                "should_run_exploits": should_run if isinstance(should_run, bool) else None,
                "skipped_reason": _text(result.get("skipped_reason"), 300),
                "tokens_in": result["tokens_in"],
                "tokens_out": result["tokens_out"],
                "cost_usd": result["cost_usd"],
                **_row_findings_summary(data.events, data.diff),
            }
        )
    row["headline"] = _headline(row["status"], row["proven"])
    row["repo_id"] = repo_id(row["repo"])
    row["head_sha"] = row["commit"]
    # The artifact's review-thread URL wins when it names this run's repo and
    # PR; otherwise the synthesized PR page (or "" when nothing is recorded).
    extra = data.result or {}
    row["provider"] = _text(extra.get("provider"), 120)
    row["discussion_url"] = (
        valid_discussion_url(extra.get("discussion_url"), row["repo"], row["pr"])
        or _discussion_url(row["repo"], row["pr"])
    )
    if not data.error:
        row["models"] = _event_models(data.events)
    return row


# -- run detail ---------------------------------------------------------------------


def _stages(events: Sequence[Event]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {
        name: {
            "name": name,
            "count": 0,
            "first_ts": "",
            "last_ts": "",
            "first_seq": None,
            "duration_s": 0.0,
        }
        for name in STAGES
    }
    parsed_ts = [_parse_ts(e.ts) for e in events]
    for seq, event in enumerate(events):
        stage = stage_of(event)
        if not stage:
            continue
        slot = seen[stage]
        slot["count"] += 1
        slot["last_ts"] = event.ts
        if slot["first_seq"] is None:
            slot["first_seq"] = seq
            slot["first_ts"] = event.ts
        step_s = 0.0
        cur_t = parsed_ts[seq]
        prev_t = parsed_ts[seq - 1] if seq > 0 else None
        if cur_t is not None and prev_t is not None and cur_t >= prev_t:
            step_s = (cur_t - prev_t).total_seconds()
        elif event.latency_ms > 0:
            step_s = event.latency_ms / 1000.0
        slot["duration_s"] = round(slot["duration_s"] + step_s, 3)
    return [
        {
            **slot,
            "reached": slot["count"] > 0,
            "duration_s": slot["duration_s"] if slot["count"] > 0 else None,
        }
        for slot in seen.values()
    ]


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


def _evidence(
    sid: str,
    entry_point: str,
    vuln_class: str,
    events: Sequence[Event],
    verdict: dict[str, Any],
) -> dict[str, Any]:
    """Collect the proof of one proven suspicion from its events."""
    own = [e for e in events if _sid(e) == sid]
    declared = _dict(verdict.get("evidence"))
    facts = _dict(verdict.get("facts"))
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
    observed_location = _dict(facts.get("observed_location")) or _dict(declared.get("observed_location"))
    observed_location = {
        "file": _text(observed_location.get("file"), 300),
        "line": _int(observed_location.get("line")) or 0,
        "function": _text(observed_location.get("function"), 200),
        "line_source": _text(observed_location.get("line_source"), 80),
    } if observed_location else {}
    effect_type = _text(effect.get("type"), 64)
    effect_display = next((entry for entry in EFFECT_SCHEMA if entry["value"] == effect_type), None)
    if effect_display:
        effect["label"] = effect_display["label"]
        effect["color"] = effect_display["color"]

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
        "observed_location": observed_location,
        "model_location": {},
        "cwe": _text(verdict.get("cwe") or declared.get("cwe"), 80)
        or get_cwe(effect_type, vuln_class).cwe_id,
        "severity": _text(verdict.get("severity") or declared.get("severity"), 32)
        or severity_from_effect(
            effect_type,
            vuln_class=vuln_class,
            provenance_ok=bool(frames) or bool(entry_point),
            has_entry_point=bool(entry_point),
        ),
    }


def _costs(events: Sequence[Event]) -> dict[str, Any]:
    roles: dict[str, dict[str, Any]] = {}
    stages: dict[str, dict[str, Any]] = {}
    models: dict[str, dict[str, Any]] = {}
    for event in events:
        role = _text(event.role, 64) or "engine"
        stage = stage_of(event) or "INTAKE"
        name = _text(event.model, 120)
        for bucket, key in ((roles, role), (stages, stage)):
            item = bucket.setdefault(key, {"cost_usd": 0.0, "tokens_in": 0, "tokens_out": 0, "events": 0})
            item["cost_usd"] += event.cost_usd
            item["tokens_in"] += event.tokens_in
            item["tokens_out"] += event.tokens_out
            item["events"] += 1
        if name:
            slot = models.setdefault(name, {"cost_usd": 0.0, "tokens_in": 0, "tokens_out": 0,
                                             "events": 0, "roles": []})
            slot["cost_usd"] += event.cost_usd
            slot["tokens_in"] += event.tokens_in
            slot["tokens_out"] += event.tokens_out
            slot["events"] += 1
            if role not in slot["roles"]:
                slot["roles"].append(role)
    for bucket in (roles, stages, models):
        for item in bucket.values():
            item["cost_usd"] = round(item["cost_usd"], 8)
    role_models: dict[str, list[str]] = {}
    for event in events:
        role = _text(event.role, 64) or "engine"
        name = _text(event.model, 120)
        if name and name not in role_models.setdefault(role, []):
            role_models[role].append(name)
    for role, item in roles.items():
        item["models"] = sorted(role_models.get(role, []))
    return {"by_role": roles, "by_stage": stages, "by_model": models}


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


def run_detail(data: RunData, *, with_graph: bool = True) -> dict[str, Any]:
    """Everything the run detail view shows, except the raw event list.

    ``with_graph=False`` skips the code graph (the repository overview aggregates the
    findings of many runs and never shows their graphs).
    """
    row = run_row(data)
    graph = build_graph_view(data) if with_graph else None
    if row["error"]:
        return {"run": row, "stages": _stages([]), "proven": [], "discarded": [], "latency_ms": 0,
                "trace": trace_to_dict(row["run_id"], []), "costs": _costs([]), "graph": graph,
                # No provider or budget cap is recorded in the ledger or artifact.
                "provider": "", "budget_usd": None,
                "artifacts": {"fix_patch": None, "exploit_test": None},
                "graph_summary": None}
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
        item = {
            **base,
            "verdict": label,
            "reason": _text(verdict.get("reason"), 600),
            # Why a non-proven suspicion was not reported; "" when the ledger records none.
            "reason_code": _text(verdict.get("reason_code"), 120),
            "effect": _text(verdict.get("effect"), 64),
            "evidence": None,
            "duplicate_of": _text(verdict.get("duplicate_of"), 200),
        }
        if label == VerdictValue.PROVEN.value:
            item["evidence"] = _evidence(sid, base["entry_point"], base["class"], events, verdict)
            item["evidence"]["model_location"] = {
                "file": base["file"],
                "line": base["line"],
            }
        items.append(item)
    proven_by_id = {item["id"]: item for item in items if item["verdict"] == VerdictValue.PROVEN.value}
    primary_ids = set(proven_by_id)
    for item in proven_by_id.values():
        evidence = item["evidence"] or {}
        duplicate_ids = verdicts.get(item["id"], {}).get("duplicates")
        if not isinstance(duplicate_ids, list):
            duplicate_ids = [
                other["id"] for other in proven_by_id.values()
                if other.get("duplicate_of") == item["id"]
            ]
        duplicates = []
        for duplicate_id in duplicate_ids[:MAX_ITEMS]:
            duplicate = proven_by_id.get(_text(duplicate_id, 200))
            if duplicate is None or duplicate["id"] == item["id"]:
                continue
            duplicate_evidence = duplicate.get("evidence") or {}
            duplicates.append(
                {
                    "suspicion_id": duplicate["id"],
                    "file": duplicate.get("file", ""),
                    "line": duplicate.get("line", 0),
                    "observed_location": duplicate_evidence.get("observed_location", {}),
                }
            )
            primary_ids.discard(duplicate["id"])
        evidence["duplicates"] = duplicates
    proven = [item for item in items if item["id"] in primary_ids]
    duplicate_ids = {item["id"] for item in items if item["verdict"] == VerdictValue.PROVEN.value} - primary_ids
    steps = trace_events(events)
    artifacts = data.artifacts
    pr_diff, pr_diff_source = pr_diff_of(data)
    fix_patch = artifacts.get("fix.patch")
    return {
        "run": row,
        "stages": _stages(events),
        "proven": proven,
        "discarded": [i for i in items if i["verdict"] != VerdictValue.PROVEN.value],
        "proven_raw": sum(1 for i in items if i["verdict"] == VerdictValue.PROVEN.value),
        "duplicates": len(duplicate_ids),
        "effect_schema": list(EFFECT_SCHEMA),
        "latency_ms": sum(e.latency_ms for e in events),
        "trace": trace_to_dict(row["run_id"], steps),
        "costs": _costs(events),
        "graph": graph,
        # The result artifact may name the provider; no budget cap is stored in
        # the ledger or artifact: "" / None mean "not recorded".
        "provider": row.get("provider", ""),
        "budget_usd": None,
        # Proof artifacts, read as text only (never executed); None means
        # the run folder or artifact does not carry that file ("not recorded").
        "artifacts": {
            "fix_patch": artifacts.get("fix.patch"),
            "exploit_test": artifacts.get("test_exploit.py"),
        },
        # Validated graph-summary.json (artifact-schema.md); None means the run
        # folder or artifact does not carry one ("not recorded").
        "graph_summary": data.graph_summary or None,
        "pr_diff": pr_diff or None,
        "pr_diff_source": pr_diff_source,
        "fix_outside_pr_diff": bool(
            pr_diff and fix_patch and fix_hunks_outside_pr_diff(fix_patch, pr_diff)
        ),
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


# -- repositories --------------------------------------------------------------------

#: Most runs one repository aggregate reads (newest first); older runs are left out.
MAX_REPO_RUNS = 500
#: Rows returned in a repository's pull request and finding lists.
MAX_REPO_ROWS = 50
SEVERITIES = ("critical", "high", "medium", "low")
UNKNOWN_REPO_ID = "unknown"
_SLUG = re.compile(r"[^a-z0-9]+")


def repo_id(name: str) -> str:
    """A stable, URL-safe id for a repository name ("" maps to ``unknown``).

    The readable slug is capped and followed by a short digest of the full name, so two
    names that slug alike ("a/b" and "a-b") still get different ids.
    """
    if not name:
        return UNKNOWN_REPO_ID
    slug = _SLUG.sub("-", name.lower()).strip("-")[:60].strip("-") or "repo"
    return f"{slug}-{hashlib.sha256(name.encode('utf-8')).hexdigest()[:6]}"


def _fix_status(evidence: dict[str, Any]) -> str:
    if (_dict(evidence.get("bypass")).get("succeeded") or 0) > 0:
        return "bypassed"
    if _dict(evidence.get("passes_on_fixed")).get("fix_verified") is True:
        return "verified"
    return "not_verified"


def _root_cause(item: dict[str, Any]) -> str:
    """Findings with the same effect, CWE and observed (or suspected) code share a root cause."""
    evidence = _dict(item.get("evidence"))
    observed = _dict(evidence.get("observed_location"))
    effect = _text(_dict(evidence.get("effect")).get("type"), 64)
    where = observed.get("file") or item.get("file") or ""
    function = observed.get("function") or item.get("entry_point") or ""
    return "|".join((effect, _text(evidence.get("cwe"), 80), str(where), str(function)))


def _finding_row(row: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    evidence = _dict(item.get("evidence"))
    effect = _dict(evidence.get("effect"))
    observed = _dict(evidence.get("observed_location"))
    severity = _text(evidence.get("severity"), 32).lower()
    return {
        "run_id": row["run_id"],
        "finding_id": item.get("id", ""),
        "class": item.get("class", ""),
        "hypothesis": item.get("hypothesis", ""),
        "entry_point": _text(item.get("entry_point"), 200),
        "reason": _text(item.get("reason"), 300),
        "severity": severity if severity in SEVERITIES else "",
        "cwe": _text(evidence.get("cwe"), 80),
        "effect": _text(effect.get("type"), 64),
        "effect_label": _text(effect.get("label"), 64),
        "file": observed.get("file") or item.get("file", ""),
        "line": observed.get("line") or item.get("line", 0),
        "fix_status": _fix_status(evidence),
        "pr": row.get("pr", ""),
        "commit": row.get("commit", ""),
        "title": row.get("title", ""),
        "started_at": row.get("started_at", ""),
        "root_cause": _root_cause(item),
    }


def _repo_summary(rid: str, entries: list[tuple[dict[str, Any], dict[str, Any] | None]]) -> dict[str, Any]:
    """Cards on the home view: one per repository. ``entries`` are newest first."""
    rows = [row for row, _ in entries]
    readable = [row for row in rows if row.get("status") != "unreadable"]
    severity_mix = {name: 0 for name in (*SEVERITIES, "unknown")}
    for _, detail in entries:
        for item in (detail or {}).get("proven", []):
            severity = _text(_dict(item.get("evidence")).get("severity"), 32).lower()
            severity_mix[severity if severity in SEVERITIES else "unknown"] += 1
    last = rows[0] if rows else {}
    return {
        "id": rid,
        "name": last.get("repo", ""),
        "synthetic": any(row.get("synthetic") for row in rows),
        "runs": len(rows),
        "readable_runs": len(readable),
        "proven": sum(row.get("proven", 0) for row in readable),
        "last_run": {key: last.get(key) for key in ("run_id", "started_at", "status", "headline", "pr", "title", "proven")}
        if last else None,
        "trend": [
            {"run_id": row["run_id"], "started_at": row.get("started_at", ""), "proven": row.get("proven", 0),
             "status": row.get("status", "")}
            for row in reversed(readable)
        ],
        "severity_mix": severity_mix,
    }


def group_by_repo(
    entries: Iterable[tuple[dict[str, Any], dict[str, Any] | None]],
) -> dict[str, list[tuple[dict[str, Any], dict[str, Any] | None]]]:
    """(row, detail) pairs grouped by repository id, each group newest first."""
    groups: dict[str, list[tuple[dict[str, Any], dict[str, Any] | None]]] = {}
    for row, detail in entries:
        groups.setdefault(row.get("repo_id") or UNKNOWN_REPO_ID, []).append((row, detail))
    for group in groups.values():
        group.sort(key=lambda entry: (entry[0].get("started_at", ""), entry[0]["run_id"]), reverse=True)
    return groups


def build_repo_index(entries: Iterable[tuple[dict[str, Any], dict[str, Any] | None]]) -> list[dict[str, Any]]:
    """Every repository with its summary, the most recently active first."""
    summaries = [_repo_summary(rid, group) for rid, group in group_by_repo(entries).items()]
    return sorted(summaries, key=lambda s: ((s["last_run"] or {}).get("started_at") or "", s["id"]), reverse=True)


def build_repo_detail(rid: str, group: list[tuple[dict[str, Any], dict[str, Any] | None]]) -> dict[str, Any]:
    """Headline metrics across a repository's runs, its recent pull requests and the most
    serious proven findings (by severity, then fix status, then recency).

    Every number is a count or sum of recorded run data; nothing is estimated.
    """
    summary = _repo_summary(rid, group)
    findings: list[dict[str, Any]] = []
    discarded_rows: list[dict[str, Any]] = []
    discarded = 0
    cost = 0.0
    tokens_in = tokens_out = 0
    for row, detail in group:
        cost += row.get("cost_usd") or 0.0
        tokens_in += row.get("tokens_in") or 0
        tokens_out += row.get("tokens_out") or 0
        if detail is None or row.get("status") == "unreadable":
            continue
        discarded += len(detail.get("discarded", []))
        findings.extend(_finding_row(row, item) for item in detail.get("proven", []))
        for item in detail.get("discarded", []):
            discarded_rows.append({
                "run_id": row["run_id"],
                "suspicion_id": item.get("id", ""),
                "class": item.get("class", ""),
                "file": item.get("file", ""),
                "line": item.get("line", 0),
                "entry_point": item.get("entry_point", ""),
                "verdict": item.get("verdict", ""),
                "reason": item.get("reason", ""),
                "reason_code": item.get("reason_code", ""),
                "effect": item.get("effect", ""),
                "pr": row.get("pr", ""),
                "started_at": row.get("started_at", ""),
            })
    causes: dict[str, dict[str, Any]] = {}
    for finding in findings:  # newest run first, so the first one seen is the latest
        cause = causes.setdefault(finding["root_cause"], {**finding, "occurrences": 0, "runs": []})
        cause["occurrences"] += 1
        cause["runs"].append(finding["run_id"])
    rank_severity = {name: i for i, name in enumerate(SEVERITIES)}
    rank_fix = {"bypassed": 0, "not_verified": 1, "verified": 2}
    # sorted() is stable: among equals the newest occurrence (insertion order) stays first.
    serious = sorted(
        causes.values(),
        key=lambda f: (rank_severity.get(f["severity"], len(SEVERITIES)), rank_fix[f["fix_status"]]),
    )
    pull_requests = [
        {key: row.get(key) for key in ("run_id", "pr", "title", "status", "headline", "proven", "started_at",
                                       "commit", "head_sha", "base_sha", "discussion_url", "models",
                                       "branch", "risk", "risk_reasons", "should_run_exploits",
                                       "cost_usd", "duration_s", "synthetic", "highest_severity", "effects",
                                       "cwes", "exploits_written", "fixes_verified", "fixes_bypassed",
                                       "files_touched", "verdicts", "suspicions_raised", "dropped")}
        for row, _ in group[:MAX_REPO_ROWS]
    ]
    durations = [
        float(row["duration_s"])
        for row, _ in group
        if row.get("status") != "unreadable" and isinstance(row.get("duration_s"), (int, float))
    ]
    median_duration_s = round(float(statistics.median(durations)), 3) if durations else None

    readable_entries = [
        (row, detail) for row, detail in group
        if row.get("status") != "unreadable" and detail is not None
    ]
    chronological = list(reversed(readable_entries))

    verdict_totals = {v.value: 0 for v in VerdictValue}
    for row, _ in readable_entries:
        rv = row.get("verdicts") or {}
        for v in VerdictValue:
            verdict_totals[v.value] += int(rv.get(v.value) or 0)

    suspicions_total = sum(int(row.get("suspicions_raised") or 0) for row, _ in readable_entries)
    exploits_total = sum(int(row.get("exploits_written") or 0) for row, _ in readable_entries)
    proven_total = len(findings)
    fixes_verified_total = sum(1 for f in findings if f["fix_status"] == "verified")
    fixes_bypassed_total = sum(1 for f in findings if f["fix_status"] == "bypassed")
    funnel = {
        "suspicions_raised": suspicions_total,
        "exploits_written": exploits_total,
        "proven": proven_total,
        "fixes_verified": fixes_verified_total,
        "bypass_resistant": fixes_verified_total,
    }

    run_series: list[dict[str, Any]] = []
    stage_sec = {name: 0.0 for name in STAGES}
    stage_ev = {name: 0 for name in STAGES}
    stage_runs = {name: 0 for name in STAGES}

    file_stats: dict[str, dict[str, int]] = {}
    per_run_files: list[tuple[dict[str, Any], dict[str, dict[str, int]]]] = []

    def _clean_path(raw: Any) -> str:
        return _text(raw, 300).removeprefix("/workspace/").lstrip("/")

    def _norm_effect(raw: Any) -> str:
        eff = _text(raw, 64).lower().removeprefix("canary_")
        return eff if eff in ("read", "write", "exec", "sql") else "unspecified"

    cost_by_role: dict[str, dict[str, Any]] = {}
    cost_by_model: dict[str, dict[str, Any]] = {}
    cumulative_cost = 0.0
    for idx, (row, detail) in enumerate(chronological, start=1):
        det = detail or {}
        eff_counts = {"read": 0, "write": 0, "exec": 0, "sql": 0, "unspecified": 0}
        run_file_map: dict[str, dict[str, int]] = {}
        run_cost = round(float(row.get("cost_usd") or 0.0), 8)
        cumulative_cost = round(cumulative_cost + run_cost, 8)

        for tf in row.get("files_touched") or []:
            cf = _clean_path(tf)
            if cf:
                run_file_map.setdefault(cf, {"proven": 0, "discarded": 0, "touched": 1})

        for item in det.get("proven", []):
            ev = _dict(item.get("evidence"))
            key = _norm_effect(_dict(ev.get("effect")).get("type"))
            eff_counts[key] += 1
            obs = _dict(ev.get("observed_location"))
            cf = _clean_path(obs.get("file") or item.get("file"))
            if cf:
                cell = run_file_map.setdefault(cf, {"proven": 0, "discarded": 0, "touched": 1})
                cell["proven"] += 1
                cell["touched"] = 1

        for item in det.get("discarded", []):
            cf = _clean_path(item.get("file"))
            if cf:
                cell = run_file_map.setdefault(cf, {"proven": 0, "discarded": 0, "touched": 1})
                cell["discarded"] += 1
                cell["touched"] = 1

        for cf, cell in run_file_map.items():
            agg = file_stats.setdefault(cf, {"proven": 0, "discarded": 0, "runs": 0})
            agg["proven"] += cell["proven"]
            agg["discarded"] += cell["discarded"]
            agg["runs"] += 1
        per_run_files.append((row, run_file_map))

        by_role_raw = _dict(_dict(det.get("costs")).get("by_role"))
        by_role: dict[str, dict[str, Any]] = {}
        for rname, rvals in by_role_raw.items():
            rv_dict = _dict(rvals)
            by_role[rname] = {
                "cost_usd": round(float(rv_dict.get("cost_usd") or 0.0), 8),
                "tokens_in": int(rv_dict.get("tokens_in") or 0),
                "tokens_out": int(rv_dict.get("tokens_out") or 0),
                "events": int(rv_dict.get("events") or 0),
                "models": sorted(_text(m, 120) for m in (rv_dict.get("models") or []) if _text(m, 120))[:10],
            }
            agg = cost_by_role.setdefault(rname, {"cost_usd": 0.0, "tokens_in": 0,
                                                  "tokens_out": 0, "events": 0, "models": []})
            agg["cost_usd"] = round(agg["cost_usd"] + by_role[rname]["cost_usd"], 8)
            agg["tokens_in"] += by_role[rname]["tokens_in"]
            agg["tokens_out"] += by_role[rname]["tokens_out"]
            agg["events"] += by_role[rname]["events"]
            for model_name in by_role[rname]["models"]:
                if model_name not in agg["models"]:
                    agg["models"].append(model_name)
        by_model_raw = _dict(_dict(det.get("costs")).get("by_model"))
        for mname, mvals in by_model_raw.items():
            mv_dict = _dict(mvals)
            model_name = _text(mname, 120)
            if not model_name:
                continue
            agg = cost_by_model.setdefault(model_name, {"cost_usd": 0.0, "tokens_in": 0,
                                                        "tokens_out": 0, "events": 0, "roles": []})
            agg["cost_usd"] = round(agg["cost_usd"] + round(float(mv_dict.get("cost_usd") or 0.0), 8), 8)
            agg["tokens_in"] += int(mv_dict.get("tokens_in") or 0)
            agg["tokens_out"] += int(mv_dict.get("tokens_out") or 0)
            agg["events"] += int(mv_dict.get("events") or 0)
            for role_name in (mv_dict.get("roles") or []):
                if _text(role_name, 64) and _text(role_name, 64) not in agg["roles"]:
                    agg["roles"].append(_text(role_name, 64))

        for st in det.get("stages") or []:
            st_dict = _dict(st)
            sname = _text(st_dict.get("name"), 32)
            if sname in stage_sec:
                ev_c = int(st_dict.get("count") or 0)
                dur_c = float(st_dict.get("duration_s") or 0.0)
                stage_sec[sname] += dur_c
                stage_ev[sname] += ev_c
                if ev_c > 0:
                    stage_runs[sname] += 1

        run_series.append({
            "order": idx,
            "run_id": row["run_id"],
            "pr": row.get("pr", ""),
            "commit": row.get("commit", ""),
            "title": row.get("title", ""),
            "started_at": row.get("started_at", ""),
            "status": row.get("status", ""),
            "proven": int(row.get("proven") or 0),
            "dropped": int(row.get("dropped") or 0),
            "suspicions_raised": int(row.get("suspicions_raised") or 0),
            "cost_usd": run_cost,
            "cumulative_cost_usd": cumulative_cost,
            "tokens_in": int(row.get("tokens_in") or 0),
            "tokens_out": int(row.get("tokens_out") or 0),
            "duration_s": row.get("duration_s"),
            "effects_breakdown": eff_counts,
            "by_role": by_role,
        })

    stage_durations = [
        {
            "stage": name,
            "duration_s": round(stage_sec[name], 3),
            "events": stage_ev[name],
            "runs_active": stage_runs[name],
        }
        for name in STAGES
    ]

    top_files = sorted(
        file_stats.keys(),
        key=lambda f: (-file_stats[f]["proven"], -file_stats[f]["discarded"], -file_stats[f]["runs"], f),
    )[:12]
    hot_cells: list[dict[str, Any]] = []
    for fname in top_files:
        for row, rmap in per_run_files:
            cell = rmap.get(fname, {"proven": 0, "discarded": 0, "touched": 0})
            hot_cells.append({
                "file": fname,
                "run_id": row["run_id"],
                "pr": row.get("pr", ""),
                "proven": cell["proven"],
                "discarded": cell["discarded"],
                "touched": bool(cell["touched"]),
            })
    hot_files = {
        "files": top_files,
        "runs": [
            {
                "order": idx,
                "run_id": row["run_id"],
                "pr": row.get("pr", ""),
                "commit": row.get("commit", ""),
                "started_at": row.get("started_at", ""),
            }
            for idx, (row, _) in enumerate(per_run_files, start=1)
        ],
        "cells": hot_cells,
    }

    cwe_buckets: dict[tuple[str, str, str], int] = {}
    for f in findings:
        key = (
            f["cwe"] or "unspecified",
            f["severity"] or "unknown",
            f["effect"] or "unspecified",
        )
        cwe_buckets[key] = cwe_buckets.get(key, 0) + 1
    cwe_distribution = [
        {"cwe": k[0], "severity": k[1], "effect": k[2], "count": count}
        for k, count in sorted(
            cwe_buckets.items(),
            key=lambda kv: (-kv[1], rank_severity.get(kv[0][1], len(SEVERITIES)), kv[0][0]),
        )
    ]

    readable_count = len(readable_entries)
    return {
        "repo": summary,
        "metrics": {
            "runs": len(group),
            "proven": proven_total,
            "root_causes": len(causes),
            "suspicions_raised": suspicions_total,
            "exploits_written": exploits_total,
            "fixes_verified": fixes_verified_total,
            "fixes_bypassed": fixes_bypassed_total,
            "discarded": discarded,
            "proven_rate": round(proven_total / suspicions_total, 4) if suspicions_total else None,
            "cost_usd": round(cost, 8),
            "cost_per_run": round(cost / readable_count, 8) if readable_count else None,
            "cost_per_proven": round(cost / proven_total, 8) if proven_total else None,
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "median_duration_s": median_duration_s,
        },
        # No budget cap is stored in any ledger or artifact: None means "not recorded".
        "budget_usd": None,
        "cost_by_role": cost_by_role,
        "cost_by_model": cost_by_model,
        "verdict_totals": verdict_totals,
        "funnel": funnel,
        "run_series": run_series,
        "stage_durations": stage_durations,
        "hot_files": hot_files,
        "cwe_distribution": cwe_distribution,
        "pull_requests": pull_requests,
        "top_findings": serious[:MAX_REPO_ROWS],
        "all_findings": findings[:MAX_REPO_ROWS],
        "discarded_findings": discarded_rows[:MAX_REPO_ROWS],
    }


# -- benchmark (bench/results, Exhibit-A repo only) ------------------------------------


#: Benchmark result files considered for ``/api/benchmark``.
BENCH_RESULTS_GLOB = "20*.json"
MAX_BENCH_FILES = 8
MAX_BENCH_BYTES = 2 * 1024 * 1024
MAX_BENCH_TARGETS = 200


def _bench_root() -> Path | None:
    root = Path(__file__).resolve().parents[3] / "bench" / "results"
    return root if root.is_dir() else None


def _bench_number(value: Any) -> float | None:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def build_benchmark(source_label: str, repo_names: Sequence[str]) -> dict[str, Any]:
    """Aggregate ``bench/results/*.json`` for the Exhibit-A repo only.

    Every figure is a count or sum over measured ``per_target`` rows; rates
    are exact divisions, never estimates. For any other source the answer is
    ``available: False`` with reason ``no benchmark data for this source``:
    the corpus evaluation describes the Exhibit-A benchmark, not this source.
    """
    names = [str(source_label or "").lower()] + [str(n or "").lower() for n in repo_names]
    if not any("exhibit-a" in name for name in names):
        return {"available": False, "reason": "no benchmark data for this source"}
    root = _bench_root()
    if root is None:
        return {"available": False, "reason": "no benchmark data for this source"}
    files = sorted(root.glob(BENCH_RESULTS_GLOB))[-MAX_BENCH_FILES:]
    if not files:
        return {"available": False, "reason": "no benchmark data for this source"}
    path = files[-1]
    try:
        if path.stat().st_size > MAX_BENCH_BYTES:
            return {"available": False, "reason": "no benchmark data for this source"}
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"available": False, "reason": "no benchmark data for this source"}
    rows = payload.get("per_target") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return {"available": False, "reason": "no benchmark data for this source"}
    systems: dict[str, dict[str, Any]] = {}
    targets: list[dict[str, Any]] = []
    for entry in rows:
        if not isinstance(entry, dict) or entry.get("measured") is not True:
            continue
        system = _text(entry.get("system"), 120) or "unrecorded system"
        slot = systems.setdefault(system, {"system": system, "targets": 0, "reported": 0,
                                           "true_positives": 0, "false_positives": 0, "discarded": 0,
                                           "calls": 0, "cost_usd": 0.0, "truth_found": 0, "truth_total": 0})
        slot["targets"] += 1
        for key in ("reported", "true_positives", "false_positives", "discarded", "calls"):
            value = _bench_number(entry.get(key))
            if value is not None:
                slot[key] += int(value)
        cost = _bench_number(entry.get("cost_usd"))
        if cost is not None:
            slot["cost_usd"] = round(slot["cost_usd"] + cost, 8)
        found, total = _bench_number(entry.get("truth_found")), _bench_number(entry.get("truth_total"))
        if found is not None:
            slot["truth_found"] += int(found)
        if total is not None:
            slot["truth_total"] += int(total)
        if len(targets) < MAX_BENCH_TARGETS:
            targets.append({
                "target": _text(entry.get("target"), 200),
                "system": system,
                "role": _text(entry.get("role"), 64),
                "reported": entry.get("reported"),
                "true_positives": entry.get("true_positives"),
                "false_positives": entry.get("false_positives"),
                "discarded": entry.get("discarded"),
                "calls": entry.get("calls"),
                "cost_usd": entry.get("cost_usd"),
                "model": _text(entry.get("model"), 120),
            })
    ordered = []
    for slot in systems.values():
        denom = slot["true_positives"] + slot["false_positives"]
        ordered.append({
            **{k: slot[k] for k in ("system", "targets", "reported", "true_positives",
                                   "false_positives", "discarded", "calls", "cost_usd")},
            "precision": round(slot["true_positives"] / denom, 4) if denom else None,
            "recall": round(slot["truth_found"] / slot["truth_total"], 4) if slot["truth_total"] else None,
        })
    ordered.sort(key=lambda s: (-s["reported"], s["system"]))
    return {
        "available": True,
        "reason": "",
        "file": path.name,
        "files": [p.name for p in files],
        "systems": ordered,
        "targets": targets,
    }


# -- code graph (whole repository) ------------------------------------------------------

#: Most nodes sent for one repository graph; beyond it, the pull request's nodes and the
#: best-connected ones are kept and the response says it was truncated.
MAX_CODEGRAPH_NODES = 3000
MAX_REACH_PATHS = 60
_CODEGRAPH_CACHE: dict[str, dict[str, Any]] = {}
_CODEGRAPH_CACHE_SIZE = 16
_CALLABLE_KINDS = ("function", "method")
_SEVERITY_RANK = {name: rank for rank, name in enumerate(reversed(SEVERITIES), start=1)}


def _worse(a: str, b: str) -> str:
    return a if _SEVERITY_RANK.get(a, 0) >= _SEVERITY_RANK.get(b, 0) else b


def build_code_graph(data: RunData) -> dict[str, Any]:
    """The whole repository as a graph for the code graph view.

    Nodes are files, functions/methods and the sinks they call; edges are calls between
    repository functions (``call``), module-level references such as route tables (also
    ``call``, from the file), calls into a sink (``sink``) and a file's definitions
    (``defines``). Entry points come from the graph catalog; "changed" nodes come from
    the run's pull request diff when the run folder carries one. Reach paths
    (entry -> changed -> sink) are proposals; only the proven paths were observed by the
    oracle. The tree is parsed with ``ast`` only, never imported or run.
    """
    diff_key = hashlib.sha256(data.diff.encode("utf-8", errors="replace")).hexdigest()[:16]
    key = f"{data.ref.run_id}:{_tree_key(data.tree)}:{diff_key}:{len(data.events)}"
    cached = _CODEGRAPH_CACHE.get(key)
    if cached is not None:
        return cached
    empty: dict[str, Any] = {
        "available": False, "reason": "run archive has no local code tree", "nodes": [], "edges": [],
        "reach_paths": [], "proven_paths": [], "effects": list(EFFECTS), "changed_source": "none",
        "stats": {}, "truncated": False,
    }
    if data.error or data.tree is None:
        return empty
    try:
        graph = build_graph(data.tree)
    except (OSError, ValueError):
        return empty | {"reason": "code tree could not be parsed"}

    callables = {n.id: n for n in graph.nodes if n.kind in _CALLABLE_KINDS}
    classes = {n.id for n in graph.nodes if n.kind == "class"}
    modules = {n.id: n for n in graph.nodes if n.kind == "module"}
    detail = run_detail(data, with_graph=False)
    run_view = build_graph_view(data)

    # entry points: catalog detection plus the suspicions' declared entry points
    entries, _ = find_entries(graph)
    entry_kind = {e.node: (e.kind, e.detail) for e in entries}
    for item in detail.get("proven", []) + detail.get("discarded", []):
        declared = item.get("entry_point") or ""
        for node in callables.values():
            if declared and node.name == declared and node.id not in entry_kind:
                entry_kind[node.id] = ("declared", "entry point named by the suspicion")

    files = sorted({n.file for n in callables.values()} | {n.file for n in modules.values()})
    file_id = {f: f"file:{f}" for f in files}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add_edge(src: str, dst: str, kind: str, line: int = 0) -> None:
        edges.setdefault((src, dst, kind), {"source": src, "target": dst, "kind": kind, "line": line})

    for node in callables.values():
        add_edge(file_id[node.file], node.id, "defines", node.line)
    for edge in graph.edges:
        dst = edge.dst
        if dst in classes:
            dst = f"{dst}.__init__"  # Class(...) runs __init__ when the class defines one
        if dst not in callables:
            continue
        if edge.src in callables and edge.src != dst:
            add_edge(edge.src, dst, "call", edge.line)
        elif edge.src in modules:
            add_edge(file_id[modules[edge.src].file], dst, "call", edge.line)

    sinks: dict[str, dict[str, Any]] = {}
    for src, found in sink_hits(graph).items():
        if src not in callables:
            continue
        for hit in found:
            sid = f"sink:{hit.target}"
            meta = sinks.setdefault(sid, {"target": hit.target, "effect": hit.effect or "", "category": hit.category,
                                          "vuln_class": hit.vuln_class, "weak": hit.weak})
            if hit.effect and not meta["effect"]:
                meta["effect"] = hit.effect
            meta["weak"] = meta["weak"] and hit.weak
            add_edge(src, sid, "sink", hit.line)

    # what the pull request changed
    changed: set[str] = set()
    changed_files: set[str] = set()
    changed_source = "none"
    if data.diff:
        lines = changed_lines(data.diff)
        changed = set(changed_nodes(graph, lines)[0]) & set(callables)
        changed_files = {f for f in lines if f in file_id}
        changed_source = "diff"

    # reach paths from the changed functions (proposals), and the oracle's proven paths
    reach: list[dict[str, Any]] = []
    if changed:
        report = find_paths(graph, sorted(changed))
        for path in report.paths[:MAX_REACH_PATHS]:
            nodes = [n for n in dict.fromkeys(path.to_changed + path.to_sink) if n in callables]
            reach.append({"entry": path.entry, "changed": path.changed, "nodes": nodes + [f"sink:{path.sink.target}"],
                          "sink": f"sink:{path.sink.target}", "effect": path.sink.effect or "",
                          "confidence": path.confidence})
    proven_paths = [
        {"entry": p["entry"], "nodes": [n for n in p["nodes"] if n in callables] + [f"sink:{p['sink']}"],
         "sink": f"sink:{p['sink']}", "effect": p.get("effect") or ""}
        for p in run_view.get("paths", [])
    ]

    # findings: each suspicion sits on the innermost function holding its location
    def holder(file: str, line: int) -> str:
        best = ""
        best_span = 10**9
        for node in callables.values():
            if node.file == file and node.start <= line <= node.end and node.end - node.start < best_span:
                best, best_span = node.id, node.end - node.start
        return best

    node_findings: dict[str, list[dict[str, Any]]] = {}
    effect_severity: dict[str, str] = {}
    for item in detail.get("proven", []) + detail.get("discarded", []):
        evidence = _dict(item.get("evidence"))
        observed = _dict(evidence.get("observed_location"))
        file = observed.get("file") or item.get("file") or ""
        line = observed.get("line") or item.get("line") or 0
        severity = _text(evidence.get("severity"), 32).lower()
        effect = _text(_dict(evidence.get("effect")).get("type"), 64)
        if item.get("verdict") == VerdictValue.PROVEN.value and severity in SEVERITIES and effect:
            effect_severity[effect] = _worse(severity, effect_severity.get(effect, ""))
        target = holder(file, line) if file and line else ""
        if target:
            node_findings.setdefault(target, []).append({
                "id": item.get("id", ""), "verdict": item.get("verdict", ""), "class": item.get("class", ""),
                "severity": severity if severity in SEVERITIES else "", "effect": effect,
                "cwe": _text(evidence.get("cwe"), 80), "line": line,
            })

    on_reach = {n for p in reach for n in p["nodes"]}
    on_proven = {n for p in proven_paths for n in p["nodes"]}
    in_pr = changed | on_reach | on_proven
    proven_edges = {(a, b) for p in proven_paths for a, b in zip(p["nodes"], p["nodes"][1:])}
    reach_edges = {(a, b) for p in reach for a, b in zip(p["nodes"], p["nodes"][1:])}

    degree: dict[str, int] = {}
    for src, dst, _ in edges:
        degree[src] = degree.get(src, 0) + 1
        degree[dst] = degree.get(dst, 0) + 1

    node_rows: list[dict[str, Any]] = []
    for f in files:
        fid = file_id[f]
        node_rows.append({
            "id": fid, "kind": "file", "label": f.rsplit("/", 1)[-1], "name": f, "module": "", "file": f,
            "line": 0, "end": 0, "entry": False, "entry_kind": "", "entry_detail": "", "sink": False,
            "effect": "", "category": "", "weak": False, "changed": f in changed_files,
            "in_pr": f in changed_files or any(callables[n].file == f for n in in_pr if n in callables),
            "proven": False, "findings": [], "severity": "", "degree": degree.get(fid, 0),
        })
    for nid, node in callables.items():
        kind, detail_text = entry_kind.get(nid, ("", ""))
        findings = node_findings.get(nid, [])
        severity = ""
        for finding in findings:
            if finding["verdict"] == VerdictValue.PROVEN.value:
                severity = _worse(finding["severity"], severity)
        if nid in on_proven:
            for path in proven_paths:
                if nid in path["nodes"]:
                    severity = _worse(effect_severity.get(path["effect"], ""), severity)
        node_rows.append({
            "id": nid, "kind": node.kind, "label": node.name.rsplit(".", 1)[-1], "name": node.name,
            "module": node.module, "file": node.file, "line": node.line, "end": node.end,
            "entry": bool(kind), "entry_kind": kind, "entry_detail": _text(detail_text, 200), "sink": False,
            "effect": "", "category": "", "weak": False, "changed": nid in changed, "in_pr": nid in in_pr,
            "proven": nid in on_proven, "findings": findings, "severity": severity, "degree": degree.get(nid, 0),
        })
    for sid, meta in sinks.items():
        severity = effect_severity.get(meta["effect"], "") if sid in on_proven else ""
        node_rows.append({
            "id": sid, "kind": "sink", "label": _text(meta["target"], 120), "name": _text(meta["target"], 200),
            "module": "", "file": "", "line": 0, "end": 0, "entry": False, "entry_kind": "", "entry_detail": "",
            "sink": True, "effect": meta["effect"], "category": meta["category"], "weak": meta["weak"],
            "changed": False, "in_pr": sid in in_pr, "proven": sid in on_proven, "findings": [],
            "severity": severity, "degree": degree.get(sid, 0),
        })

    truncated = len(node_rows) > MAX_CODEGRAPH_NODES
    if truncated:
        node_rows.sort(key=lambda n: (not n["in_pr"], not n["proven"], -n["degree"], n["id"]))
        node_rows = node_rows[:MAX_CODEGRAPH_NODES]
    kept = {n["id"] for n in node_rows}
    edge_rows = [
        {**e, "proven": (e["source"], e["target"]) in proven_edges,
         "in_pr": (e["source"], e["target"]) in proven_edges | reach_edges}
        for e in edges.values() if e["source"] in kept and e["target"] in kept
    ]
    result = {
        "available": True,
        "reason": "",
        "nodes": node_rows,
        "edges": edge_rows,
        "reach_paths": reach,
        "proven_paths": proven_paths,
        "effects": list(EFFECTS),
        "changed_source": changed_source,
        "truncated": truncated,
        "stats": {
            "files": len(files),
            "functions": len(callables),
            "sinks": len(sinks),
            "calls": sum(1 for e in edge_rows if e["kind"] == "call"),
            "entries": sum(1 for n in node_rows if n["entry"]),
            "changed": len(changed),
            "reach_paths": len(reach),
            "proven_paths": len(proven_paths),
            "graph_truncated": graph.truncated,
        },
    }
    if len(_CODEGRAPH_CACHE) >= _CODEGRAPH_CACHE_SIZE:
        _CODEGRAPH_CACHE.pop(next(iter(_CODEGRAPH_CACHE)))
    _CODEGRAPH_CACHE[key] = result
    return result
