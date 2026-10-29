"""Turn a run's ledger into CI output: result JSON, Markdown summary, PR comment.

The functions here are pure (events and dicts in, strings and dicts out) so
they can be unit-tested without a sandbox, a model or the network. ``main``
is the only part that touches files; the GitHub Action calls it after
``exhibit-a run``.

The gate is the ledger's ``verdict`` events, nothing else. A pull request is
red only when ``fail_on == "proven"`` and at least one suspicion's latest
verdict is ``proven``. Every other outcome, including a run that never
completed, is worded as "nothing could be proven", never as "safe": the
status field says how much was actually verified.

Model output (suspicion ids, reasons) reaches the Markdown, so every
untrusted string is escaped before rendering: no HTML, no @mentions, no
table breakage, no copy of the comment marker.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ..ledger import Ledger
from ..schemas import Event, EventType, VerdictValue

#: Version of the result JSON layout. Bump on any breaking change.
SCHEMA_VERSION = "1"

#: Hidden marker that identifies the one PR comment this tool owns.
COMMENT_MARKER = "<!-- exhibit-a:pr-comment v1 -->"

#: Author the comment must have for it to be updated in place.
DEFAULT_COMMENT_AUTHOR = "github-actions[bot]"

FAIL_ON_VALUES = ("proven", "never")

#: How much of the pipeline actually ran.
#: completed: the baseline passed and every raised suspicion was judged.
#: aborted: the baseline failed or a model step aborted the run.
#: timed_out: the run hit max-runtime-minutes before finishing.
#: not_run: no ledger events (engine not wired for this surface, or crashed).
#: skipped: the risk gate decided exploits were not needed.
STATUSES = ("completed", "aborted", "timed_out", "not_run", "skipped")

_TIMEOUT_EXIT_CODES = (124, 137)
_MAX_TEXT = 300
_FULL_SYSTEM = {"naive": False, "oracle": True, "differential": True, "defender": True}


# -- result -------------------------------------------------------------------------


def _latest_by_suspicion(events: Sequence[Event], kind: EventType) -> dict[str, Event]:
    latest: dict[str, Event] = {}
    for event in events:
        if event.type == kind:
            sid = event.payload.get("suspicion_id")
            if isinstance(sid, str):
                latest[sid] = event
    return latest


def _select_run(events: Sequence[Event], run_id: str | None) -> tuple[str, list[Event]]:
    if not events:
        return run_id or "", []
    chosen = run_id if run_id is not None else events[-1].run_id
    return chosen, [e for e in events if e.run_id == chosen]


def build_result(
    events: Iterable[Event],
    *,
    run_id: str | None = None,
    engine_exit: int | None = None,
    risk: Mapping[str, Any] | None = None,
    skipped_reason: str = "",
) -> dict[str, Any]:
    """Project ledger events of one run into the machine-readable CI result.

    ``run_id`` defaults to the run of the last event. ``engine_exit`` is the
    exit code of ``exhibit-a run``; it is only used to recognise a timeout,
    because the CLI also exits non-zero when nothing was proven. ``risk`` is
    the gate's ``Classification.to_dict()``.
    """
    run, own = _select_run(list(events), run_id)
    verdict_events = _latest_by_suspicion(own, EventType.VERDICT)
    packaged = _latest_by_suspicion(own, EventType.PACKAGED)

    counts: dict[str, int] = {value.value: 0 for value in VerdictValue}
    findings: list[dict[str, Any]] = []
    for sid, event in verdict_events.items():
        label = str(event.payload.get("verdict", "unknown"))
        counts[label] = counts.get(label, 0) + 1
        if label == VerdictValue.PROVEN.value:
            pkg = packaged.get(sid)
            findings.append({
                "suspicion_id": sid,
                "reason": str(event.payload.get("reason", "")),
                "fix_verified": bool(pkg and pkg.payload.get("fix_verified")),
                "package": str(pkg.payload.get("path", "")) if pkg else "",
            })

    raised = sum(1 for e in own if e.type == EventType.SUSPICION_RAISED)
    baselines = [
        e for e in own if e.type == EventType.BASELINE_DONE and "suspicion_id" not in e.payload
    ]
    flags = dict(baselines[0].payload.get("flags") or {}) if baselines else {}
    ablated = any(flags.get(k, v) != v for k, v in _FULL_SYSTEM.items())

    if skipped_reason:
        status = "skipped"
    elif engine_exit in _TIMEOUT_EXIT_CODES:
        status = "timed_out"
    elif not own:
        status = "not_run"
    elif baselines and baselines[0].payload.get("ok") is not True:
        status = "aborted"
    elif raised > len(verdict_events) and not flags.get("naive"):
        status = "aborted"  # suspicions raised but never judged
    else:
        status = "completed"

    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run,
        "status": status,
        "skipped_reason": skipped_reason,
        "engine_exit": engine_exit,
        "proven": counts[VerdictValue.PROVEN.value],
        "verdicts": counts,
        "suspicions_raised": raised,
        "dropped": sum(counts.values()) - counts[VerdictValue.PROVEN.value],
        "findings": sorted(findings, key=lambda f: f["suspicion_id"]),
        "flags": flags,
        "ablated": ablated,
        "risk": dict(risk) if risk else None,
        "tokens_in": sum(e.tokens_in for e in own),
        "tokens_out": sum(e.tokens_out for e in own),
        "cost_usd": round(sum(e.cost_usd for e in own), 6),
        "surface_ran": bool(own),
    }


def exit_code(result: Mapping[str, Any], fail_on: str) -> int:
    """Non-zero only when failing on proven findings and one exists."""
    if fail_on not in FAIL_ON_VALUES:
        raise ValueError(f"fail_on must be one of {FAIL_ON_VALUES}, got {fail_on!r}")
    return 1 if fail_on == "proven" and int(result.get("proven", 0)) > 0 else 0


def step_outputs(result: Mapping[str, Any]) -> dict[str, str]:
    """Flat key/value pairs for ``$GITHUB_OUTPUT``."""
    out = {
        "status": str(result["status"]),
        "proven": str(result["proven"]),
        "dropped": str(result["dropped"]),
        "suspicions-raised": str(result["suspicions_raised"]),
    }
    for label, count in result["verdicts"].items():
        out[label.replace("_", "-")] = str(count)
    return out


# -- rendering ----------------------------------------------------------------------


_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+!|~>])")


def _escape(text: Any, limit: int = _MAX_TEXT) -> str:
    """Make an untrusted string inert inside Markdown table cells and prose."""
    value = str(text).replace(COMMENT_MARKER, "")
    value = " ".join(value.split())  # no newlines: keeps tables and headings intact
    if len(value) > limit:
        value = value[: limit - 1] + "…"
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    value = _MARKDOWN_SPECIAL.sub(r"\\\1", value)
    return value.replace("@", "@​")  # no mentions, no notifications


_HEADLINES = {
    "skipped": "Exploits not run (risk gate): nothing was verified, so nothing could be proven",
    "timed_out": "Run timed out before finishing: nothing could be proven in the time allowed",
    "not_run": "Engine produced no verdicts: nothing was verified, so nothing could be proven",
    "aborted": "Run aborted before every suspicion was judged: nothing could be proven",
    "completed": "Nothing could be proven",
}


def _headline(result: Mapping[str, Any]) -> str:
    proven = int(result["proven"])
    if proven:
        noun = "finding" if proven == 1 else "findings"
        return f"\U0001f534 {proven} proven {noun}"
    icon = "\U0001f7e2" if result["status"] == "completed" else "⚪"
    return f"{icon} {_HEADLINES[result['status']]}"


def render_markdown(result: Mapping[str, Any]) -> str:
    """Markdown for ``$GITHUB_STEP_SUMMARY``."""
    lines = [f"## Exhibit A: {_headline(result)}", ""]
    if result["status"] == "skipped" and result.get("skipped_reason"):
        lines += [f"Reason: {_escape(result['skipped_reason'])}", ""]
    lines += [
        "A green result means *nothing could be proven*. It is not a statement "
        "that the change is secure.",
        "",
        f"- Status: `{result['status']}`",
        f"- Suspicions raised: {result['suspicions_raised']}, proven: "
        f"{result['proven']}, dropped without proof: {result['dropped']}",
    ]
    if result.get("risk"):
        lines.append(f"- Risk gate: `{_escape(result['risk'].get('risk', '?'))}`")
    if result.get("ablated"):
        lines.append(
            "- Warning: this run used ablation flags "
            f"`{_escape(json.dumps(result['flags'], sort_keys=True))}`; "
            "its verdicts do not meet the full proof standard."
        )
    lines.append(
        f"- Tokens in/out: {result['tokens_in']}/{result['tokens_out']}, "
        f"cost: ${float(result['cost_usd']):.4f}"
    )
    lines += ["", "| Verdict | Count |", "|---|---|"]
    lines += [f"| {_escape(k)} | {v} |" for k, v in sorted(result["verdicts"].items())]
    if result["findings"]:
        lines += [
            "",
            "### Proven findings",
            "",
            "| Suspicion | Fix verified | Oracle reason |",
            "|---|---|---|",
        ]
        for finding in result["findings"]:
            lines.append(
                f"| {_escape(finding['suspicion_id'], 120)} | "
                f"{'yes' if finding['fix_verified'] else 'no'} | "
                f"{_escape(finding['reason'])} |"
            )
        lines += [
            "",
            "Each proven finding comes with an exploit test, a proposed fix and "
            "evidence in the `exhibit-a-ledger` artifact. Nothing is merged automatically.",
        ]
    return "\n".join(lines) + "\n"


def render_comment(result: Mapping[str, Any]) -> str:
    """PR comment body; the marker lets later runs update it in place."""
    return f"{COMMENT_MARKER}\n{render_markdown(result)}"


def find_marker_comment(
    comments: Iterable[Mapping[str, Any]], author: str = DEFAULT_COMMENT_AUTHOR
) -> int | None:
    """Id of the comment to update, or None to create one.

    Only a comment that starts with the marker AND was written by ``author``
    counts, so a human comment quoting the marker is never overwritten.
    When several match, the oldest (lowest id) wins.
    """
    ids = [
        int(c["id"])
        for c in comments
        if isinstance(c.get("id"), int)
        and str(c.get("body") or "").startswith(COMMENT_MARKER)
        and (c.get("user") or {}).get("login") == author
    ]
    return min(ids) if ids else None


# -- CLI ----------------------------------------------------------------------------


def _write_outputs(path: Path, outputs: Mapping[str, str]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for key, value in outputs.items():
            handle.write(f"{key}={value}\n")


def _cmd_build(args: argparse.Namespace) -> int:
    events = Ledger(Path(args.ledger)).read_all() if args.ledger else []
    risk = json.loads(Path(args.risk).read_text(encoding="utf-8")) if args.risk else None
    result = build_result(
        events,
        run_id=args.run_id,
        engine_exit=args.engine_exit,
        risk=risk,
        skipped_reason=args.skipped_reason,
    )
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "summary.md").write_text(render_markdown(result), encoding="utf-8")
    (out / "comment.md").write_text(render_comment(result), encoding="utf-8")
    if args.step_summary:
        with Path(args.step_summary).open("a", encoding="utf-8") as handle:
            handle.write(render_markdown(result))
    if args.github_output:
        outputs = step_outputs(result)
        outputs["exit-code"] = str(exit_code(result, args.fail_on))
        _write_outputs(Path(args.github_output), outputs)
    print(json.dumps({k: result[k] for k in ("status", "proven", "dropped")}, sort_keys=True))
    return exit_code(result, args.fail_on) if args.gate else 0


def _cmd_find_comment(args: argparse.Namespace) -> int:
    data = json.loads(Path(args.comments).read_text(encoding="utf-8"))
    pages = data if data and isinstance(data[0], list) else [data]  # gh --paginate --slurp
    found = find_marker_comment((c for page in pages for c in page), args.author)
    print("" if found is None else found)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m exhibit_a.ci.summary")
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="Write result.json, summary.md and comment.md.")
    build.add_argument("--ledger", default=None, help="Ledger JSONL (missing file = no events).")
    build.add_argument("--out-dir", required=True)
    build.add_argument("--run-id", default=None)
    build.add_argument("--engine-exit", type=int, default=None)
    build.add_argument("--risk", default=None, help="JSON written by exhibit_a.ci.gate.")
    build.add_argument("--skipped-reason", default="")
    build.add_argument("--fail-on", choices=FAIL_ON_VALUES, default="proven")
    build.add_argument("--step-summary", default=None, help="Append Markdown here.")
    build.add_argument("--github-output", default=None, help="Append key=value outputs here.")
    build.add_argument(
        "--gate", action="store_true", help="Exit non-zero per --fail-on (default: exit 0)."
    )
    build.set_defaults(func=_cmd_build)

    find = sub.add_parser("find-comment", help="Print the id of the comment to update.")
    find.add_argument("comments", help="JSON list of issue comments from the GitHub API.")
    find.add_argument("--author", default=DEFAULT_COMMENT_AUTHOR)
    find.set_defaults(func=_cmd_find_comment)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError) as exc:
        print(f"summary: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
