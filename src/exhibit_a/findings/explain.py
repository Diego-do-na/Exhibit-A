"""The plain explanation that opens a proven finding, built from facts only.

``explain`` fills a fixed template from the facts the oracle observed and the loop checked:
the effect, the entry point, the sink caller and its file:line, what the exploit test did, what
the fix changed and whether it was verified. It never reads model text. The model's hypothesis
is appended by ``model_guess`` under a label that says it is the model's guess, so a reader can
never take a sentence of the model for something the oracle saw.

The result is plain text. Callers escape it for Markdown or HTML, since names in it come from
the code under test.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

_EFFECTS = {
    "canary_read": "the application read a file outside the allowed directory (the canary file)",
    "canary_write": "the application created or wrote a file outside the allowed directory (the canary file)",
    "canary_exec": "the application ran a program outside the allowed directory (the canary program)",
}
_LINE_SOURCES = {
    "graph_sink_call": "the line of the sink call, found by the static call graph inside the function the oracle saw",
    "function_start": "the line where that function starts, as the oracle recorded it",
}

#: Label put in front of the model's hypothesis wherever it is shown.
MODEL_GUESS_LABEL = "Model's hypothesis (the model's guess; the oracle did not observe it)"
MAX_FIELD = 300


def _text(value: Any, limit: int = MAX_FIELD) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def summarize_patch(patch_text: str) -> dict[str, Any]:
    """Files and added/removed line counts of a unified diff, ``{}`` for an empty one.

    The patch is the loop's own (``difflib`` over the files the fixer proposed): a file header
    is a ``---``/``+++`` pair that a ``@@`` line follows, so a changed line that merely starts
    with ``++`` or ``--`` is counted as a change, not read as a header.
    """
    lines = patch_text.splitlines()
    files: list[str] = []
    added = removed = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        header = (line.startswith("--- ") and i + 2 < len(lines)
                  and lines[i + 1].startswith("+++ ") and lines[i + 2].startswith("@@"))
        if header:
            name = lines[i + 1][4:].strip()
            name = name[2:] if name.startswith("b/") else name
            if name not in files and len(files) < 50:
                files.append(name)
            i += 2
            continue
        if line.startswith("+"):
            added += 1
        elif line.startswith("-"):
            removed += 1
        i += 1
    if not files:
        return {}
    return {"fix_files": files, "fix_added": added, "fix_removed": removed}


_FACT_TEXT = ("effect", "access", "entry_point", "entry_file", "sink_function", "test")
_FACT_INT = ("runs", "fix_added", "fix_removed", "bypass_tried", "bypass_succeeded")
_MAX_CHAIN = 64


def clean_facts(raw: Any) -> dict[str, Any] | None:
    """A bounded, well-typed copy of facts read from a ledger or package, or None.

    Those files are data, not code: anything that is not one of the known keys with the right
    type is dropped, text is capped, so a malformed or hostile record can neither break a
    renderer nor smuggle in a field the template would show.
    """
    if not isinstance(raw, Mapping):
        return None
    out: dict[str, Any] = {}
    for key in _FACT_TEXT:
        if isinstance(raw.get(key), str):
            out[key] = _text(raw[key])
    for key in _FACT_INT:
        if _int(raw.get(key)) is not None:
            out[key] = raw[key]
    if isinstance(raw.get("fix_verified"), bool):
        out["fix_verified"] = raw["fix_verified"]
    files = raw.get("fix_files")
    if isinstance(files, list):
        out["fix_files"] = [_text(f, 200) for f in files[:50] if isinstance(f, str)]
    location = raw.get("observed_location")
    if isinstance(location, Mapping) and isinstance(location.get("file"), str):
        clean: dict[str, Any] = {"file": _text(location["file"], 300)}
        if _int(location.get("line")) is not None:
            clean["line"] = location["line"]
        for key in ("function", "line_source", "sink_call"):
            if isinstance(location.get(key), str):
                clean[key] = _text(location[key])
        out["observed_location"] = clean
    chain = raw.get("chain")
    if isinstance(chain, list) and 0 < len(chain) <= _MAX_CHAIN:
        frames = [
            {"file": _text(f["file"], 300), "qualname": _text(f["qualname"], 200), "line": f["line"]}
            for f in chain
            if isinstance(f, Mapping) and isinstance(f.get("file"), str)
            and isinstance(f.get("qualname"), str) and _int(f.get("line")) is not None
        ]
        if len(frames) == len(chain):
            out["chain"] = frames
    return out or None


def where(location: Mapping[str, Any] | None) -> str:
    """``file:line`` of an observed location, or ``""`` when it has no file."""
    if not isinstance(location, Mapping) or not isinstance(location.get("file"), str):
        return ""
    line = _int(location.get("line"))
    return f"{_text(location['file'], 200)}:{line}" if line else _text(location["file"], 200)


def explain(facts: Mapping[str, Any] | None) -> str:
    """The template paragraph for one proven finding; ``""`` when there are no facts at all."""
    if not isinstance(facts, Mapping) or not facts:
        return ""
    sentences: list[str] = []

    effect = facts.get("effect")
    if isinstance(effect, str) and effect:
        phrase = _EFFECTS.get(effect, f"the effect '{_text(effect, 60)}'")
        sentences.append(f"The oracle observed that {phrase}.")

    entry, sink = facts.get("entry_point"), facts.get("sink_function")
    location = facts.get("observed_location")
    spot = where(location)
    if isinstance(entry, str) and entry:
        route = f"It happened through the entry point '{_text(entry, 120)}'"
        if isinstance(sink, str) and sink:
            route += f", in the sink caller '{_text(sink, 120)}'"
        if spot:
            route += f", at {spot}"
        sentences.append(route + ".")
        source = location.get("line_source") if isinstance(location, Mapping) else None
        if spot and source in _LINE_SOURCES:
            sentences.append(f"That line is {_LINE_SOURCES[source]}.")

    runs = _int(facts.get("runs"))
    test = facts.get("test")
    drove = isinstance(entry, str) and bool(entry)
    did = "The exploit test"
    if isinstance(test, str) and test:
        did += f" ({_text(test, 120)})"
    did += " drove that entry point and failed" if drove else " failed"
    did += " on the vulnerable code"
    if runs:
        did += f" in {runs} of {runs} runs"
    if drove and isinstance(effect, str) and effect:
        did += ", with the effect observed each time"
    sentences.append(did + ".")

    files = facts.get("fix_files")
    verified = facts.get("fix_verified")
    if isinstance(files, list) and files:
        names = ", ".join(f"'{_text(f, 120)}'" for f in files[:5] if isinstance(f, str))
        added, removed = _int(facts.get("fix_added")), _int(facts.get("fix_removed"))
        counts = f" (+{added}/-{removed})" if added is not None and removed is not None else ""
        sentences.append(f"The proposed fix changed {names}{counts}.")
    if verified is True:
        sentences.append(
            "The fix was verified: the same exploit test passes on the fixed code and the "
            "project's own baseline test still passes there."
        )
    elif verified is False:
        sentences.append("The fix was not verified.")
    tried, succeeded = _int(facts.get("bypass_tried")), _int(facts.get("bypass_succeeded"))
    if tried and succeeded:
        sentences.append(f"{succeeded} of {tried} bypass variants still reached the effect on the fixed code.")
    return " ".join(sentences)


def model_guess(hypothesis: Any) -> str:
    """The model's hypothesis under its label, or ``""`` when there is none."""
    text = _text(hypothesis, 600) if hypothesis else ""
    return f"{MODEL_GUESS_LABEL}: {text}" if text else ""
