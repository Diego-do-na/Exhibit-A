"""Render portable finding packages without trusting their text content."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any

from exhibit_a.findings import clean_facts, explain, model_guess, summarize_patch, where

_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+!|~>])")
_ZERO_WIDTH = "\u200b"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid report package file: {path.name}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"report package file is not an object: {path.name}")
    return value


def _package_data(package_dir: str | Path) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    directory = Path(package_dir)
    verdict = _read_json(directory / "verdict.json")
    evidence_path = directory / "evidence.json"
    evidence = _read_json(evidence_path) if evidence_path.is_file() else {}
    return directory, verdict, evidence


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _md(value: Any, limit: int | None = None) -> str:
    text = " ".join(_text(value).split())
    if limit is not None and len(text) > limit:
        text = text[: limit - 1] + "…"
    text = text.replace("<", "&lt;").replace(">", "&gt;").replace("@", f"@{_ZERO_WIDTH}")
    return _MARKDOWN_SPECIAL.sub(r"\\\1", text)


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _code(value: Any) -> str:
    """One line of untrusted code for an indented Markdown code block, shown as written.

    Markdown is not parsed inside an indented code block, so backslash escapes would only
    show up as literal backslashes (and collapsing whitespace would destroy the code's
    indentation). The text stays inert anyway: control characters are dropped, tabs become
    spaces, and a zero-width space after every "<", "@" and "](" means no renderer that
    ignores code blocks can see a tag, a mention or a link target in it.
    """
    text = _CONTROL.sub("", _text(value).replace("\t", "    ").replace("\r", ""))
    return (text.replace("<", f"<{_ZERO_WIDTH}").replace("@", f"@{_ZERO_WIDTH}")
            .replace("](", f"]{_ZERO_WIDTH}("))


def _inline_code(value: Any, limit: int = 200) -> str:
    """A short untrusted value (a file name) inside a Markdown code span."""
    text = " ".join(_code(value).split()).replace("`", "'")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _html(value: Any) -> str:
    return html.escape(_text(value), quote=True)


def _first(mapping: dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return default


def _source(evidence: dict[str, Any], directory: Path, file_name: str) -> str:
    embedded = evidence.get("suspicious_code")
    if isinstance(embedded, dict) and isinstance(embedded.get("content"), str):
        return embedded["content"]
    if isinstance(embedded, str):
        return embedded
    candidate = (directory / file_name).resolve()
    if candidate.is_relative_to(directory.resolve()) and candidate.is_file():
        return candidate.read_text(encoding="utf-8")
    return "(source not included in this package)"


#: Lines shown on each side of the highlighted line (the whole file is in the package).
_CONTEXT_LINES = 8
#: Lines shown from the top when no line is highlighted.
_HEAD_LINES = 40


#: Marker of the line the oracle observed, and of the line the model named.
OBSERVED_MARK = ">"
MODEL_MARK = "?"


def _line_numbered(source: str, marks: dict[int, str]) -> list[tuple[int, str, str]]:
    """Numbered lines around every marked line as ``(number, text, marker)``.

    Windows around marks that are close together merge; a gap between windows is one row with
    number 0. With no usable mark the first lines are shown, unmarked.
    """
    lines = source.splitlines()
    spans: list[list[int]] = []
    for line in sorted(n for n in marks if 1 <= n <= len(lines)):
        first, last = max(1, line - _CONTEXT_LINES), min(len(lines), line + _CONTEXT_LINES)
        if spans and first <= spans[-1][1] + 1:
            spans[-1][1] = max(spans[-1][1], last)
        else:
            spans.append([first, last])
    if not spans:
        return [(n, text, " ") for n, text in enumerate(lines[:_HEAD_LINES], 1)]
    rows: list[tuple[int, str, str]] = []
    for first, last in spans:
        if rows:
            rows.append((0, "...", " "))
        rows.extend((n, lines[n - 1], marks.get(n, " ")) for n in range(first, last + 1))
    return rows


def _severity(verdict: dict[str, Any], evidence: dict[str, Any]) -> str:
    if verdict.get("verdict") != "proven":
        return "informational"
    proof = evidence.get("evidence") if isinstance(evidence.get("evidence"), dict) else verdict.get("evidence", {})
    provenance = proof.get("provenance", {}) if isinstance(proof, dict) else {}
    oracle = proof.get("oracle", {}) if isinstance(proof, dict) else {}
    if provenance.get("ok") and (oracle.get("effect") or oracle.get("reason") or oracle.get("events")):
        return "high"
    return "medium"


def _usage(evidence: dict[str, Any], directory: Path) -> tuple[Any, Any]:
    usage = evidence.get("usage")
    if isinstance(usage, dict):
        return usage.get("tokens_in", 0) + usage.get("tokens_out", 0), usage.get("cost_usd", 0.0)
    ledger = directory.parent / "ledger.jsonl"
    if ledger.is_file():
        tokens = cost = 0
        for line in ledger.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            tokens += int(event.get("tokens_in", 0)) + int(event.get("tokens_out", 0))
            cost += float(event.get("cost_usd", 0.0))
        return tokens, cost
    return 0, 0.0


def _observed(evidence: dict[str, Any], provenance: dict[str, Any]) -> dict[str, Any] | None:
    """The location the oracle observed (``file``, ``line``, ``function``, ``line_source``), if any."""
    raw = evidence.get("observed_location") or provenance.get("observed_location")
    facts = clean_facts({"observed_location": raw}) if isinstance(raw, dict) else None
    found = (facts or {}).get("observed_location")
    return found if found and found.get("line") else None


def _observed_source(
    evidence: dict[str, Any], observed: dict[str, Any] | None, model: dict[str, Any], source: str
) -> str | None:
    """Source text of the observed file: the model's file when it is the same, else a copy."""
    if observed is None:
        return None
    if observed["file"] == model.get("file"):
        return source
    extra = evidence.get("observed_code")
    if isinstance(extra, dict) and extra.get("file") == observed["file"] and isinstance(extra.get("content"), str):
        return extra["content"]
    return None


def _fallback_facts(proof: dict[str, Any], oracle: dict[str, Any], patch: str) -> dict[str, Any] | None:
    facts: dict[str, Any] = {}
    if isinstance(oracle.get("effect"), str):
        facts["effect"] = oracle["effect"]
    if isinstance(proof.get("test_path"), str):
        facts["test"] = proof["test_path"]
    if isinstance(proof.get("runs"), int) and proof["runs"] > 0:
        facts["runs"] = proof["runs"]
    if proof.get("passes_on") == "fixed":
        facts["fix_verified"] = True
    facts.update(summarize_patch(patch))
    return clean_facts(facts)


def _details(directory: Path, verdict: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    suspicion = evidence.get("suspicion") if isinstance(evidence.get("suspicion"), dict) else {}
    proof = evidence.get("evidence") if isinstance(evidence.get("evidence"), dict) else verdict.get("evidence", {})
    if not isinstance(proof, dict):
        proof = {}
    location = suspicion.get("location") if isinstance(suspicion.get("location"), dict) else {}
    oracle = proof.get("oracle") if isinstance(proof.get("oracle"), dict) else {}
    provenance = proof.get("provenance") if isinstance(proof.get("provenance"), dict) else {}
    bypass = evidence.get("bypass_attempts") or verdict.get("bypass_attempts") or {}
    tokens, cost = _usage(evidence, directory)
    patch = (directory / "fix.patch").read_text(encoding="utf-8") if (directory / "fix.patch").is_file() else ""
    source = _source(evidence, directory, _text(location.get("file", "")))
    observed = _observed(evidence, provenance)
    facts = clean_facts(evidence.get("facts"))
    if facts is None:
        # A package without recorded facts: only what the proof itself and the patch say.
        facts = _fallback_facts(proof, oracle, patch)
    duplicates = evidence.get("duplicates") if isinstance(evidence.get("duplicates"), list) else []
    return {
        "observed": observed,
        "observed_source": _observed_source(evidence, observed, location, source),
        "facts": facts,
        "duplicates": [d for d in duplicates if isinstance(d, dict)][:20],
        "duplicate_of": _text(verdict.get("duplicate_of") or evidence.get("duplicate_of")),
        "verdict": verdict.get("verdict", "unknown"),
        "class": _first(suspicion, "class", "vuln_class", default="unknown"),
        "severity": _severity(verdict, evidence),
        "file": location.get("file", "unknown"),
        "line": location.get("line", 0),
        "source": source,
        "hypothesis": _first(suspicion, "hypothesis", default=evidence.get("reason", "")),
        "model_hypothesis": suspicion.get("hypothesis", ""),
        "test": _first(proof, "test_path", default="test_exploit.py"),
        "event": _first(oracle, "effect", "reason", default="not recorded"),
        "provenance": provenance,
        "runs": _first(proof, "runs", default=0),
        "patch": patch or "(no patch included)",
        "bypass": bypass,
        "discarded": evidence.get("discarded_suspicions", 0),
        "tokens": tokens,
        "cost": cost,
    }


_LINE_SOURCE_LABELS = {
    "graph_sink_call": "line of the sink call, placed by the static call graph inside the function the oracle observed",
    "function_start": "line where the function the oracle observed starts",
}


def _marks(data: dict[str, Any]) -> tuple[dict[int, str], str]:
    """Which lines to mark in which source: ``({line: marker}, source text)``.

    The oracle-observed line is marked ``>`` and the model's line ``?``, and a line both name
    keeps ``>``. The code shown is the observed file when its text is in the package, else the
    model's file, so a marker never points into text that is not the file it names.
    """
    observed, model_line = data["observed"], int(data["line"] or 0)
    if observed is not None and data["observed_source"] is not None:
        marks = {int(observed["line"]): OBSERVED_MARK}
        if observed["file"] == data["file"] and model_line and model_line not in marks:
            marks[model_line] = MODEL_MARK
        return marks, data["observed_source"]
    return {model_line: MODEL_MARK if observed is not None else ">"}, data["source"]


def _location_lines(data: dict[str, Any]) -> list[str]:
    """Markdown lines that label the observed and the model's location (observed present)."""
    observed = data["observed"]
    label = _LINE_SOURCE_LABELS.get(observed.get("line_source", ""), "line the oracle observed")
    lines = [
        f"- **Oracle-observed location** (marked `{OBSERVED_MARK}`): `{_inline_code(observed['file'])}:{observed['line']}`"
        f", {_md(label)}"
        + (f"; function `{_inline_code(observed['function'])}`" if observed.get("function") else ""),
        f"- **Model's location** (marked `{MODEL_MARK}`, the model's guess): "
        f"`{_inline_code(data['file'])}:{data['line']}`",
    ]
    if data["observed_source"] is None:
        lines.append("- The observed file's source is not part of this package; the code below is the model's file.")
    return lines


def _proof_lines(data: dict[str, Any]) -> list[str]:
    """The opening of a proven finding: oracle facts as a template, then the model's guess."""
    if data["verdict"] != "proven":
        return []
    text = explain(data["facts"])
    guess = model_guess(data["model_hypothesis"])
    lines: list[str] = []
    if data["duplicate_of"]:
        lines += [
            f"This proof is a duplicate of `{_inline_code(data['duplicate_of'])}`: the same effect through the "
            "same entry point and the same application frames to the sink. See that finding's package.",
            "",
        ]
    if text or guess:
        lines += ["## What was proven", ""]
        if text:
            lines += [_md(text), ""]
        if guess:
            lines += [_md(guess), ""]
    return lines


def _duplicate_lines(data: dict[str, Any]) -> list[str]:
    if not data["duplicates"]:
        return []
    lines = [
        "## Duplicate proofs",
        "",
        "These proofs showed the same effect through the same entry point and the same application "
        "frames to the sink, so they are listed here instead of as separate findings.",
        "",
    ]
    for dup in data["duplicates"]:
        location = dup.get("model_location") if isinstance(dup.get("model_location"), dict) else {}
        observed = where(dup.get("observed_location"))
        item = f"- `{_inline_code(dup.get('suspicion_id', '?'))}` (package `{_inline_code(dup.get('package', ''))}`)"
        item += f"; observed at `{_inline_code(observed)}`" if observed else ""
        item += f"; the model's location was `{_inline_code(where(location) or 'unknown')}`"
        hypothesis = model_guess(dup.get("model_hypothesis"))
        lines.append(item + (f"; {_md(hypothesis, 300)}" if hypothesis else ""))
    return lines + [""]


def render_markdown(package_dir: str | Path) -> str:
    """Render a package as Markdown with inert model, code, and diff text."""
    directory, verdict, evidence = _package_data(package_dir)
    data = _details(directory, verdict, evidence)
    lines = [
        f"# Exhibit A finding: {_md(data['verdict'])}",
        "",
        f"- **Vulnerability class:** {_md(data['class'])}",
        f"- **Severity:** {_md(data['severity'])} (proven + reachable entry point + observed effect => high)",
        "",
        *_proof_lines(data),
        "## Suspicious code",
        "",
    ]
    marks, shown = _marks(data)
    if data["observed"] is not None:
        lines += [*_location_lines(data), ""]
    else:
        lines += [f"**File:** `{_inline_code(data['file'])}`; **highlighted line:** {data['line']}", ""]
    for number, content, marker in _line_numbered(shown, marks):
        lines.append(f"    {marker} {number:4} | {_code(content)}" if number else f"        {content}")
    lines += [
        "",
        "## Hypothesis (the model's guess, not part of the proof)",
        "",
        _md(data["hypothesis"]),
        "",
        "## Exploit test",
        "",
        f"`{_inline_code(data['test'])}`",
        "",
        "## Oracle evidence",
        "",
        f"- Event: {_md(data['event'])}",
        f"- Provenance: {_md(json.dumps(data['provenance'], sort_keys=True))}",
        f"- Stable runs: {data['runs']}",
        "",
        "## Red → green",
        "",
        f"- Vulnerable: {_md(data['verdict'])}",
        f"- Fixed: {_md((verdict.get('evidence') or {}).get('passes_on', 'not verified'))}",
        "",
        "## Patch",
        "",
    ]
    lines.extend(f"    {_code(line)}" for line in data["patch"].splitlines())
    lines += [
        "",
        "## Bypass check",
        "",
        f"Tried: {data['bypass'].get('tried', 0)}; succeeded: {data['bypass'].get('succeeded', 0)}",
        "",
        *_duplicate_lines(data),
        "## Accounting",
        "",
        f"- Discarded suspicions: {data['discarded']}",
        f"- Tokens: {data['tokens']}; cost: ${float(data['cost']):.6f}",
        "",
    ]
    if data["verdict"] != "proven":
        lines.insert(1, "Nothing could be proven; this result is not a claim about project security.")
        lines.insert(2, "")
    return "\n".join(lines)


def _proof_html(data: dict[str, Any]) -> str:
    if data["verdict"] != "proven":
        return ""
    text = explain(data["facts"])
    guess = model_guess(data["model_hypothesis"])
    out = ""
    if data["duplicate_of"]:
        out += (f'<p>This proof is a duplicate of <code>{_html(data["duplicate_of"])}</code>: the same effect through '
                "the same entry point and the same application frames to the sink. See that finding's package.</p>")
    if text or guess:
        out += "<h2>What was proven</h2>"
        out += f"<p>{_html(text)}</p>" if text else ""
        out += f'<p class="guess">{_html(guess)}</p>' if guess else ""
    return out


def _duplicates_html(data: dict[str, Any]) -> str:
    if not data["duplicates"]:
        return ""
    items = ""
    for dup in data["duplicates"]:
        location = dup.get("model_location") if isinstance(dup.get("model_location"), dict) else {}
        observed = where(dup.get("observed_location"))
        hypothesis = model_guess(dup.get("model_hypothesis"))
        items += (
            f"<li><code>{_html(dup.get('suspicion_id', '?'))}</code> (package <code>{_html(dup.get('package', ''))}</code>)"
            + (f"; observed at <code>{_html(observed)}</code>" if observed else "")
            + f"; the model's location was <code>{_html(where(location) or 'unknown')}</code>"
            + (f"; {_html(hypothesis)}" if hypothesis else "") + "</li>"
        )
    return ("<h2>Duplicate proofs</h2><p>These proofs showed the same effect through the same entry point and the same "
            f"application frames to the sink, so they are listed here instead of as separate findings.</p><ul>{items}</ul>")


def render_html(package_dir: str | Path) -> str:
    """Render a package as self-contained HTML with escaped dynamic content."""
    directory, verdict, evidence = _package_data(package_dir)
    data = _details(directory, verdict, evidence)
    marks, shown = _marks(data)
    classes = {OBSERVED_MARK: "hit", MODEL_MARK: "model", " ": ""}
    code = "".join(
        f'<span class="{classes.get(marker, "hit")}">{number:4} {_html(content)}</span>\n' if number
        else f'<span class="gap">     ...</span>\n'
        for number, content, marker in _line_numbered(shown, marks)
    )
    if data["observed"] is not None:
        observed = data["observed"]
        label = _LINE_SOURCE_LABELS.get(observed.get("line_source", ""), "line the oracle observed")
        where_html = (
            f'<p><b>Oracle-observed location</b> (highlighted red): <code>{_html(observed["file"])}:{_html(observed["line"])}</code>, '
            f'{_html(label)}</p><p><b>Model\'s location</b> (marked in yellow, the model\'s guess): '
            f'<code>{_html(data["file"])}:{_html(data["line"])}</code></p>'
            + ("" if data["observed_source"] is not None else
               "<p>The observed file's source is not part of this package; the code below is the model's file.</p>")
        )
    else:
        where_html = f'<p><b>File:</b> {_html(data["file"])}; <b>highlighted line:</b> {_html(data["line"])}</p>'
    proof_html = _proof_html(data)
    duplicates_html = _duplicates_html(data)
    safe = data["verdict"] == "proven"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Exhibit A finding</title>
<style>body{{font:16px system-ui,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;color:#202124}}pre{{background:#f6f8fa;padding:1rem;overflow:auto}}.hit{{display:block;background:#ffd7d7}}.model{{display:block;background:#fff3b0}}.gap{{display:block;color:#6a737d}}.meta{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.5rem 2rem}}</style>
</head><body><h1>Exhibit A finding: {_html(data["verdict"])}</h1>
{"" if safe else '<p>Nothing could be proven; this result is not a claim about project security.</p>'}
{proof_html}
<div class="meta"><p><b>Vulnerability class:</b> {_html(data["class"])}</p><p><b>Severity:</b> {_html(data["severity"])} (proven + reachable entry point + observed effect =&gt; high)</p></div>
<h2>Suspicious code</h2>{where_html}<pre><code>{code}</code></pre>
<h2>Hypothesis <small>(the model's guess, not part of the proof)</small></h2><p>{_html(data["hypothesis"])}</p>
<h2>Exploit test</h2><p><code>{_html(data["test"])}</code></p>
<h2>Oracle evidence</h2><ul><li>Event: {_html(data["event"])}</li><li>Provenance: <code>{_html(json.dumps(data["provenance"], sort_keys=True))}</code></li><li>Stable runs: {_html(data["runs"])}</li></ul>
<h2>Red → green</h2><p>Vulnerable: {_html(data["verdict"])}; fixed: {_html((verdict.get("evidence") or {}).get("passes_on", "not verified"))}</p>
<h2>Patch</h2><pre>{_html(data["patch"])}</pre>
<h2>Bypass check</h2><p>Tried: {_html(data["bypass"].get("tried", 0))}; succeeded: {_html(data["bypass"].get("succeeded", 0))}</p>
{duplicates_html}<h2>Accounting</h2><ul><li>Discarded suspicions: {_html(data["discarded"])}</li><li>Tokens: {_html(data["tokens"])}; cost: ${float(data["cost"]):.6f}</li></ul>
</body></html>"""
