"""Render portable finding packages without trusting their text content."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any

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


def _line_numbered(source: str, selected: int) -> list[tuple[int, str, bool]]:
    return [(number, line, number == selected) for number, line in enumerate(source.splitlines(), 1)]


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
    return {
        "verdict": verdict.get("verdict", "unknown"),
        "class": _first(suspicion, "class", "vuln_class", default="unknown"),
        "severity": _severity(verdict, evidence),
        "file": location.get("file", "unknown"),
        "line": location.get("line", 0),
        "source": _source(evidence, directory, _text(location.get("file", ""))),
        "hypothesis": _first(suspicion, "hypothesis", default=evidence.get("reason", "")),
        "test": _first(proof, "test_path", default="test_exploit.py"),
        "event": _first(oracle, "effect", "reason", default="not recorded"),
        "provenance": provenance,
        "runs": _first(proof, "runs", default=0),
        "patch": (directory / "fix.patch").read_text(encoding="utf-8") if (directory / "fix.patch").is_file() else "(no patch included)",
        "bypass": bypass,
        "discarded": evidence.get("discarded_suspicions", 0),
        "tokens": tokens,
        "cost": cost,
    }


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
        "## Suspicious code",
        "",
        f"**File:** `{_md(data['file'])}`; **highlighted line:** {data['line']}",
        "",
    ]
    for number, content, selected in _line_numbered(data["source"], int(data["line"] or 0)):
        lines.append(f"{'> ' if selected else '  '}{number:4} {_md(content, None)}")
    lines += [
        "",
        "## Hypothesis",
        "",
        _md(data["hypothesis"]),
        "",
        "## Exploit test",
        "",
        f"`{_md(data['test'])}`",
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
    lines.extend(f"    {_md(line, None)}" for line in data["patch"].splitlines())
    lines += [
        "",
        "## Bypass check",
        "",
        f"Tried: {data['bypass'].get('tried', 0)}; succeeded: {data['bypass'].get('succeeded', 0)}",
        "",
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


def render_html(package_dir: str | Path) -> str:
    """Render a package as self-contained HTML with escaped dynamic content."""
    directory, verdict, evidence = _package_data(package_dir)
    data = _details(directory, verdict, evidence)
    code = "".join(
        f'<span class="{"hit" if selected else ""}">{number:4} {_html(content)}</span>\n'
        for number, content, selected in _line_numbered(data["source"], int(data["line"] or 0))
    )
    safe = data["verdict"] == "proven"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Exhibit A finding</title>
<style>body{{font:16px system-ui,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;color:#202124}}pre{{background:#f6f8fa;padding:1rem;overflow:auto}}.hit{{display:block;background:#ffd7d7}}.meta{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.5rem 2rem}}</style>
</head><body><h1>Exhibit A finding: {_html(data["verdict"])}</h1>
{"" if safe else '<p>Nothing could be proven; this result is not a claim about project security.</p>'}
<div class="meta"><p><b>Vulnerability class:</b> {_html(data["class"])}</p><p><b>Severity:</b> {_html(data["severity"])} (proven + reachable entry point + observed effect =&gt; high)</p></div>
<h2>Suspicious code</h2><p><b>File:</b> {_html(data["file"])}; <b>highlighted line:</b> {_html(data["line"])}</p><pre><code>{code}</code></pre>
<h2>Hypothesis</h2><p>{_html(data["hypothesis"])}</p>
<h2>Exploit test</h2><p><code>{_html(data["test"])}</code></p>
<h2>Oracle evidence</h2><ul><li>Event: {_html(data["event"])}</li><li>Provenance: <code>{_html(json.dumps(data["provenance"], sort_keys=True))}</code></li><li>Stable runs: {_html(data["runs"])}</li></ul>
<h2>Red → green</h2><p>Vulnerable: {_html(data["verdict"])}; fixed: {_html((verdict.get("evidence") or {}).get("passes_on", "not verified"))}</p>
<h2>Patch</h2><pre>{_html(data["patch"])}</pre>
<h2>Bypass check</h2><p>Tried: {_html(data["bypass"].get("tried", 0))}; succeeded: {_html(data["bypass"].get("succeeded", 0))}</p>
<h2>Accounting</h2><ul><li>Discarded suspicions: {_html(data["discarded"])}</li><li>Tokens: {_html(data["tokens"])}; cost: ${float(data["cost"]):.6f}</li></ul>
</body></html>"""
