"""Build review suggestions and an optional fix-PR payload from a proof bundle.

This module deliberately does not call GitHub or execute the proof test.  It
only parses bounded unified diffs and copies the already verified exploit into
the conventional regression-test directory.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..triage.diffparse import parse_diff

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True)
class _Hunk:
    path: str
    new_start: int
    new_count: int
    lines: tuple[str, ...]


def _patch_hunks(text: str) -> list[_Hunk]:
    result: list[_Hunk] = []
    path = ""
    current: _Hunk | None = None
    body: list[str] = []
    for raw in text.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:].split("\t", 1)[0].removeprefix("b/")
        match = _HUNK.match(raw)
        if match:
            if current is not None:
                result.append(_Hunk(current.path, current.new_start, current.new_count, tuple(body)))
            body = []
            current = _Hunk(
                path,
                int(match.group(3)),
                int(match.group(4) or "1"),
                (),
            )
        elif current is not None:
            body.append(raw)
    if current is not None:
        result.append(_Hunk(current.path, current.new_start, current.new_count, tuple(body)))
    return result


def _changed_lines(diff: str) -> dict[str, set[int]]:
    """Return new-side lines changed by the PR, keyed by repository path."""
    parsed = parse_diff(diff)
    changed: dict[str, set[int]] = {}
    for file_change in parsed.files:
        path = next((p for p in reversed(file_change.paths) if p), None)
        if not path:
            continue
        line = 0
        for raw in file_change.body:
            match = _HUNK.match(raw)
            if match:
                line = int(match.group(3))
                continue
            if not line:
                continue
            marker = raw[:1]
            if marker in {" ", "+"}:
                if marker == "+":
                    changed.setdefault(path, set()).add(line)
                line += 1
    return changed


def _suggestion_text(hunk: _Hunk, changed: set[int]) -> tuple[int, int, str] | None:
    """Map a fix hunk to a contiguous changed PR range and its replacement."""
    new_lines: list[tuple[int, str]] = []
    line = hunk.new_start
    for raw in hunk.lines:
        marker = raw[:1]
        if marker in {" ", "+"}:
            new_lines.append((line, raw[1:]))
            line += 1
    mapped = [item for item in new_lines if item[0] in changed]
    if not mapped:
        return None
    first, last = mapped[0][0], mapped[-1][0]
    content = "\n".join(text for number, text in new_lines if first <= number <= last)
    return first, last, content + ("\n" if content else "")


def build_review_comments(run_dir: str | Path, pr_diff: str) -> list[dict[str, Any]]:
    """Return recorded GitHub review-comment payloads for a verified fix.

    A hunk that cannot map to changed PR lines becomes an ordinary issue-style
    comment payload rather than an invalid suggestion.
    """
    root = Path(run_dir)
    packages = sorted(root.glob("packages/*/fix.patch"))
    changed = _changed_lines(pr_diff)
    comments: list[dict[str, Any]] = []
    for patch_path in packages:
        patch = patch_path.read_text(encoding="utf-8")
        for index, hunk in enumerate(_patch_hunks(patch), 1):
            mapped = _suggestion_text(hunk, changed.get(hunk.path, set()))
            if mapped:
                start, end, content = mapped
                body = f"Apply the verified fix:\n\n```suggestion\n{content}```"
                payload: dict[str, Any] = {
                    "body": body,
                    "path": hunk.path,
                    "line": end,
                    "side": "RIGHT",
                }
                if start != end:
                    payload.update({"start_line": start, "start_side": "RIGHT"})
                comments.append(payload)
            else:
                comments.append({
                    "body": (
                        f"Verified fix hunk {index} for `{hunk.path}` is outside the PR diff.\n\n"
                        f"```diff\n{chr(10).join(hunk.lines)}\n```"
                    ),
                    "path": hunk.path,
                })
    return comments


def _proof_test(root: Path) -> Path:
    candidates = sorted(root.glob("packages/*/test_exploit.py"))
    if not candidates:
        raise ValueError(f"{root} contains no packaged test_exploit.py")
    return candidates[0]


def build_fix_branch_payload(run_dir: str | Path) -> dict[str, Any]:
    """Return files for a fix branch, including the proof as a regression test."""
    root = Path(run_dir)
    patch_files = sorted(root.glob("packages/*/fix.patch"))
    if not patch_files:
        raise ValueError(f"{root} contains no fix.patch")
    patch = patch_files[0].read_text(encoding="utf-8")
    test = _proof_test(root)
    finding = patch_files[0].parent.name
    test_path = f"tests/exhibit_a/test_{re.sub(r'[^A-Za-z0-9_]+', '_', finding).strip('_')}.py"
    return {
        "patch": patch,
        "test_path": test_path,
        "test": test.read_text(encoding="utf-8"),
        "files": [
            {"path": "fix.patch", "content": patch},
            {"path": test_path, "content": test.read_text(encoding="utf-8")},
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("comments", "branch"))
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--diff", default="")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    payload: Any = (
        build_review_comments(args.run_dir, Path(args.diff).read_text(encoding="utf-8"))
        if args.command == "comments"
        else build_fix_branch_payload(args.run_dir)
    )
    Path(args.output).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
