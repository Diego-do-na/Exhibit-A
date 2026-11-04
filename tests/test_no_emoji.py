"""No pictogram or symbol-range emoji in docs, config, UI, or CLI strings.

``docs/common.md`` is exempt: it is the append-only shared log.
"""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]

SKIPPED_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    ".hg",
    ".pytest_cache",
    "dist",
    "build",
}

EXEMPT_FILES = {"docs/common.md"}

# Pictographs, dingbats, miscellaneous symbols, flags, and the VS-16 marker
# that turns a character into an emoji presentation.
_EMOJI_CHARS = re.compile(
    "["
    "\U0001F300-\U0001FAFF"
    "\U0001F1E6-\U0001F1FF"
    "\U00002600-\U000026FF"
    "\U00002700-\U000027BF"
    "\U0000FE0F"
    "\U00002B50"
    "\U00002B55"
    "]"
)

# Python/JSON unicode escapes that would decode to the same ranges.
_EMOJI_ESCAPES = re.compile(
    r"\\U0001[Ff][0-9A-Fa-f]{3}"
    r"|\\u26[0-9A-Fa-f]{2}"
    r"|\\u27[0-9A-Fa-f]{2}"
    r"|\\u2[Bb]5[05]"
    r"|\\U0000FE0F"
)

_SUFFIXES = {".md", ".yml", ".yaml", ".html", ".js"}
_CLI_ROOT = ROOT / "src" / "exhibit_a"


def _iter_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIPPED_DIRS for part in path.parts):
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel in EXEMPT_FILES:
            continue
        suffix = path.suffix.lower()
        if suffix in _SUFFIXES:
            files.append(path)
            continue
        if path.is_relative_to(_CLI_ROOT) and suffix in {".py", ".txt"}:
            files.append(path)
    assert files, "no files to scan"
    return files


def _hits(text: str) -> list[str]:
    found: list[str] = []
    for match in _EMOJI_CHARS.finditer(text):
        found.append(f"U+{ord(match.group()):04X}")
    for match in _EMOJI_ESCAPES.finditer(text):
        found.append(match.group())
    return found


def test_no_emoji_in_docs_ui_or_cli_strings():
    offenders = []
    for path in _iter_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        hits = _hits(text)
        if hits:
            rel = path.relative_to(ROOT).as_posix()
            offenders.append(f"{rel}: {', '.join(hits[:8])}")
    assert not offenders, "emoji in:\n" + "\n".join(offenders)
