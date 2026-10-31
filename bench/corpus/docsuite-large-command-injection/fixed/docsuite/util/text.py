"""Text helpers."""

import re
import unicodedata

_NON_WORD = re.compile(r"[^a-z0-9]+")


def slugify(text, limit=60):
    """A lower-case ASCII slug of ``text``, at most ``limit`` characters, never empty."""
    folded = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    slug = _NON_WORD.sub("-", folded.lower()).strip("-")[:limit].strip("-")
    return slug or "untitled"


def truncate(text, width, marker="..."):
    """``text`` shortened to ``width`` characters, ending in ``marker`` when it was cut."""
    if len(text) <= width:
        return text
    return text[: max(0, width - len(marker))] + marker


def word_count(text):
    """Number of whitespace-separated words."""
    return len(text.split())


def first_line(text):
    """The first non-empty line of ``text``, stripped."""
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


def snippet(text, needle, radius=30):
    """A short excerpt of ``text`` around the first occurrence of ``needle``."""
    index = text.lower().find(needle.lower())
    if index < 0:
        return truncate(first_line(text), 2 * radius)
    start = max(0, index - radius)
    return text[start : index + len(needle) + radius].replace("\n", " ").strip()
