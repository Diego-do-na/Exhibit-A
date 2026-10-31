"""Tag handling."""

import re

_SEPARATORS = re.compile(r"[,;]+")


def normalize_tag(tag):
    """A tag: lower-case, stripped, spaces turned into dashes."""
    return re.sub(r"\s+", "-", tag.strip().lower()).strip("-")


def split_tags(value):
    """A comma- or semicolon-separated string turned into normalized tags."""
    if isinstance(value, list):
        items = value
    else:
        items = _SEPARATORS.split(str(value))
    seen = []
    for item in items:
        tag = normalize_tag(item)
        if tag and tag not in seen:
            seen.append(tag)
    return seen


def tagged(documents, tag):
    """The documents carrying ``tag``."""
    wanted = normalize_tag(tag)
    return [doc for doc in documents if wanted in [normalize_tag(t) for t in doc.tags]]


def cloud(documents, limit=20):
    """The most used tags with their counts, most used first."""
    counts = {}
    for doc in documents:
        for tag in doc.tags:
            key = normalize_tag(tag)
            counts[key] = counts.get(key, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [{"tag": tag, "count": count} for tag, count in ranked[:limit]]
