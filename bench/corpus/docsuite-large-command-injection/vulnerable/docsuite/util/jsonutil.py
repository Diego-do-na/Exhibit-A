"""JSON helpers."""

import json


def dumps(value):
    """Compact, key-sorted JSON text."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def loads(text, default=None):
    """Decode JSON text, returning ``default`` for text that is not valid JSON."""
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def pick(mapping, keys):
    """A new mapping with only the given keys that ``mapping`` has."""
    return {key: mapping[key] for key in keys if key in mapping}
