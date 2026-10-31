"""Checks applied to request values before a use case sees them."""

from ..errors import BadRequest


def require(data, key, kind=str):
    """``data[key]`` when it is present and of the right type, else a 400."""
    if key not in data:
        raise BadRequest(f"missing field: {key}")
    value = data[key]
    if not isinstance(value, kind):
        raise BadRequest(f"field {key} must be a {kind.__name__}")
    return value


def optional(data, key, kind=str, default=None):
    """``data[key]`` when present (type-checked), else ``default``."""
    if key not in data or data[key] is None:
        return default
    return require(data, key, kind)


def clean_title(value, limit):
    """A title: stripped, non-empty and at most ``limit`` characters."""
    title = value.strip()
    if not title:
        raise BadRequest("the title must not be empty")
    if len(title) > limit:
        raise BadRequest(f"the title is longer than {limit} characters")
    return title


def clean_tags(values, limit=10):
    """A list of lower-case tags, deduplicated, at most ``limit`` of them."""
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise BadRequest("tags must be a list of strings")
    seen = []
    for item in values:
        tag = item.strip().lower()
        if tag and tag not in seen:
            seen.append(tag)
    if len(seen) > limit:
        raise BadRequest(f"at most {limit} tags are allowed")
    return seen


def choice(value, allowed, name):
    """``value`` when it is one of ``allowed``, else a 400 naming the field."""
    if value not in allowed:
        raise BadRequest(f"{name} must be one of: {', '.join(allowed)}")
    return value
