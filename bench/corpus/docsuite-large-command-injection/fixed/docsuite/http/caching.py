"""Conditional responses with entity tags."""

import hashlib


def etag_for(payload):
    """A stable tag for response bytes."""
    return hashlib.sha256(payload).hexdigest()[:16]


def not_modified(request, tag):
    """Whether the request already holds the representation tagged ``tag``."""
    offered = request.header("if-none-match", "")
    return bool(offered) and offered.strip() == tag


def cache_headers(tag, max_age=60):
    """The headers marking a representation cacheable under ``tag``."""
    return {"etag": tag, "cache-control": f"max-age={max_age}"}


def fresh(request, payload, max_age=60):
    """``(tag, headers)`` for ``payload``, honouring conditional requests."""
    tag = etag_for(payload)
    if not_modified(request, tag):
        return tag, dict(cache_headers(tag, max_age), status="not_modified")
    return tag, cache_headers(tag, max_age)


def parse_match(value):
    """The entity tags listed in an ``If-None-Match`` header value."""
    return [part.strip() for part in value.split(",") if part.strip()]
