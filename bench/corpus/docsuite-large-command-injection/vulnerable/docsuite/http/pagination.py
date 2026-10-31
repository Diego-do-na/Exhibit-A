"""Paging of list results."""

from ..errors import BadRequest


def page_of(query, default_size, max_size=100):
    """``(offset, size)`` from the ``page`` and ``size`` query parameters (pages count from 1)."""
    try:
        page = int(query.get("page", 1))
        size = int(query.get("size", default_size))
    except (TypeError, ValueError):
        raise BadRequest("page and size must be whole numbers") from None
    if page < 1 or size < 1:
        raise BadRequest("page and size must be positive")
    size = min(size, max_size)
    return (page - 1) * size, size


def slice_items(items, offset, size):
    """The requested window of ``items`` with the paging details."""
    window = items[offset : offset + size]
    return {"items": window, "total": len(items), "offset": offset, "size": size}
