"""Small helpers for reading request parameters."""

from shop.errors import ApiError


def as_list(value):
    """Return a request value as a list of strings (repeated parameters arrive as lists)."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def first(value, default=""):
    """Return the first value of a request parameter, or a default."""
    items = as_list(value)
    return items[0] if items else default


def clean_text(value):
    """Trim surrounding whitespace from a text parameter."""
    return str(value).strip()


def parse_int(value, default, low, high):
    """Parse an integer parameter and keep it inside ``low..high``."""
    if value in (None, ""):
        return default
    try:
        number = int(str(value))
    except ValueError:
        raise ApiError(400, "not a number") from None
    return max(low, min(high, number))
