"""Date parameters of the report requests."""

import datetime

from .errors import ReportError


def parse_day(text):
    """A ``YYYY-MM-DD`` text as a date."""
    try:
        return datetime.date.fromisoformat(text)
    except (TypeError, ValueError):
        raise ReportError("dates are written YYYY-MM-DD") from None
