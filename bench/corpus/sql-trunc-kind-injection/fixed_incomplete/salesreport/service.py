"""Use cases: one function per report."""

from . import reports
from .config import DEFAULT_SINCE, MAX_TOP_CUSTOMERS
from .dates import parse_day
from .db import connect
from .errors import ReportError


def revenue_report(unit, since):
    """Revenue per period of the given unit."""
    conn = connect()
    try:
        return reports.revenue_by_period(conn, unit, parse_day(since or DEFAULT_SINCE))
    finally:
        conn.close()


def seasonality_report(part, since):
    """Order counts per value of a date part."""
    conn = connect()
    try:
        return reports.orders_by_part(conn, part, parse_day(since or DEFAULT_SINCE))
    finally:
        conn.close()


def top_customers_report(limit):
    """The best customers by paid revenue."""
    try:
        count = int(limit)
    except (TypeError, ValueError):
        raise ReportError("limit must be a whole number") from None
    conn = connect()
    try:
        return reports.top_customers(conn, max(1, min(count, MAX_TOP_CUSTOMERS)))
    finally:
        conn.close()
