"""Errors the service reports to its callers."""


class ReportError(Exception):
    """A request that cannot be answered as asked."""

    status = 400
