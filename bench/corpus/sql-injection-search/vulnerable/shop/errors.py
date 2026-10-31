"""Errors that become HTTP responses."""


class ApiError(Exception):
    """A request that cannot be served, with the status to answer."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message
