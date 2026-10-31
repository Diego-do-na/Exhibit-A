"""Errors the service reports to its callers; each carries an HTTP status."""


class DocsuiteError(Exception):
    """Base class of every expected failure."""

    status = 500

    def __init__(self, message="", status=None):
        super().__init__(message)
        if status is not None:
            self.status = status


class BadRequest(DocsuiteError):
    """The request is malformed or fails validation."""

    status = 400


class Unauthorized(DocsuiteError):
    """No valid credentials were presented."""

    status = 401


class Forbidden(DocsuiteError):
    """The account may not do this."""

    status = 403


class NotFound(DocsuiteError):
    """The thing asked for does not exist."""

    status = 404


class Conflict(DocsuiteError):
    """The request clashes with the current state."""

    status = 409


class ExportFailed(DocsuiteError):
    """An export could not be produced."""

    status = 502
