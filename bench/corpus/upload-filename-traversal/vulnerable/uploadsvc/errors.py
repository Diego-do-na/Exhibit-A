"""Errors raised while handling an upload."""


class UploadError(Exception):
    """Base class: the request cannot be stored as sent."""

    status = 400


class InvalidFileName(UploadError):
    """The file name of a part is unusable."""


class MalformedBody(UploadError):
    """The request body is not a well-formed multipart document."""


class TooLarge(UploadError):
    """The request is over a configured limit."""

    status = 413
