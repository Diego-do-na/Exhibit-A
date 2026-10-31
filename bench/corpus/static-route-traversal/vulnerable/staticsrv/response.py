"""Response objects returned by the application."""


class Response:
    """Status code, headers and a bytes body."""

    def __init__(self, status, body=b"", headers=None):
        self.status = status
        self.body = body
        self.headers = dict(headers or {})

    @property
    def text(self):
        """The body decoded as UTF-8, with undecodable bytes replaced."""
        return self.body.decode("utf-8", "replace")


def not_found():
    """A plain 404 response."""
    return Response(404, b"not found", {"content-type": "text/plain"})


def method_not_allowed():
    """A plain 405 response listing the accepted methods."""
    return Response(405, b"method not allowed", {"content-type": "text/plain", "allow": "GET, HEAD"})
