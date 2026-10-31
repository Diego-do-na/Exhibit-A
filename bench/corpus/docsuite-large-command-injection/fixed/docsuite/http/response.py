"""Responses produced by controllers."""

from ..util import jsonutil


class Response:
    """Status, headers and a JSON-serializable body."""

    def __init__(self, status=200, body=None, headers=None):
        self.status = status
        self.body = {} if body is None else body
        self.headers = {"content-type": "application/json"}
        self.headers.update(headers or {})

    def encoded(self):
        """The body as bytes."""
        if isinstance(self.body, bytes):
            return self.body
        return jsonutil.dumps(self.body).encode("utf-8")

    def __repr__(self):
        return f"Response({self.status}, {self.body!r})"


def ok(body=None, **headers):
    """A 200 response."""
    return Response(200, body, headers)


def created(body=None, location=None):
    """A 201 response, with a Location header when given."""
    return Response(201, body, {"location": location} if location else None)


def no_content():
    """A 204 response."""
    return Response(204, {})


def error(status, message):
    """An error response with a JSON message."""
    return Response(status, {"error": message})
