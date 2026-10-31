"""The request object handed to controllers."""

from ..errors import BadRequest
from ..util import jsonutil


class Request:
    """One request: method, path, query, headers and a decoded JSON body."""

    def __init__(self, method, path, headers=None, body=b"", query=None):
        self.method = method.upper()
        self.path = path
        self.query = dict(query or {})
        self.headers = {key.lower(): value for key, value in (headers or {}).items()}
        self.raw_body = body or b""
        self.params = {}
        self.account = None

    def header(self, name, default=None):
        """A header value by case-insensitive name."""
        return self.headers.get(name.lower(), default)

    def json(self):
        """The body decoded as a JSON object ({} when there is no body)."""
        if not self.raw_body:
            return {}
        data = jsonutil.loads(self.raw_body.decode("utf-8", "replace"))
        if not isinstance(data, dict):
            raise BadRequest("the body must be a JSON object")
        return data

    def bearer_token(self):
        """The token of an ``Authorization: Bearer`` header, or None."""
        value = self.header("authorization", "")
        scheme, _, token = value.partition(" ")
        return token.strip() if scheme.lower() == "bearer" and token.strip() else None
