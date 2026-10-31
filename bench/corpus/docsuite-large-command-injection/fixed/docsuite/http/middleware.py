"""Cross-cutting request handling: timing headers, request ids and size limits."""

import time

from ..errors import BadRequest
from ..util import ids


class RequestContext:
    """Per-request bookkeeping."""

    def __init__(self):
        self.request_id = ids.next_id("req")
        self.started = time.monotonic()

    def elapsed_ms(self):
        """Milliseconds since the request began."""
        return int((time.monotonic() - self.started) * 1000)


def check_size(request, limit):
    """Refuse a request body over ``limit`` bytes."""
    if len(request.raw_body) > limit:
        raise BadRequest("request body is too large", status=413)


def decorate(response, context):
    """Add the request id and timing to a response."""
    response.headers["x-request-id"] = context.request_id
    response.headers["x-elapsed-ms"] = str(context.elapsed_ms())
    return response


def public_paths():
    """Paths that need no credentials."""
    return ("/accounts/login",)
