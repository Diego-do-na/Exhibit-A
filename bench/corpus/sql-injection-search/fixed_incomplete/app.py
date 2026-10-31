"""Product catalog service for a small online shop.

``App`` is the HTTP-facing object: it receives a method, a path and the
request parameters and returns a response mapping. Everything behind it lives
in the ``shop`` package (routes, services, repository, models, utilities).
"""

from shop.routes import dispatch
from shop.errors import ApiError


class App:
    """Answer catalog requests."""

    def handle_request(self, method, path, params=None):
        """Entry point: route one request and return ``{"status", "body"}``."""
        try:
            return dispatch(method, path, params or {})
        except ApiError as error:
            return {"status": error.status, "body": {"error": error.message}}


def create_app():
    """Build the catalog service."""
    return App()
