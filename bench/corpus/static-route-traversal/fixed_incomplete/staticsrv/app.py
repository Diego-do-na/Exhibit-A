"""The application: routes requests to static routes."""

from .response import method_not_allowed, not_found
from .routes import StaticRoute


class App:
    """Dispatch a request to the first route that claims its path."""

    def __init__(self, routes):
        self.routes = list(routes)

    def handle_request(self, method, path, headers=None):
        """Entry point: answer a GET or HEAD request for ``path``."""
        if method not in ("GET", "HEAD"):
            return method_not_allowed()
        for route in self.routes:
            if route.matches(path):
                return route.serve(method, path, headers or {})
        return not_found()


def create_app(directory):
    """Serve ``directory`` under /static (following links) and /assets (not following them)."""
    return App([
        StaticRoute("/static", directory, follow_symlinks=True),
        StaticRoute("/assets", directory),
    ])
