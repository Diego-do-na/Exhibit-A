"""Tiny file server that confines every download to its base directory (eval fixture, SAFE).

The vulnerable twin is ``../vulnerable/app.py``; the one change is in ``download``. It exists so
that a test which roots the app at the canary's directory (audit A-11 P1b) has a safe app to
misuse: proving it would be a false proof.
"""

import os


class Reply:
    """Minimal response carrying a status code and a text body."""

    def __init__(self, status, body):
        self.status = status
        self.body = body


def load_file(path):
    """Sink: return the text content of the file at ``path``."""
    with open(path, encoding="utf-8") as handle:
        return handle.read()


class App:
    """Small app dispatching download requests to a handler."""

    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.handlers = {}

    def on(self, route):
        """Register the view function serving ``route``."""

        def wrapper(view):
            self.handlers[route] = view
            return view

        return wrapper

    def handle_request(self, method, route, params=None):
        """Entry point: run the handler registered for ``route``."""
        view = self.handlers.get(route)
        if method != "GET" or view is None:
            return Reply(404, "not found")
        return view(params or {})


def create_app(base_dir):
    """Build an app whose download handler confines the requested name to ``base_dir``."""
    app = App(base_dir)

    @app.on("/download")
    def download(params):
        wanted = params.get("name", "")
        base = os.path.realpath(app.base_dir)
        target = os.path.realpath(os.path.join(base, wanted))
        if os.path.commonpath([base, target]) != base:
            return Reply(403, "forbidden")
        return Reply(200, load_file(target))

    return app
