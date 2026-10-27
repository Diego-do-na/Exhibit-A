"""Tiny Flask-style file server with a path traversal bug (fixture, intentionally vulnerable)."""

import os
from dataclasses import dataclass


@dataclass
class Response:
    status: int
    body: str


def read_file(path):
    """Sink: reads a file from disk."""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class App:
    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.routes = {}

    def route(self, path):
        def register(view):
            self.routes[path] = view
            return view

        return register

    def handle_request(self, method, path, query=None):
        """Entry point: dispatch a request to its view."""
        view = self.routes.get(path)
        if method != "GET" or view is None:
            return Response(404, "not found")
        return view(query or {})


def create_app(base_dir):
    app = App(base_dir)

    @app.route("/download")
    def download(query):
        name = query.get("name", "")
        # BUG: the name is joined without checking it stays inside base_dir.
        return Response(200, read_file(os.path.join(app.base_dir, name)))

    return app
