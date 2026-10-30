"""Pamphlet shelf: a tiny web-style app that serves text pamphlets from one directory.

Original demo code for the live pull-request demo (docs/ci/live-pr-demo.md). On main it
confines every requested name to the shelf directory; the prepared patches in patches/
change it for the demo. It is not a real service and is never deployed.
"""

import os
from dataclasses import dataclass


@dataclass
class Response:
    status: int
    body: str


def read_text(path):
    """Sink: read one file from disk."""
    with open(path, encoding="utf-8") as handle:
        return handle.read()


class App:
    """Serves GET /index (the pamphlet names) and GET /pamphlet?name=<file>."""

    def __init__(self, shelf_dir):
        self.shelf_dir = shelf_dir

    def _resolve(self, name):
        """Map a pamphlet name to a file inside the shelf, or None when it points outside."""
        root = os.path.realpath(self.shelf_dir)
        target = os.path.realpath(os.path.join(root, name))
        if os.path.commonpath([root, target]) != root:
            return None
        return target

    def handle_request(self, method, path, query=None):
        """Entry point: dispatch one request."""
        if method != "GET":
            return Response(405, "method not allowed")
        if path == "/index":
            names = sorted(os.listdir(self.shelf_dir))
            return Response(200, "\n".join(names))
        if path == "/pamphlet":
            target = self._resolve((query or {}).get("name", ""))
            if target is None or not os.path.isfile(target):
                return Response(404, "not found")
            return Response(200, read_text(target))
        return Response(404, "not found")


def create_app(shelf_dir):
    return App(shelf_dir)
