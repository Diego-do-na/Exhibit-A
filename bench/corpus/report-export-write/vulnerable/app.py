"""Analysis export service.

``App`` answers export requests carrying a report name and content by
storing the content under that name in the export directory.
"""

import os


def store_report(dest_dir, name, data):
    """Write ``data`` under ``name`` inside ``dest_dir``."""
    path = os.path.join(dest_dir, name)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)
    return name


class App:
    """Answer export requests carrying a report name and content."""

    def __init__(self, dest_dir):
        self.dest_dir = dest_dir

    def handle_request(self, method, name=None, data=b""):
        """Entry point: store ``name`` on POST, reject anything else."""
        if method != "POST":
            return "method not allowed"
        return store_report(self.dest_dir, name, data)


def create_app(dest_dir):
    """Build an analysis export service."""
    return App(dest_dir)
