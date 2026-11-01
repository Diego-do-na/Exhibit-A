"""Analysis export service.

``App`` answers export requests carrying a report name and content by
storing the content under the base name in the export directory.
"""

import os


def store_report(dest_dir, name, data):
    """Write ``data`` under the base name of ``name`` inside ``dest_dir``."""
    stored = os.path.basename(name)
    if not stored or stored in (".", ".."):
        raise ValueError("unsupported name")
    path = os.path.join(dest_dir, stored)
    root = os.path.realpath(dest_dir)
    target = os.path.realpath(path)
    if target != root and not target.startswith(root + os.sep):
        raise ValueError("name escapes the export directory")
    with open(target, "wb") as handle:
        handle.write(data)
    return stored


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
