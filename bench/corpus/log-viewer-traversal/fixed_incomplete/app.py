"""Log viewer service.

``App`` answers viewer requests carrying a log name by reading that file
under the log directory and returning its text.
"""

import os


def read_log(base, name):
    """Read ``base/name`` and return the entry text."""
    path = os.path.join(base, name)
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    return {"name": name, "text": text}


class App:
    """Answer viewer requests carrying a log name."""

    def __init__(self, base):
        self.base = base

    def handle_request(self, method, name=None):
        """Entry point: show ``name`` on GET, reject anything else."""
        if method != "GET":
            return "method not allowed"
        return read_log(self.base, name.replace("../", ""))


def create_app(base):
    """Build a log viewer service."""
    return App(base)
