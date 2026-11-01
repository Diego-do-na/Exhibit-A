"""Log viewer service.

``App`` answers viewer requests carrying a log name by reading that file
under the log directory and returning its text.
"""

import os


def read_log(base, name):
    """Read ``base/name`` when it stays inside ``base``."""
    if not isinstance(name, str):
        raise TypeError("unsupported name")
    target = os.path.realpath(os.path.join(base, name))
    root = os.path.realpath(base)
    if target != root and not target.startswith(root + os.sep):
        raise ValueError("name escapes the log directory")
    with open(target, encoding="utf-8") as handle:
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
        return read_log(self.base, name)


def create_app(base):
    """Build a log viewer service."""
    return App(base)
