"""Directory listing service for the upload review workflow.

``App`` answers listing requests for names inside its base directory. A name
carrying one of the rejected shell metacharacters is refused before the
listing runs; anything else is listed with the platform ``ls`` command.
"""

import subprocess

_REJECTED = (";", "|", "&", "`", "$", "(", ")")


def list_dir(base, name):
    """List ``base/name`` with the platform ``ls`` command."""
    if any(mark in name for mark in _REJECTED):
        raise ValueError("unsupported name")
    command = "ls " + base + "/" + name
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


class App:
    """Answer listing requests for names inside ``base``."""

    def __init__(self, base):
        self.base = base

    def handle_request(self, method, name=None):
        """Entry point: list ``name`` on POST, reject anything else."""
        if method != "POST":
            return "method not allowed"
        return list_dir(self.base, name)


def create_app(base):
    """Build an app that lists names inside ``base``."""
    return App(base)
