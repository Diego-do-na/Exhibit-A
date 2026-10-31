"""Directory listing service for the upload review workflow.

``App`` answers listing requests for names inside its base directory. The
requested name reaches ``ls`` as a separate argument vector element, so the
platform shell never interprets it.
"""

import os
import subprocess


def list_dir(base, name):
    """List ``base/name`` with the platform ``ls`` command."""
    argv = ["ls", os.path.join(base, name)]
    return subprocess.run(argv, capture_output=True, text=True).stdout


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
