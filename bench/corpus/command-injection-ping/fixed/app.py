"""Connectivity check service.

``App`` answers check requests carrying a host name by pinging that host
without a shell and returning the tool output.
"""

import re
import subprocess


def ping(host):
    """Run the reachability check for ``host`` and return its output."""
    if not isinstance(host, str) or re.fullmatch(r"[A-Za-z0-9.-]+", host) is None:
        raise ValueError("unsupported host")
    try:
        done = subprocess.run(["ping", "-c", "1", host],
                              capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        return ""
    return done.stdout


class App:
    """Answer check requests carrying a host name."""

    def __init__(self, base):
        self.base = base

    def handle_request(self, method, host=None):
        """Entry point: check ``host`` on POST, reject anything else."""
        if method != "POST":
            return "method not allowed"
        return ping(host)


def create_app(base):
    """Build a connectivity check service."""
    return App(base)
