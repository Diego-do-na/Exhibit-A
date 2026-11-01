"""Connectivity check service.

``App`` answers check requests carrying a host name by pinging that host
and returning the tool output.
"""

import re
import subprocess


def ping(host):
    """Run the reachability check for ``host`` and return its output."""
    command = "ping -c 1 " + host
    done = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
    return done.stdout


class App:
    """Answer check requests carrying a host name."""

    def __init__(self, base):
        self.base = base

    def handle_request(self, method, host=None):
        """Entry point: check ``host`` on POST, reject anything else."""
        if method != "POST":
            return "method not allowed"
        if any(mark in host for mark in (";", "&", "|")):
            raise ValueError("unsupported host")
        return ping(host)


def create_app(base):
    """Build a connectivity check service."""
    return App(base)
