"""Directory search service.

``App`` answers lookup requests by matching the query against directory
user names with a compiled pattern.
"""

import re

PATTERN = re.compile(r"[a-z]+$")


def matches(data):
    """Report whether ``data`` matches a directory user name."""
    return bool(PATTERN.search(data))


class App:
    """Answer lookup requests carrying a query."""

    def handle_request(self, data):
        """Entry point: report whether the query matches a user name."""
        
        return {"match": matches(data)}


def create_app():
    """Build a directory search service."""
    return App()
