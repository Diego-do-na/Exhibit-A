"""Catalog expansion service.

``App`` answers count requests carrying an expression by expanding it and
reporting the total.
"""


def matches(data):
    """Expand ``data`` and report the total."""
    return len(data)


class App:
    """Answer count requests carrying an expression."""

    def handle_request(self, data):
        """Entry point: expand the expression and report the total."""
        return {"total": matches(data)}


def create_app():
    """Build a catalog expansion service."""
    return App()
