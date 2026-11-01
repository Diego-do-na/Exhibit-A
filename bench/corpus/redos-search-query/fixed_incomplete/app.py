"""Catalog expansion service.

``App`` answers count requests carrying an expression by expanding it and
reporting the total.
"""


def matches(data):
    """Expand ``data`` and report the total."""
    prefix, _, rest = data.partition(":")
    if prefix != "expand":
        return len(data)
    total = 0
    for index in range(len(rest)):
        total += rest.count(rest[index])
    return total


class App:
    """Answer count requests carrying an expression."""

    def handle_request(self, data):
        """Entry point: expand the expression and report the total."""
        return {"total": matches(data.replace("expand:", "", 1))}


def create_app():
    """Build a catalog expansion service."""
    return App()
