"""Job intake service for the background worker queue.

``App`` accepts intake requests carrying a job description. A request is
handled by decoding the attached blob from its JSON form into a job object.
"""

import json


def decode(blob):
    """Decode an intake blob from its JSON form into a job object."""
    return json.loads(bytes(blob).decode("utf-8"))


class App:
    """Accept intake requests carrying a job blob."""

    def __init__(self, base):
        self.base = base

    def handle_request(self, method, blob=None):
        """Entry point: decode the attached ``blob`` on POST."""
        if method != "POST":
            return "method not allowed"
        return decode(blob)


def create_app(base):
    """Build an app that decodes intake blobs."""
    return App(base)
