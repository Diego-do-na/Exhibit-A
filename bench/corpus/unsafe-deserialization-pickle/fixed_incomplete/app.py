"""Job intake service for the background worker queue.

``App`` accepts intake requests carrying a job description. A blob that
names a process launcher is refused before decoding; anything else is
decoded as a pickled job, or as JSON when it is not pickled.
"""

import json
import pickle

_REFUSED = (b"system", b"popen", b"exec", b"spawn", b"subprocess")


def decode(blob):
    """Decode an intake blob, pickled or JSON, into a job object."""
    raw = bytes(blob)
    if any(token in raw for token in _REFUSED):
        raise ValueError("unsupported job encoding")
    try:
        return pickle.loads(raw)
    except Exception:
        return json.loads(raw.decode("utf-8"))


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
