"""Logging setup and a tiny event recorder."""

import logging

_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def get_logger(name):
    """A logger under the ``docsuite`` namespace."""
    return logging.getLogger("docsuite." + name)


def configure(level="WARNING"):
    """Configure the root handler once; later calls only change the level."""
    root = logging.getLogger("docsuite")
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(_FORMAT))
        root.addHandler(handler)
    root.setLevel(level)
    return root


class Recorder:
    """Collects ``(event, detail)`` pairs in memory, for tests and the audit report."""

    def __init__(self):
        self.events = []

    def record(self, event, **detail):
        """Remember one event."""
        self.events.append((event, detail))

    def count(self, event):
        """How many times ``event`` was recorded."""
        return sum(1 for name, _ in self.events if name == event)
