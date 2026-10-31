"""Per-document activity feeds."""

from ..util import dates


class ActivityLog:
    """What happened to each document, newest last, kept in memory."""

    def __init__(self, limit=50):
        self._events = {}
        self.limit = limit

    def record(self, doc_id, kind, actor, detail=""):
        """Remember one event for ``doc_id`` and return it."""
        event = {"kind": kind, "actor": actor, "detail": detail,
                 "at": dates.stamp()}
        feed = self._events.setdefault(doc_id, [])
        feed.append(event)
        del feed[: max(0, len(feed) - self.limit)]
        return event

    def feed(self, doc_id, limit=10):
        """The newest ``limit`` events for ``doc_id``, newest first."""
        return list(reversed(self._events.get(doc_id, [])))[:limit]

    def kinds(self, doc_id):
        """The distinct event kinds recorded for ``doc_id``."""
        return sorted({event["kind"] for event in self._events.get(doc_id, [])})

    def count(self, doc_id):
        """How many events ``doc_id`` has."""
        return len(self._events.get(doc_id, []))

    def recent_kinds(self, limit=10):
        """The newest events of every document, flattened, newest first."""
        every = [event for feed in self._events.values() for event in feed]
        every.sort(key=lambda event: event["at"], reverse=True)
        return every[:limit]
