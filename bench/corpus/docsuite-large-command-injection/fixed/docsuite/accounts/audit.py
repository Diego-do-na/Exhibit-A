"""Who tried to log in, and whether it worked."""

from ..util import dates


class LoginAudit:
    """Remember recent login attempts, newest last, kept in memory."""

    def __init__(self, limit=200):
        self._attempts = []
        self.limit = limit

    def record(self, name, worked):
        """Remember one login attempt for ``name``."""
        entry = {"name": name, "worked": worked, "at": dates.stamp()}
        self._attempts.append(entry)
        del self._attempts[: max(0, len(self._attempts) - self.limit)]
        return entry

    def recent(self, limit=20):
        """The newest ``limit`` attempts, newest first."""
        return list(reversed(self._attempts))[:limit]

    def failures(self, limit=20):
        """The newest failed attempts, newest first."""
        return [entry for entry in self.recent(self.limit)
                if not entry["worked"]][:limit]

    def failures_for(self, name, limit=5):
        """The newest failed attempts for one name, newest first."""
        return [entry for entry in self.recent(self.limit)
                if entry["name"] == name and not entry["worked"]][:limit]

    def counts(self):
        """Totals of worked and failed attempts."""
        worked = sum(1 for entry in self._attempts if entry["worked"])
        return {"worked": worked, "failed": len(self._attempts) - worked,
                "total": len(self._attempts)}
