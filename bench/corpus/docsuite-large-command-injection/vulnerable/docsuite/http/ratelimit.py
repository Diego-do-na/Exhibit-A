"""Per-token request budgets."""

import time

from ..errors import DocsuiteError


class RateLimiter:
    """Allow a number of requests per token in a sliding window."""

    def __init__(self, limit=600, window_seconds=60):
        self.limit = limit
        self.window = window_seconds
        self._hits = {}

    def _prune(self, token, moment):
        kept = [seen for seen in self._hits.get(token, [])
                if moment - seen < self.window]
        self._hits[token] = kept
        return kept

    def check(self, token):
        """Record one request for ``token``; raise 429 past the limit."""
        moment = time.monotonic()
        kept = self._prune(token or "anonymous", moment)
        if len(kept) >= self.limit:
            raise DocsuiteError("too many requests", status=429)
        kept.append(moment)
        self._hits[token or "anonymous"] = kept
        return {"remaining": self.limit - len(kept)}

    def remaining(self, token):
        """Requests ``token`` may still make in the current window."""
        kept = self._prune(token or "anonymous", time.monotonic())
        return max(0, self.limit - len(kept))

    def reset(self, token):
        """Forget the recorded requests of ``token``."""
        self._hits.pop(token or "anonymous", None)

    def reset_all(self):
        """Forget every recorded request."""
        self._hits.clear()
