"""Per-account notification preferences."""

NOTIFIABLE = ("welcome", "export_ready", "cleanup_done", "quota_warning", "digest")


class PreferenceStore:
    """Which message kinds each account wants, kept in memory."""

    def __init__(self):
        self._muted = {}

    def mute(self, account_id, kind):
        """Stop sending ``kind`` to ``account_id`` and return the muted set."""
        if kind not in NOTIFIABLE:
            raise KeyError(f"unknown message kind: {kind}")
        self._muted.setdefault(account_id, set()).add(kind)
        return self.shown(account_id)

    def unmute(self, account_id, kind):
        """Send ``kind`` to ``account_id`` again."""
        if kind not in NOTIFIABLE:
            raise KeyError(f"unknown message kind: {kind}")
        self._muted.get(account_id, set()).discard(kind)
        return self.shown(account_id)

    def muted(self, account_id):
        """The kinds ``account_id`` does not want, sorted."""
        return sorted(self._muted.get(account_id, set()))

    def shown(self, account_id):
        """The kinds ``account_id`` still wants, in a stable order."""
        quiet = self._muted.get(account_id, set())
        return [kind for kind in NOTIFIABLE if kind not in quiet]

    def wants(self, account_id, kind):
        """Whether ``kind`` may be sent to ``account_id``."""
        return kind in self.shown(account_id)

    def describe(self, account_id):
        """The preference mapping shown for ``account_id``."""
        return {"account": account_id, "shown": self.shown(account_id),
                "muted": self.muted(account_id)}
