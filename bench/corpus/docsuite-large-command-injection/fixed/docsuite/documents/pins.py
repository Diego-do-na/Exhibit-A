"""Pinned documents, kept in memory."""


class PinBoard:
    """The documents each account pinned for quick access."""

    def __init__(self):
        self._pins = {}

    def pin(self, account_id, doc_id):
        """Pin ``doc_id`` for ``account_id``; True when it is newly pinned."""
        pinned = self._pins.setdefault(account_id, [])
        if doc_id in pinned:
            return False
        pinned.append(doc_id)
        return True

    def unpin(self, account_id, doc_id):
        """Remove a pin; True when something was removed."""
        pinned = self._pins.get(account_id, [])
        if doc_id not in pinned:
            return False
        pinned.remove(doc_id)
        return True

    def pinned(self, account_id):
        """The pinned document ids of ``account_id``, in pin order."""
        return list(self._pins.get(account_id, []))

    def pinned_by(self, doc_id):
        """The accounts that pinned ``doc_id``, sorted."""
        return sorted(account for account, docs in self._pins.items()
                      if doc_id in docs)

    def clear(self, account_id):
        """Remove every pin of ``account_id`` and return how many were removed."""
        count = len(self._pins.get(account_id, []))
        self._pins[account_id] = []
        return count
