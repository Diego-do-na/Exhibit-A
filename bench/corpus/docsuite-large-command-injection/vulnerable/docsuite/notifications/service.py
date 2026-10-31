"""Notification use cases."""

from .digest import queue_digest
from .preferences import PreferenceStore
from .templates import render


class NotificationService:
    """Tell accounts about exports, cleanups and quota use."""

    def __init__(self, outbox, preferences=None):
        self.outbox = outbox
        self.preferences = preferences or PreferenceStore()

    def welcome(self, account):
        """Queue the welcome message for a new account."""
        body = render("welcome", {"name": account.name, "role": account.role})
        return self.outbox.queue(account.id, "Welcome", body)

    def export_ready(self, account, title, name):
        """Queue the export-finished message."""
        body = render("export_ready", {"name": account.name, "format": name,
                                       "title": title})
        return self.outbox.queue(account.id, "Export ready", body)

    def cleanup_done(self, account, scope, removed):
        """Queue the cleanup-finished message."""
        body = render("cleanup_done", {"name": account.name, "scope": scope,
                                       "removed": removed})
        return self.outbox.queue(account.id, "Cleanup done", body)

    def quota_warning(self, account, percent):
        """Queue the quota warning message."""
        body = render("quota_warning", {"name": account.name, "percent": percent})
        return self.outbox.queue(account.id, "Quota warning", body)

    def digest_for(self, account, documents, jobs):
        """Queue the periodic digest for ``account`` and return its id."""
        return queue_digest(self.outbox, account, documents, jobs)

    def flush(self, limit=25):
        """Mark up to ``limit`` queued messages sent and return their ids."""
        sent = []
        for message in self.outbox.pending()[:limit]:
            if self.outbox.mark_sent(message["id"]):
                sent.append(message["id"])
        return sent
