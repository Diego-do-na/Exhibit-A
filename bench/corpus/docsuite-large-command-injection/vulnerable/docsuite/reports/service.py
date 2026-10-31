"""Report use cases."""

from ..maintenance import vacuum
from ..storage.health import service_health
from ..storage.manifest import collect
from ..storage.quota import tree_bytes
from .trends import trends
from .summary import summarize_all
from .usage import document_stats, usage_report


class ReportService:
    """Assemble the admin usage report from the live services."""

    def __init__(self, settings, accounts, documents, exports, audit=None):
        self.settings = settings
        self.accounts = accounts
        self.documents = documents
        self.exports = exports
        self.audit = audit

    def admin_usage(self):
        """Headline numbers plus per-scope storage summaries."""
        scoped = [self.settings.path(name)
                  for name in ("documents", "exports", "outbox", "cache")]
        report = usage_report(
            self.accounts.all(),
            self.documents.all(),
            self.settings.data_dir,
            self.exports.queue.list(),
        )
        report["scopes"] = vacuum.summarize_many(scoped)
        report["bytes_on_disk"] = tree_bytes(self.settings.data_dir)
        report["trends"] = trends(self.documents.all())
        report["health"] = service_health(self.settings.data_dir)
        report["logins"] = self.audit.counts() if self.audit is not None else {}
        report["summary"] = summarize_all(report)
        report["manifest"] = collect(
            self.settings.data_dir,
            ("documents", "exports", "outbox", "cache", "versions", "audit",
             "backups"),
        )
        return report

    def library(self):
        """Counts and averages over the document collection."""
        return document_stats(self.documents.all())
