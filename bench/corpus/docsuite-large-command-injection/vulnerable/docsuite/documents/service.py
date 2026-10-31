"""Document use cases."""

from ..util.text import truncate
from .activity import ActivityLog
from .links import neighbours, related
from .pins import PinBoard
from .search import recent, search_by_tag, search_documents
from .tags import split_tags


class DocumentService:
    """Create, read, update, list and search documents."""

    def __init__(self, repository, versions, board, activity=None, pins=None):
        self.repository = repository
        self.versions = versions
        self.board = board
        self.activity = activity or ActivityLog()
        self.pins = pins or PinBoard()

    def create_document(self, owner, title, body, tags=()):
        """Store a new document owned by ``owner``."""
        document = self.repository.create(title, body, owner, split_tags(tags))
        self.activity.record(document.id, "created", owner, title)
        return document

    def get_document(self, doc_id):
        """A document with its note count and recent activity attached."""
        document = self.repository.require(doc_id)
        payload = document.to_dict()
        payload["notes"] = self.board.count(doc_id)
        payload["activity"] = self.activity.feed(doc_id)
        payload["neighbours"] = neighbours(self.repository.all(), document)
        return payload

    def update_document(self, doc_id, title=None, body=None, tags=None, actor=""):
        """Snapshot the document, then apply the new values."""
        current = self.repository.require(doc_id)
        self.versions.snapshot(current)
        cleaned = split_tags(tags) if tags is not None else None
        document = self.repository.update(doc_id, title=title, body=body,
                                          tags=cleaned)
        self.activity.record(doc_id, "updated", actor, document.title)
        return document

    def list_documents(self, owner=None):
        """Summaries of every document, or only those owned by ``owner``."""
        if owner is None:
            documents = self.repository.all()
        else:
            documents = self.repository.by_owner(owner)
        return [doc.summary() for doc in documents]

    def search(self, query, limit=20):
        """Full-text search over every document."""
        return search_documents(self.repository.all(), query, limit)

    def by_tag(self, tag, limit=20):
        """Documents carrying ``tag``."""
        return search_by_tag(self.repository.all(), tag, limit)

    def related(self, doc_id, limit=5):
        """Documents sharing tags with ``doc_id``."""
        document = self.repository.require(doc_id)
        return related(self.repository.all(), document, limit)

    def pin(self, account_id, doc_id):
        """Pin ``doc_id`` for ``account_id``; True when it is newly pinned."""
        self.repository.require(doc_id)
        return self.pins.pin(account_id, doc_id)

    def unpin(self, account_id, doc_id):
        """Remove a pin; True when something was removed."""
        return self.pins.unpin(account_id, doc_id)

    def pinned_for(self, account_id):
        """The pinned documents of ``account_id`` as summaries."""
        summaries = []
        for doc_id in self.pins.pinned(account_id):
            document = self.repository.get(doc_id)
            if document is not None:
                summaries.append(document.summary())
        return summaries

    def recent(self, limit=10):
        """The most recently touched documents."""
        return recent(self.repository.all(), limit)

    def preview(self, doc_id, width=120):
        """The title and a shortened body of a document."""
        document = self.repository.require(doc_id)
        return {"id": document.id, "title": document.title,
                "preview": truncate(document.body, width)}
