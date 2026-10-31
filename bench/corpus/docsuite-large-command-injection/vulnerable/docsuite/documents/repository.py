"""Documents kept as JSON files below the data directory."""

import json
import os

from ..errors import NotFound
from ..storage.paths import below
from ..util import dates, ids
from .models import Document


class DocumentRepository:
    """Load and store documents; every path stays below the collection directory."""

    def __init__(self, data_dir):
        self.directory = os.path.abspath(os.path.join(data_dir, "documents"))
        os.makedirs(self.directory, exist_ok=True)

    def _path(self, doc_id):
        return below(self.directory, doc_id + ".json")

    def create(self, title, body, owner, tags=()):
        """Store a new document and return it."""
        doc_id = ids.next_id("doc")
        moment = dates.stamp()
        document = Document(id=doc_id, title=title, body=body, owner=owner,
                            tags=list(tags), created=moment, updated=moment)
        self._write(document)
        return document

    def get(self, doc_id):
        """The document with this id, or None."""
        path = self._path(doc_id)
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8") as handle:
            return Document.from_dict(json.load(handle))

    def require(self, doc_id):
        """The document with this id, or a 404."""
        document = self.get(doc_id)
        if document is None:
            raise NotFound(f"no such document: {doc_id}")
        return document

    def update(self, doc_id, title=None, body=None, tags=None):
        """Change the given fields of a document and return it."""
        document = self.require(doc_id)
        if title is not None:
            document.title = title
        if body is not None:
            document.body = body
        if tags is not None:
            document.tags = list(tags)
        document.updated = dates.stamp()
        self._write(document)
        return document

    def remove(self, doc_id):
        """Remove a document; True when something was removed."""
        path = self._path(doc_id)
        if not os.path.isfile(path):
            return False
        os.remove(path)
        return True

    def all(self):
        """Every document, ordered by id."""
        found = []
        for entry in sorted(os.listdir(self.directory)):
            if entry.endswith(".json"):
                with open(os.path.join(self.directory, entry), encoding="utf-8") as handle:
                    found.append(Document.from_dict(json.load(handle)))
        return found

    def by_owner(self, owner):
        """Every document owned by ``owner``, ordered by id."""
        return [doc for doc in self.all() if doc.owner == owner]

    def _write(self, document):
        path = self._path(document.id)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(document.to_dict(), handle, indent=2, sort_keys=True)
