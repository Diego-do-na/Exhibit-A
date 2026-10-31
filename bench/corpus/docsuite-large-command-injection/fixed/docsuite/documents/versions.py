"""Snapshots of documents taken on every update."""

import json
import os

from ..storage.paths import below
from ..util import dates


class VersionStore:
    """Earlier copies of documents, kept as files below the versions directory."""

    def __init__(self, data_dir):
        self.directory = os.path.abspath(os.path.join(data_dir, "versions"))
        os.makedirs(self.directory, exist_ok=True)

    def snapshot(self, document):
        """Store the current shape of ``document`` as its next version."""
        number = len(self.history(document.id)) + 1
        path = below(self.directory, f"{document.id}-v{number}.json")
        payload = dict(document.to_dict(), version=number, taken=dates.stamp())
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        return number

    def history(self, doc_id):
        """Every stored version of ``doc_id``, oldest first."""
        versions = []
        for entry in sorted(os.listdir(self.directory)):
            if entry.startswith(doc_id + "-v") and entry.endswith(".json"):
                with open(os.path.join(self.directory, entry), encoding="utf-8") as handle:
                    versions.append(json.load(handle))
        versions.sort(key=lambda item: item.get("version", 0))
        return versions

    def get(self, doc_id, number):
        """Version ``number`` of ``doc_id``, or None."""
        for version in self.history(doc_id):
            if version.get("version") == number:
                return version
        return None

    def count(self, doc_id):
        """How many versions of ``doc_id`` are stored."""
        return len(self.history(doc_id))
