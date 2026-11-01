"""Library document service.

``App`` answers document requests carrying a caller and a document id and
returns the stored content only when the caller owns the document.
"""

import json
import os

STORE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "store.json")


def load_store():
    """Load the document store."""
    with open(STORE_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def lookup(resource):
    """Return the stored entry for ``resource``, or None."""
    name = resource[:-1] if resource.endswith("/") else resource
    return load_store().get(name)


class App:
    """Answer document requests carrying a caller and a document id."""

    def handle_request(self, auth, resource):
        """Entry point: return the document only to its owner."""
        entry = lookup(resource)
        if entry is None:
            raise KeyError("no such document")
        if entry["owner"] != auth:
            raise PermissionError("not the owner")
        return {"status": 200, "body": {"document": entry["content"], "reader": auth}}


def create_app():
    """Build a library document service."""
    return App()
