"""Report export service.

``App`` answers export requests carrying a caller, a report id and a
sharing flag by loading the report store and returning the stored content.
"""

import json
import os

STORE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "store.json")


def load_store():
    """Load the report store."""
    with open(STORE_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def lookup(resource):
    """Return the stored entry for ``resource``, or None."""
    name = resource[:-1] if resource.endswith("/") else resource
    return load_store().get(name)


class App:
    """Answer export requests carrying a caller and a report id."""

    def handle_request(self, auth, resource):
        """Entry point: return the report, checking owners under private/."""
        entry = lookup(resource)
        if entry is None:
            raise KeyError("no such report")
        if resource.startswith("private/") and entry["owner"] != auth:
            raise PermissionError("not the owner")
        return {"status": 200, "body": {"report": entry["content"], "reader": auth}}


def create_app():
    """Build a report export service."""
    return App()
