"""Catalog import service.

``App`` accepts catalog documents as XML. Each document is parsed into a
plain text listing of the catalog body. External entities are not resolved.
"""

import xml.etree.ElementTree as ET


def parse_catalog(document):
    """Parse a catalog document and return its text body."""
    root = ET.fromstring(document)
    return "".join(root.itertext())


class App:
    """Answer import requests carrying a catalog document."""

    def __init__(self, base):
        self.base = base

    def handle_request(self, method, document=None):
        """Entry point: import ``document`` on POST, reject anything else."""
        if method != "POST":
            return "method not allowed"
        return parse_catalog(document)


def create_app(base):
    """Build an app that imports catalog documents."""
    return App(base)
