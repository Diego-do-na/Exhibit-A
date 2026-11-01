"""Catalog import service.

``App`` accepts catalog documents as XML. Each document is parsed into a
plain text listing of the catalog body, including any referenced external
entries the handler resolves.
"""

import io
import xml.sax
from xml.sax.handler import ContentHandler, EntityResolver, feature_external_ges


class CatalogHandler(ContentHandler, EntityResolver):
    """Collect character data; resolve external entities to local files."""

    def __init__(self):
        self.chunks = []

    def resolveEntity(self, publicId, systemId):
        path = systemId
        if path.startswith("file://"):
            path = path[len("file://"):]
        return open(path, encoding="utf-8")

    def characters(self, content):
        self.chunks.append(content)

    def text(self):
        return "".join(self.chunks)


def parse_catalog(document):
    """Parse a catalog document and return its text body."""
    handler = CatalogHandler()
    parser = xml.sax.make_parser()
    parser.setFeature(feature_external_ges, True)
    parser.setContentHandler(handler)
    parser.setEntityResolver(handler)
    parser.parse(io.StringIO(document))
    return handler.text()


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
