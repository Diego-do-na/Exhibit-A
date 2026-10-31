"""Content type lookup by file extension."""

import os

TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".txt": "text/plain; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
}

DEFAULT = "application/octet-stream"


def content_type(name):
    """Content type for a file name, by extension."""
    return TYPES.get(os.path.splitext(name)[1].lower(), DEFAULT)
