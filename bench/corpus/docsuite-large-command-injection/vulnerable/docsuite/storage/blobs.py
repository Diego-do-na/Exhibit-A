"""Opaque byte blobs kept as files below one directory."""

import os

from .paths import below


class BlobStore:
    """Write, read, list and remove named blobs below ``root``."""

    def __init__(self, root):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)

    def put(self, name, data):
        """Store ``data`` under ``name`` and return the name."""
        path = below(self.root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return name

    def get(self, name):
        """The bytes stored under ``name``, or None."""
        path = below(self.root, name)
        if not os.path.isfile(path):
            return None
        with open(path, "rb") as handle:
            return handle.read()

    def remove(self, name):
        """Remove ``name``; True when something was removed."""
        path = below(self.root, name)
        if not os.path.isfile(path):
            return False
        os.remove(path)
        return True

    def names(self):
        """The blob names directly below the root, sorted."""
        return sorted(
            entry
            for entry in os.listdir(self.root)
            if os.path.isfile(os.path.join(self.root, entry))
        )

    def size_of(self, name):
        """The size of ``name`` in bytes, or None."""
        path = below(self.root, name)
        if not os.path.isfile(path):
            return None
        return os.path.getsize(path)
