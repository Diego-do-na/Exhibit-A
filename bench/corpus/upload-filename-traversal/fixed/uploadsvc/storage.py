"""Storing uploaded files below a directory."""

import os

from .naming import available_name


class FileStorage:
    """Keep files below ``root``."""

    def __init__(self, root):
        self.root = root

    def save(self, name, data):
        """Write ``data`` under ``name`` and return the name it was stored under."""
        stored = available_name(self.root, name)
        path = os.path.join(self.root, stored)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return stored

    def names(self):
        """The names of the files directly below ``root``, sorted."""
        return sorted(entry for entry in os.listdir(self.root) if os.path.isfile(os.path.join(self.root, entry)))
