"""The object an upload becomes once it has been read from the request."""

import os

from .errors import InvalidFileName


def sanitize(name):
    """Reduce a client-supplied file name to the name it should be stored under.

    Some clients send the full local path of the file, using backslashes, so only what
    follows the last backslash is kept.
    """
    name = name.strip()
    name = name[name.rfind("\\") + 1:]
    if not name:
        raise InvalidFileName("empty file name")
    if name != os.path.basename(name) or name in {".", ".."}:
        raise InvalidFileName("file name has path elements")
    return name


class UploadedFile:
    """A named blob of bytes received from a client."""

    def __init__(self, name, data):
        self.name = sanitize(name)
        self.data = data

    @property
    def size(self):
        """Number of bytes received."""
        return len(self.data)
