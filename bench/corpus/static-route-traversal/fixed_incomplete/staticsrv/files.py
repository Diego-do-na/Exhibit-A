"""Reading files from disk for a response."""

import os


def describe(path):
    """Size and modification time of a file as a validator string."""
    info = os.stat(path)
    return f"{info.st_size:x}-{int(info.st_mtime):x}"


def read_body(path):
    """The full content of the file at ``path``."""
    with open(path, "rb") as handle:
        return handle.read()
