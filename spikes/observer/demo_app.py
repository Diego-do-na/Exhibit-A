"""A toy 'application' for the observer spike.

It stands in for an app with a declared entry point (`serve`) that reaches a
file-reading sink through a helper. A path-traversal bug is modelled by `serve`
happily opening whatever relative path it is handed, including one that escapes
the allowed directory.
"""
from __future__ import annotations

import os


def _read_file(path: str) -> bytes:
    # The sink. Application code, one frame below the entry point.
    with open(path, "rb") as fh:
        return fh.read()


def serve(allowed_dir: str, user_path: str) -> bytes:
    """Declared entry point. Vulnerable: no containment check on user_path."""
    target = os.path.join(allowed_dir, user_path)
    return _read_file(target)
