"""Keeping every file access below a root directory."""

import os

from ..errors import BadRequest


def below(root, *parts):
    """``root/parts`` as an absolute path, refused when it escapes ``root``."""
    base = os.path.abspath(root)
    path = os.path.abspath(os.path.join(base, *[str(part) for part in parts]))
    if path != base and not path.startswith(base + os.sep):
        raise BadRequest("the name must stay inside its directory")
    return path


def inside(root, path):
    """Whether ``path`` already sits at or below ``root``."""
    base = os.path.abspath(root)
    target = os.path.abspath(path)
    return target == base or target.startswith(base + os.sep)


def relative(root, path):
    """``path`` shown relative to ``root`` (for reports and listings)."""
    return os.path.relpath(os.path.abspath(path), os.path.abspath(root))
