"""Choosing a name for a stored file that does not clash with an existing one."""

import os


def available_name(root, name):
    """``name``, or ``name`` with a counter appended when ``root`` already holds a file by that name."""
    stem, ext = os.path.splitext(name)
    candidate = name
    counter = 0
    while os.path.exists(os.path.join(root, candidate)):
        counter += 1
        candidate = f"{stem}_{counter}{ext}"
    return candidate
