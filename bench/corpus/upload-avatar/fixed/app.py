"""Avatar upload service.

``App`` accepts upload requests carrying a file name and the file bytes.
The bytes are stored under the base name only, confined to the avatar
directory.
"""

import os


def store_avatar(root, name, data):
    """Write ``data`` under the base name of ``name`` inside ``root``."""
    stored = os.path.basename(name)
    if not stored or stored in (".", ".."):
        raise ValueError("unsupported name")
    path = os.path.join(root, stored)
    dest = os.path.realpath(root)
    target = os.path.realpath(path)
    if target != dest and not target.startswith(dest + os.sep):
        raise ValueError("name escapes destination")
    os.makedirs(os.path.dirname(target) or dest, exist_ok=True)
    with open(target, "wb") as handle:
        handle.write(data)
    return stored


class App:
    """Answer upload requests carrying a file name and bytes."""

    def __init__(self, dest_dir):
        self.dest_dir = dest_dir

    def handle_request(self, method, name=None, data=b""):
        """Entry point: store ``name`` on POST, reject anything else."""
        if method != "POST":
            return "method not allowed"
        return store_avatar(self.dest_dir, name, data)


def create_app(dest_dir):
    """Build an app that stores avatars in ``dest_dir``."""
    return App(dest_dir)
