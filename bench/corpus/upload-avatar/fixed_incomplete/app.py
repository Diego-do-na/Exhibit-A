"""Avatar upload service.

``App`` accepts upload requests carrying a file name and the file bytes.
Names that contain ``..`` are refused; anything else is stored under that
name in the avatar directory.
"""

import os


def store_avatar(root, name, data):
    """Write ``data`` under ``name`` inside ``root``."""
    if ".." in name:
        raise ValueError("unsupported name")
    path = os.path.join(root, name)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)
    return name


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
