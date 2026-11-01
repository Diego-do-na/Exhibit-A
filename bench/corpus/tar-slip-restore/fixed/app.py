"""Backup restore service.

``App`` accepts restore requests carrying a tar archive. Each member is
extracted into the restore directory only when the resolved path stays
inside that directory.
"""

import io
import os
import tarfile


def pack(members):
    """Serialise ``(name, data)`` pairs into a tar archive."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        for name, data in members:
            raw = data.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return buf.getvalue()


def _inside(dest, name):
    """Whether extracting ``name`` into ``dest`` would stay under ``dest``."""
    root = os.path.abspath(dest)
    target = os.path.abspath(os.path.join(root, name))
    return target == root or target.startswith(root + os.sep)


def restore(dest, blob):
    """Extract archive members whose resolved path stays inside ``dest``."""
    archive = tarfile.open(fileobj=io.BytesIO(blob), mode="r")
    kept = [member for member in archive.getmembers() if _inside(dest, member.name)]
    archive.extractall(dest, members=kept)
    return dest


class App:
    """Answer restore requests carrying a tar archive."""

    def __init__(self, dest_dir):
        self.dest_dir = dest_dir

    def handle_request(self, method, blob=None):
        """Entry point: restore ``blob`` on POST, reject anything else."""
        if method != "POST":
            return "method not allowed"
        return restore(self.dest_dir, blob)


def create_app(dest_dir):
    """Build an app that restores archives into ``dest_dir``."""
    return App(dest_dir)
