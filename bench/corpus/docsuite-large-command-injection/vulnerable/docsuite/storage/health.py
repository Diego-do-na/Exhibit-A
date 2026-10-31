"""Health of the data directory."""

import os

from ..storage.quota import tree_bytes


def directory_health(path):
    """Whether ``path`` exists, is a directory and can be listed."""
    if not os.path.exists(path):
        return {"path": path, "state": "missing"}
    if not os.path.isdir(path):
        return {"path": path, "state": "not_a_directory"}
    try:
        entries = os.listdir(path)
    except OSError:
        return {"path": path, "state": "unreadable"}
    return {"path": path, "state": "ok", "entries": len(entries)}


def storage_health(data_dir, names):
    """Health of each expected subdirectory plus the byte total."""
    base = os.path.abspath(data_dir)
    parts = [directory_health(os.path.join(base, name)) for name in names]
    states = {part["state"] for part in parts}
    if "missing" in states or "unreadable" in states:
        overall = "degraded"
    elif "not_a_directory" in states:
        overall = "broken"
    else:
        overall = "ok"
    return {"overall": overall, "bytes": tree_bytes(base), "parts": parts}


EXPECTED = ("documents", "versions", "exports", "outbox", "cache", "audit",
            "backups", "blobs")


def service_health(data_dir):
    """The health mapping included in the admin usage report."""
    return storage_health(data_dir, EXPECTED)
