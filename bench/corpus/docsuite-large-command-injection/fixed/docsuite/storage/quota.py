"""Directory sizes and quota checks."""

import os


def usage_bytes(directory):
    """The bytes held by the files directly below ``directory``."""
    total = 0
    if not os.path.isdir(directory):
        return total
    for entry in os.listdir(directory):
        path = os.path.join(directory, entry)
        if os.path.isfile(path) and not os.path.islink(path):
            total += os.path.getsize(path)
    return total


def tree_bytes(directory):
    """The bytes held by every file under ``directory``, at any depth."""
    total = 0
    for current, _, files in os.walk(directory):
        for name in files:
            path = os.path.join(current, name)
            if os.path.isfile(path) and not os.path.islink(path):
                total += os.path.getsize(path)
    return total


def over_quota(used_bytes, quota_bytes):
    """Whether ``used_bytes`` is past the allowed ``quota_bytes``."""
    return used_bytes > quota_bytes


def quota_report(used_bytes, quota_bytes):
    """A small mapping describing quota use, for the usage report."""
    percent = round(100.0 * used_bytes / quota_bytes, 1) if quota_bytes else 0.0
    return {"used_bytes": used_bytes, "quota_bytes": quota_bytes,
            "percent": percent, "over": over_quota(used_bytes, quota_bytes)}
