"""Point-in-time copies of one scope directory."""

import os
import shutil

from ..storage.paths import below
from ..util import dates


def backup_name(scope):
    """A timestamped backup folder name for ``scope``."""
    stamp = dates.stamp().replace(":", "").replace("+", "")
    return f"{scope}-{stamp}"


def backup_scope(scope, directory):
    """Copy every file of ``directory`` into a timestamped backup folder."""
    name = backup_name(scope)
    destination = below(os.path.join(directory, "..", "backups"), name)
    os.makedirs(destination, exist_ok=True)
    copied = []
    for entry in sorted(os.listdir(directory)):
        source = os.path.join(directory, entry)
        if os.path.isfile(source) and not os.path.islink(source):
            shutil.copy2(source, os.path.join(destination, entry))
            copied.append(entry)
    return {"backup": name, "scope": scope, "copied": copied}


def backups_for(directory):
    """The backup folder names next to ``directory``, newest first."""
    root = os.path.join(directory, "..", "backups")
    if not os.path.isdir(root):
        return []
    return sorted(os.listdir(root), reverse=True)


def prune_backups(directory, keep=5):
    """Remove backup folders beyond the newest ``keep`` and return the removed names."""
    root = os.path.join(directory, "..", "backups")
    names = backups_for(directory)
    removed = []
    for name in names[keep:]:
        path = os.path.join(root, name)
        if os.path.isdir(path):
            shutil.rmtree(path)
            removed.append(name)
    return removed
