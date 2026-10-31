"""Manifests describing what the data directory holds."""

import json
import os

from ..storage.paths import below, relative


def write_manifest(data_dir, entries):
    """Store ``entries`` (name -> description) as the directory manifest."""
    payload = {"entries": dict(entries)}
    with open(below(data_dir, "manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    return payload


def read_manifest(data_dir):
    """The stored manifest, or an empty one when none was written."""
    path = os.path.join(os.path.abspath(data_dir), "manifest.json")
    if not os.path.isfile(path):
        return {"entries": {}}
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def collect(data_dir, names):
    """Describe the current subdirectories of ``data_dir`` for the manifest."""
    base = os.path.abspath(data_dir)
    found = {}
    for name in names:
        path = os.path.join(base, name)
        if os.path.isdir(path):
            count = sum(
                len(files) for _, _, files in os.walk(path)
            )
            found[name] = {"path": relative(base, path), "files": count}
    return found


def refresh(data_dir, names):
    """Rewrite the manifest from the directories that exist now."""
    return write_manifest(data_dir, collect(data_dir, names))
