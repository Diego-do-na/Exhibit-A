"""History of cleanup passes, kept as JSON lines."""

import json
import os

from ..storage.paths import below
from ..util import dates


class CleanupHistory:
    """Append-only record of what each cleanup pass did."""

    def __init__(self, data_dir):
        self.directory = os.path.abspath(os.path.join(data_dir, "audit"))
        os.makedirs(self.directory, exist_ok=True)

    def _path(self):
        return below(self.directory, "cleanups.jsonl")

    def append(self, scope, target, removed, actor):
        """Remember one cleanup pass and return the entry."""
        entry = {"scope": scope, "target": target, "removed": list(removed),
                 "actor": actor, "at": dates.stamp()}
        with open(self._path(), "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def entries(self, limit=50):
        """The newest ``limit`` entries, newest first."""
        path = self._path()
        if not os.path.isfile(path):
            return []
        with open(path, encoding="utf-8") as handle:
            rows = [json.loads(line) for line in handle if line.strip()]
        return list(reversed(rows))[:limit]

    def total_removed(self):
        """How many files every recorded pass removed."""
        path = self._path()
        if not os.path.isfile(path):
            return 0
        total = 0
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    total += len(json.loads(line).get("removed", []))
        return total
