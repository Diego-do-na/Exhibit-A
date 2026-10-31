"""Storage summaries built without a shell."""

import os
import subprocess


def list_entries(directory):
    """The entry names of ``directory`` through an argument vector, never a shell."""
    completed = subprocess.run(
        ["ls", directory], capture_output=True, text=True, shell=False
    )
    if completed.returncode != 0:
        return []
    return [line for line in completed.stdout.splitlines() if line]


def summarize(directory):
    """Entry count and byte total of ``directory``, for the upkeep report."""
    entries = list_entries(directory)
    total = 0
    for entry in entries:
        path = os.path.join(directory, entry)
        if os.path.isfile(path) and not os.path.islink(path):
            total += os.path.getsize(path)
    return {"directory": directory, "entries": len(entries), "bytes": total}


def summarize_many(directories):
    """A summary per directory, in the order given."""
    return [summarize(directory) for directory in directories]
