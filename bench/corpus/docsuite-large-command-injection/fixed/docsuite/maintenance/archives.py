"""Directory inventories for the cleanup audit line."""

import os
import subprocess

from ..errors import BadRequest


def inventory(directory, name):
    """List ``directory/name`` with the platform ``ls`` command for the audit line.

    The target must be a plain entry name inside the directory: anything that
    could name another location is refused, and the name reaches ``ls`` as a
    separate argument, so the platform shell never interprets it.
    """
    if name in ("", "..") or os.path.basename(name) != name:
        raise BadRequest("the inventory target must be a plain entry name")
    completed = subprocess.run(
        ["ls", os.path.join(directory, name)],
        capture_output=True, text=True, shell=False,
    )
    return completed.stdout


def audit_line(directory, name, removed):
    """One human-readable line describing what a cleanup pass did."""
    listing = inventory(directory, name).strip().splitlines()
    kept = len(listing)
    return (
        f"cleanup of {directory}/{name}: {removed} temporary file(s) removed, "
        f"{kept} entrie(s) remain"
    )
