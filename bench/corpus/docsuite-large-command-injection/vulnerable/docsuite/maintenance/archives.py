"""Directory inventories for the cleanup audit line."""

import subprocess


def inventory(directory, name):
    """List ``directory/name`` with the platform ``ls`` command for the audit line."""
    command = "ls " + directory + "/" + name
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


def audit_line(directory, name, removed):
    """One human-readable line describing what a cleanup pass did."""
    listing = inventory(directory, name).strip().splitlines()
    kept = len(listing)
    return (
        f"cleanup of {directory}/{name}: {removed} temporary file(s) removed, "
        f"{kept} entrie(s) remain"
    )
