"""Which directories a cleanup pass touches and what it removes."""

import os
from dataclasses import dataclass

from ..errors import BadRequest
from ..storage.paths import below

SCOPES = ("exports", "cache", "outbox", "tmp")
TEMPORARY_ENDING = ".tmp"


@dataclass
class CleanupPlan:
    """The resolved directory and the requested target of one cleanup pass."""

    scope: str
    directory: str
    target: str


def check_scope(scope):
    """The scope name, or a 400 for an unknown one."""
    if scope not in SCOPES:
        raise BadRequest(f"unknown cleanup scope: {scope}")
    return scope


def select_targets(settings, scope, target):
    """Resolve ``scope`` to its directory and pair it with ``target``.

    The target names one entry of the scope directory (``.`` for the whole
    directory); it must be a string.
    """
    check_scope(scope)
    if not isinstance(target, str) or not target:
        raise BadRequest("the cleanup target must be a non-empty string")
    directory = os.path.abspath(settings.path(scope))
    os.makedirs(directory, exist_ok=True)
    return CleanupPlan(scope=scope, directory=directory, target=target)


def sweep(plan, recorder=None):
    """Remove the temporary files below the plan directory and return their names."""
    removed = []
    for entry in sorted(os.listdir(plan.directory)):
        if entry.endswith(TEMPORARY_ENDING):
            path = below(plan.directory, entry)
            if os.path.isfile(path):
                os.remove(path)
                removed.append(entry)
    if recorder is not None:
        recorder.record("sweep", scope=plan.scope, removed=len(removed))
    return removed
