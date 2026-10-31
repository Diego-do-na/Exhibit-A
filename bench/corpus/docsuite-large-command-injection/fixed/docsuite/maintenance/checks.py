"""Readiness checks run before a cleanup pass."""

import os

from ..errors import BadRequest


def directory_ready(directory):
    """Whether ``directory`` exists and can be listed."""
    if not os.path.isdir(directory):
        return {"ready": False, "reason": "the directory does not exist"}
    try:
        os.listdir(directory)
    except OSError as trouble:
        return {"ready": False, "reason": f"the directory cannot be listed: {trouble}"}
    return {"ready": True, "reason": ""}


def target_present(directory, target):
    """Whether ``target`` names something inside ``directory`` (``.`` always does)."""
    if target == ".":
        return True
    return os.path.exists(os.path.join(directory, target))


def writable(directory):
    """Whether new files can be created below ``directory``."""
    probe = os.path.join(directory, ".writability-probe")
    try:
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("ok")
        os.remove(probe)
    except OSError:
        return False
    return True


def readiness(settings, scope, directory):
    """Every pre-cleanup check for ``scope`` in one mapping."""
    checks = {
        "directory": directory_ready(directory),
        "writable": writable(directory) if os.path.isdir(directory) else False,
        "formats": sorted(settings.export_formats),
    }
    ready = checks["directory"]["ready"] and checks["writable"]
    return {"scope": scope, "ready": ready, "checks": checks}


def require_ready(report):
    """Raise a 400 when a readiness ``report`` did not pass."""
    if not report.get("ready"):
        raise BadRequest("the cleanup scope is not ready")
    return report
