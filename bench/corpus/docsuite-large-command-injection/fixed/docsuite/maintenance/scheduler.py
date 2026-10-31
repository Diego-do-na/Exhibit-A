"""Cleanup timetables."""

import datetime

from ..errors import BadRequest
from ..util import dates

SCHEDULES = ("hourly", "daily", "weekly", "never")
INTERVALS = {"hourly": 3600, "daily": 86400, "weekly": 604800, "never": 0}


def parse_schedule(text):
    """The schedule name, or a 400 for an unknown one."""
    name = str(text or "").strip().lower()
    if name not in SCHEDULES:
        raise BadRequest(f"unknown schedule: {text}")
    return name


def interval_seconds(name):
    """Seconds between runs of schedule ``name`` (0 means never)."""
    return INTERVALS[parse_schedule(name)]


def next_run(last_stamp, name):
    """The stamp after ``last_stamp`` when schedule ``name`` runs again, or None."""
    gap = interval_seconds(name)
    if not gap:
        return None
    try:
        moment = dates.parse_stamp(last_stamp)
    except (TypeError, ValueError):
        return dates.stamp()
    return dates.stamp(moment + datetime.timedelta(seconds=gap))


def describe(name):
    """A short mapping describing schedule ``name``."""
    gap = interval_seconds(name)
    return {"schedule": parse_schedule(name), "every_seconds": gap,
            "enabled": gap > 0}
