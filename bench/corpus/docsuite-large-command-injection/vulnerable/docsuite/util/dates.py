"""Clock and date helpers."""

import datetime

_FIXED_NOW = None


def now():
    """The current UTC time, or the frozen time set with ``freeze``."""
    return _FIXED_NOW or datetime.datetime.now(datetime.timezone.utc)


def freeze(moment):
    """Freeze ``now()`` at ``moment`` (None unfreezes); used by tests and replays."""
    global _FIXED_NOW
    _FIXED_NOW = moment


def stamp(moment=None):
    """An ISO-8601 text for ``moment`` (default now), with seconds precision."""
    return (moment or now()).replace(microsecond=0).isoformat()


def parse_stamp(text):
    """The datetime an ``stamp`` text stands for."""
    return datetime.datetime.fromisoformat(text)


def age_days(text, reference=None):
    """Whole days between a stamp and ``reference`` (default now)."""
    return ((reference or now()) - parse_stamp(text)).days
