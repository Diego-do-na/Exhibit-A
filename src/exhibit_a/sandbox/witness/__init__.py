"""OS-level canary witness: a supervisor outside the test process.

The in-process oracle plugin lives in the untrusted test. This package is the second
witness: a tiny supervisor started before pytest, as a sibling, with a key the test
never receives. It observes canary access at the OS level (inotify on canary paths,
the exec marker, the loopback listener, a read watch on the SQLite file) and writes
HMAC-signed observations to a log the judge requires in agreement with the plugin.

Effects the supervisor can see: ``canary_read``, ``canary_write``, ``canary_exec``,
``canary_sql``, ``canary_connect``. ``canary_dos``, ``canary_redirect`` and
``canary_access`` have no OS-level canary the supervisor can watch; they keep the
in-process standard. Isolated and resource-limited, not "100% safe".
"""

from __future__ import annotations

from pathlib import Path

OBSERVABLE_EFFECTS = frozenset({
    "canary_read", "canary_write", "canary_exec", "canary_sql", "canary_connect",
})

SUPERVISOR_SOURCE = Path(__file__).resolve().parent / "supervisor.py"

ACCESS_KINDS = frozenset({"access", "accept"})


def observed_effects(bodies: list[dict]) -> list[str]:
    """Effect names for which at least one verified access/accept observation exists."""
    seen: list[str] = []
    for body in bodies:
        if not isinstance(body, dict):
            continue
        kind = body.get("kind")
        effect = body.get("effect")
        if kind in ACCESS_KINDS and isinstance(effect, str) and effect in OBSERVABLE_EFFECTS:
            if effect not in seen:
                seen.append(effect)
    return seen


def log_status(bodies: list[dict], rejected: list[str]) -> str:
    """``ok`` only when the supervisor's start line verified and the log was not tampered with.

    Anything else fails closed: missing supervisor, overflow, or a line that did not verify.
    """
    if rejected:
        return "unavailable"
    if any(isinstance(b, dict) and b.get("kind") == "overflow" for b in bodies):
        return "unavailable"
    if any(isinstance(b, dict) and b.get("kind") == "start" for b in bodies):
        return "ok"
    return "unavailable"
