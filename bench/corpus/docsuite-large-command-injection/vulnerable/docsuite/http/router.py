"""Matching a request to the name of the handler that answers it."""

import re

ROUTES = (
    ("POST", "/accounts/login", "accounts.login"),
    ("POST", "/accounts/logout", "accounts.logout"),
    ("GET", "/accounts/me", "accounts.me"),
    ("GET", "/documents", "documents.list"),
    ("POST", "/documents", "documents.create"),
    ("GET", "/documents/{id}", "documents.show"),
    ("PUT", "/documents/{id}", "documents.update"),
    ("GET", "/documents/{id}/versions", "documents.versions"),
    ("GET", "/documents/{id}/related", "documents.related"),
    ("POST", "/documents/{id}/pin", "documents.pin"),
    ("DELETE", "/documents/{id}/pin", "documents.unpin"),
    ("GET", "/pins", "pins.list"),
    ("GET", "/search", "documents.search"),
    ("POST", "/exports", "exports.create"),
    ("GET", "/exports/{id}", "exports.show"),
    ("POST", "/exports/{id}/deliver", "exports.deliver"),
    ("GET", "/notifications/digest", "notifications.digest"),
    ("GET", "/notifications/preferences", "notifications.preferences"),
    ("PUT", "/notifications/preferences", "notifications.update_preferences"),
    ("POST", "/notifications/flush", "notifications.flush"),
    ("GET", "/admin/usage", "admin.usage"),
    ("POST", "/admin/cleanup", "admin.cleanup"),
    ("POST", "/admin/backup", "admin.backup"),
)


def _compile(pattern):
    names = re.findall(r"{(\w+)}", pattern)
    regex = re.sub(r"{\w+}", r"([^/]+)", pattern)
    return re.compile("^" + regex + "$"), names


_COMPILED = [(method, *_compile(path), name) for method, path, name in ROUTES]


def match(method, path):
    """``(handler name, path params)`` for a request, or ``(None, {})``; 405 shows as ``("405", {})``."""
    allowed = False
    for route_method, regex, names, name in _COMPILED:
        found = regex.match(path)
        if not found:
            continue
        if route_method == method.upper():
            return name, dict(zip(names, found.groups()))
        allowed = True
    return ("405", {}) if allowed else (None, {})
