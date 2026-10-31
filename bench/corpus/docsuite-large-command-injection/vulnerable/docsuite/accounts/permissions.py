"""What each role may do."""

from ..errors import Forbidden

REQUIRED = {
    "documents.read": "viewer",
    "documents.write": "editor",
    "exports.create": "viewer",
    "notifications.read": "viewer",
    "notifications.write": "viewer",
    "admin.read": "admin",
    "admin.write": "admin",
}

ORDER = ("viewer", "editor", "admin")


def allowed(account, action):
    """Whether the account's role reaches the role an action needs."""
    needed = REQUIRED.get(action)
    if needed is None:
        return False
    return ORDER.index(account.role) >= ORDER.index(needed)


def require(account, action):
    """Raise 403 unless the account may do ``action``."""
    if not allowed(account, action):
        raise Forbidden(f"{account.role} may not {action}")
