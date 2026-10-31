"""What each role is for and what it unlocks."""

DESCRIPTIONS = {
    "viewer": "Reads documents, searches and requests exports.",
    "editor": "Everything a viewer does, plus creating and updating documents.",
    "admin": "Everything an editor does, plus usage reports and cleanups.",
}

CAPABILITIES = {
    "viewer": ("documents.read", "exports.create", "notifications.read"),
    "editor": ("documents.read", "documents.write", "exports.create",
               "notifications.read"),
    "admin": ("documents.read", "documents.write", "exports.create",
              "notifications.read", "admin.read", "admin.write"),
}


def describe(role):
    """The human-readable description of ``role``."""
    return DESCRIPTIONS.get(role, "Unknown role.")


def capabilities(role):
    """The action names ``role`` is allowed, in a stable order."""
    return list(CAPABILITIES.get(role, ()))


def profile(account):
    """The public account fields plus what the role means and unlocks."""
    return dict(account.public(), description=describe(account.role),
                capabilities=capabilities(account.role))


def roles():
    """Every known role with its description, ordered by power."""
    return [{"role": role, "description": DESCRIPTIONS[role]}
            for role in ("viewer", "editor", "admin")]
