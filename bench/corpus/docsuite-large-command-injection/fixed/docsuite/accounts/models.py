"""The account record."""

from dataclasses import dataclass, field

ROLES = ("viewer", "editor", "admin")


@dataclass
class Account:
    """One person who can use the service."""

    id: str
    name: str
    role: str
    token: str
    active: bool = True
    quota: int = 50
    tags: list = field(default_factory=list)

    def public(self):
        """The fields that may be shown to other accounts."""
        return {"id": self.id, "name": self.name, "role": self.role}

    def rank(self):
        """Position of the role in ``ROLES`` (higher is more powerful)."""
        return ROLES.index(self.role)
