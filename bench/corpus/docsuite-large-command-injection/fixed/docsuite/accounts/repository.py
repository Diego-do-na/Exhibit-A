"""In-memory account store."""

from .models import Account

SEED = (
    ("acc-1", "Ana Ruiz", "admin", "tok-ana"),
    ("acc-2", "Ben Ortiz", "editor", "tok-ben"),
    ("acc-3", "Cara Lin", "viewer", "tok-cara"),
)


class AccountRepository:
    """Accounts indexed by id and by token."""

    def __init__(self):
        self._by_id = {}

    def add(self, account):
        """Store an account, replacing one with the same id."""
        self._by_id[account.id] = account
        return account

    def get(self, account_id):
        """The account with this id, or None."""
        return self._by_id.get(account_id)

    def by_token(self, token):
        """The account holding this token, or None."""
        for account in self._by_id.values():
            if account.token == token:
                return account
        return None

    def all(self):
        """Every account, ordered by id."""
        return [self._by_id[key] for key in sorted(self._by_id)]

    @classmethod
    def seeded(cls):
        """A repository holding the demo accounts."""
        repo = cls()
        for account_id, name, role, token in SEED:
            repo.add(Account(account_id, name, role, token))
        return repo
