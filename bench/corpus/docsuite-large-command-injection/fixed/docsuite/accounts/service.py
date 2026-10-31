"""Use cases about accounts."""

from ..errors import NotFound, Unauthorized
from . import tokens


class AccountService:
    """Login, lookup and listing of accounts."""

    def __init__(self, repository, secret="docsuite-demo-secret"):
        self.repository = repository
        self.secret = secret

    def login(self, name, token):
        """Check a name and an API token and return a session token for the account."""
        account = self.repository.by_token(token)
        if account is None or account.name.lower() != name.lower() or not account.active:
            raise Unauthorized("wrong name or token")
        return tokens.issue(account, self.secret)

    def from_session(self, session_token):
        """The account a session token belongs to."""
        account_id = tokens.verify(session_token, self.secret)
        account = self.repository.get(account_id) if account_id else None
        if account is None:
            raise Unauthorized("invalid session")
        return account

    def get(self, account_id):
        """An account by id, or 404."""
        account = self.repository.get(account_id)
        if account is None:
            raise NotFound(f"no such account: {account_id}")
        return account

    def directory(self):
        """The public view of every active account."""
        return [account.public() for account in self.repository.all()
                if account.active]