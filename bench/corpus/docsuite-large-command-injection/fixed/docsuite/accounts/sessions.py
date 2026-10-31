"""Issued session tokens and their lifetime."""

from ..util import dates
from . import tokens


class SessionStore:
    """Remember the session tokens handed out at login."""

    def __init__(self, secret, lifetime_days=7):
        self.secret = secret
        self.lifetime_days = lifetime_days
        self._sessions = {}

    def open(self, account):
        """Issue a session token for ``account`` and remember it."""
        token = tokens.issue(account, self.secret)
        self._sessions[token] = {"account": account.id, "opened": dates.stamp()}
        return token

    def close(self, token):
        """Forget a session token; True when it existed."""
        return self._sessions.pop(token, None) is not None

    def owner(self, token):
        """The account id a live session token belongs to, or None."""
        if tokens.verify(token, self.secret) is None:
            return None
        held = self._sessions.get(token)
        if held is None:
            return None
        if self.expired(token):
            return None
        return held["account"]

    def expired(self, token):
        """Whether a remembered session token is past its lifetime."""
        held = self._sessions.get(token)
        if held is None:
            return True
        age = dates.age_days(held["opened"])
        return age > self.lifetime_days

    def active_for(self, account_id):
        """The live session tokens of one account."""
        return sorted(
            token for token, held in self._sessions.items()
            if held["account"] == account_id and not self.expired(token)
        )

    def sweep(self):
        """Forget every expired session and return how many were removed."""
        gone = [token for token in self._sessions if self.expired(token)]
        for token in gone:
            del self._sessions[token]
        return len(gone)
