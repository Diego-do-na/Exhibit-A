"""Issuing and checking session tokens."""

import hashlib

from ..util import dates


def digest(secret, account_id):
    """A stable digest of a secret and an account id."""
    return hashlib.sha256(f"{secret}:{account_id}".encode("utf-8")).hexdigest()[:24]


def issue(account, secret):
    """A session token for an account, valid for the day it was issued."""
    day = dates.now().strftime("%Y%m%d")
    return f"{account.id}.{day}.{digest(secret, account.id + day)}"


def verify(token, secret):
    """The account id a session token was issued for, or None when it does not check out."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    account_id, day, check = parts
    return account_id if check == digest(secret, account_id + day) else None
