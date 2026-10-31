"""Turning a bearer token into the account making the request."""

from ..errors import Unauthorized
from .middleware import public_paths


def authenticate(request, accounts):
    """Set ``request.account`` from the bearer token; public paths may go without one."""
    token = request.bearer_token()
    if token is None:
        if request.path in public_paths():
            return None
        raise Unauthorized("a bearer token is required")
    account = accounts.by_token(token)
    if account is None or not account.active:
        raise Unauthorized("unknown or disabled token")
    request.account = account
    return account
