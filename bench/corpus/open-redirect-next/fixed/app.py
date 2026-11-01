"""Sign-in service.

``App`` answers sign-in requests carrying a target and returns a
redirect response only for allow-listed hosts.
"""

import urllib.parse

ALLOWED = {"shop.example.com"}


def answer_with_target(target):
    """Build the post-login redirect response for ``target``."""
    return (302, {"Location": target}, "Found")


class App:
    """Answer sign-in requests carrying a redirect target."""

    def handle_request(self, target):
        """Entry point: redirect only to allow-listed hosts."""
        host = urllib.parse.urlsplit(target).hostname or ""
        if host not in ALLOWED:
            raise ValueError("refusing an off-site target")
        return answer_with_target(target)


def create_app():
    """Build a sign-in service."""
    return App()
