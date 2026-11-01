"""Sign-in service.

``App`` answers sign-in requests carrying a target and returns a
redirect response sending the browser to that target.
"""

import urllib.parse


def answer_with_target(target):
    """Build the post-login redirect response for ``target``."""
    return (302, {"Location": target}, "Found")


class App:
    """Answer sign-in requests carrying a redirect target."""

    def handle_request(self, target):
        """Entry point: redirect to the caller's target."""
        if not isinstance(target, str):
            raise TypeError("unsupported target")
        return answer_with_target(target)


def create_app():
    """Build a sign-in service."""
    return App()
