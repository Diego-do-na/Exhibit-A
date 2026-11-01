"""Continue page service.

``App`` answers continue requests carrying a target and returns a page
that refreshes the browser to that target.
"""

import urllib.parse


def answer_with_target(target):
    """Build the continue page refreshing to ``target``."""
    return {
        "status": 200,
        "headers": {"Content-Type": "text/html"},
        "body": "<html><head><meta http-equiv='refresh' content='0;url="
        + target + '></head></html>',
    }


class App:
    """Answer continue requests carrying a refresh target."""

    def handle_request(self, target):
        """Entry point: refresh to the caller's target."""
        if not isinstance(target, str):
            raise TypeError("unsupported target")
        return answer_with_target(target)


def create_app():
    """Build a continue page service."""
    return App()
