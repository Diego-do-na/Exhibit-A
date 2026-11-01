"""Continue page service.

``App`` answers continue requests with a plain page and never refreshes
to a caller-supplied target.
"""


def answer_with_target(target):
    """Build the continue page, ignoring any caller target."""
    _ = target
    return {
        "status": 200,
        "headers": {"Content-Type": "text/html"},
        "body": "<html><head><title>gone</title></head></html>",
    }


class App:
    """Answer continue requests carrying a refresh target."""

    def handle_request(self, target):
        """Entry point: answer with a plain page, never a refresh."""
        if not isinstance(target, str):
            raise TypeError("unsupported target")
        return answer_with_target(target)


def create_app():
    """Build a continue page service."""
    return App()
