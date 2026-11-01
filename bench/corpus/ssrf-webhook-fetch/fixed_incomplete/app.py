"""Webhook delivery service.

``App`` answers delivery requests carrying a subscriber URL by fetching
that URL and returning the response body.
"""

import urllib.parse
import urllib.request


def fetch(url):
    """Fetch ``url`` and return the response body."""
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read().decode("utf-8", "replace")


class App:
    """Answer delivery requests carrying a subscriber URL."""

    def handle_request(self, url):
        """Entry point: fetch the subscriber URL unless it names loopback."""
        if not isinstance(url, str) or not url.startswith("http"):
            raise ValueError("unsupported subscriber")
        if "localhost" in url:
            raise ValueError("refusing a loopback subscriber")
        return {"status": 200, "body": fetch(url)}


def create_app():
    """Build a webhook delivery service."""
    return App()
