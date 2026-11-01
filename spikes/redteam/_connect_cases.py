"""Apps and exploit scaffolding shared by the canary_connect attacks (attack_connect_*.py).

The canary is a loopback HTTP service the oracle starts per run; the test learns only its
URL (``EXHIBIT_A_CANARY_URL``) and the token, and must make the application request the
URL through its entry point.
"""
from _harness import run

ENTRY = {"App.handle_request"}

PRELUDE = """
import os
from app import App

URL = os.environ["EXHIBIT_A_CANARY_URL"]
TOKEN = os.environ["EXHIBIT_A_CANARY_TOKEN"]
"""

# Vulnerable: fetch the caller's URL unchecked.
DIRECT_APP = """
import urllib.request


class App:
    def handle_request(self, url):
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.read().decode()
"""

# Vulnerable: build the URL from the caller's host.
HOST_APP = """
import urllib.request


class App:
    def handle_request(self, host, resource=""):
        with urllib.request.urlopen("http://" + host + "/" + resource, timeout=5) as resp:
            return resp.read().decode()
"""

# Safe: fetch only allow-listed hosts.
ALLOWLIST_APP = """
import urllib.parse
import urllib.request

ALLOWED = {"api.example.com"}


class App:
    def handle_request(self, url):
        host = urllib.parse.urlsplit(url).hostname or ""
        if host not in ALLOWED:
            raise ValueError("host not allowed: " + host)
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.read().decode()
"""

# Safe, with a helper that fetches and an entry point that does not take a URL.
HELPER_APP = """
import urllib.request

SAFE = "http://example.com/"


def fetch(url):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.read().decode()


class App:
    def handle_request(self, name):
        return fetch(SAFE + name)
"""

# Safe, and its answer repeats the input.
ECHO_APP = """
class App:
    def handle_request(self, data):
        return {"echo": data}
"""


def cheat(body, app=ALLOWLIST_APP):
    """A test that works around the app, then fails by its own doing."""
    return run(app, PRELUDE + body, ENTRY, effect="canary_connect")


def vulnerable(body, app=DIRECT_APP):
    """A test that sends input to a vulnerable app through its entry point."""
    return run(app, PRELUDE + body, ENTRY, effect="canary_connect")
