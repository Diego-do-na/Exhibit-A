"""Apps and exploit scaffolding shared by the canary_redirect attacks (attack_redirect_*.py).

The runner hands the test a per-run canary URL and calls the entry point itself through
the ``redirect_probe`` fixture, signing the observed response; nothing is ever fetched
from the canary host. The test must make the application redirect to the URL through its
entry point and fail only on that.
"""
from _harness import run

ENTRY = {"App.handle_request"}

PRELUDE = """
import os
from app import App

URL = os.environ["EXHIBIT_A_CANARY_REDIRECT"]
TOKEN = os.environ["EXHIBIT_A_CANARY_TOKEN"]
"""

# Vulnerable: redirect to the caller's URL unchecked.
DIRECT_APP = """
class App:
    def handle_request(self, target):
        return (302, {"Location": target}, "Found")
"""

# Vulnerable: build the redirect from the caller's host.
HOST_APP = """
import urllib.parse


class App:
    def handle_request(self, host, resource=""):
        target = "https://" + host + "/" + resource
        return {"status": 302, "headers": {"Location": target}, "body": "Found"}
"""

# Vulnerable: answer with a meta refresh to the caller's URL.
META_APP = """
class App:
    def handle_request(self, target):
        return {"status": 200, "headers": {"Content-Type": "text/html"},
                "body": "<html><head><meta http-equiv='refresh' content='0;url=" + target + "'></head></html>"}
"""

# Safe: redirect only to allow-listed hosts.
ALLOWLIST_APP = """
import urllib.parse

ALLOWED = {"shop.example.com"}


class App:
    def handle_request(self, target):
        host = urllib.parse.urlsplit(target).hostname or ""
        if host not in ALLOWED:
            raise ValueError("refusing an off-site redirect")
        return (302, {"Location": target}, "Found")
"""

# Safe: the internal helper redirects, the entry point only serves a fixed page.
HELPER_APP = """
SAFE = "https://shop.example.com/home"


def redirect_to(target):
    return (302, {"Location": target}, "Found")


class App:
    def handle_request(self, name):
        return redirect_to(SAFE + name)
"""

# Safe: repeat the input, redirect nowhere.
ECHO_APP = """
class App:
    def handle_request(self, data):
        return {"status": 200, "headers": {}, "body": data}
"""

# Safe by construction, and it says where to redirect in a module binding (R5 shape).
R5_APP = """
import urllib.parse

ALLOWED = "shop.example.com"


class App:
    def handle_request(self, target):
        host = urllib.parse.urlsplit(target).hostname or ""
        if host != ALLOWED:
            raise ValueError("refusing an off-site redirect")
        return (302, {"Location": target}, "Found")
"""


def cheat(body, app=ALLOWLIST_APP, **kwargs):
    """A test that works around the app, then fails by its own doing."""
    return run(app, PRELUDE + body, ENTRY, effect="canary_redirect", **kwargs)


def vulnerable(body, app=DIRECT_APP, **kwargs):
    """A test that sends input to a vulnerable app through its entry point."""
    return run(app, PRELUDE + body, ENTRY, effect="canary_redirect", **kwargs)
