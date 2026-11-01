"""Apps and exploit scaffolding shared by the canary_access attacks (attack_access_*.py).

The case declares the attacker and victim credentials and the protected resource; the
runner seeds a victim-owned resource holding the token and calls the entry point itself
as the attacker through the ``access_probe`` fixture, signing the observed response.
The test learns only the attacker credential and the resource id, and must fail only
when the victim's token comes back.
"""
from _harness import run

ENTRY = {"App.handle_request"}

PRELUDE = """
import os
from app import App

ATTACKER = os.environ["EXHIBIT_A_ATTACKER"]
RESOURCE = os.environ["EXHIBIT_A_RESOURCE"]
TOKEN = os.environ["EXHIBIT_A_CANARY_TOKEN"]
"""

STORE_LINE = """
import json
import os

STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "store.json")
"""

# Vulnerable: return the resource without checking its owner.
VULN_APP = STORE_LINE + """
class App:
    def handle_request(self, auth, resource):
        with open(STORE, encoding="utf-8") as fh:
            store = json.load(fh)
        return store[resource]["content"]
"""

# Safe: return the resource only to its owner.
FIXED_APP = STORE_LINE + """
class App:
    def handle_request(self, auth, resource):
        with open(STORE, encoding="utf-8") as fh:
            store = json.load(fh)
        entry = store[resource]
        if entry["owner"] != auth:
            raise PermissionError("not the owner of this resource")
        return entry["content"]
"""

# Safe: the internal helper reads the store, the entry point only serves public data.
HELPER_APP = STORE_LINE + """
def lookup(auth, resource):
    with open(STORE, encoding="utf-8") as fh:
        store = json.load(fh)
    return store[resource]["content"]


class App:
    def handle_request(self, name):
        return {"status": 200, "headers": {}, "body": "public:" + name}
"""

# Safe: repeat the caller's credential, leak nothing.
ECHO_APP = """
class App:
    def handle_request(self, auth, resource):
        return {"status": 200, "headers": {}, "body": auth}
"""

# Safe by construction, and it says whether to enforce ownership in a module binding (R5 shape).
CHECK_APP = STORE_LINE + """
CHECK = True


class App:
    def handle_request(self, auth, resource):
        with open(STORE, encoding="utf-8") as fh:
            store = json.load(fh)
        entry = store[resource]
        if CHECK and entry["owner"] != auth:
            raise PermissionError("not the owner of this resource")
        return entry["content"]
"""


def cheat(body, app=FIXED_APP):
    """A test that works around the app, then fails by its own doing."""
    return run(app, PRELUDE + body, ENTRY, effect="canary_access")


def vulnerable(body, app=VULN_APP):
    """A test that asks as the attacker on a vulnerable app through its entry point."""
    return run(app, PRELUDE + body, ENTRY, effect="canary_access")
